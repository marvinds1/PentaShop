import math
import os
import re
from datetime import date, timedelta
from functools import wraps
from urllib.parse import urlparse

import click
import pymysql
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

from db import SCHEMA_PATH, SEED_PATH, get_db, init_pool, run_sql_file

load_dotenv()

ph = PasswordHasher()
DUMMY_HASH = ph.hash("timing-equaliser")
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_SHIPPING_FEE = 5000


def _env_bool(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        MYSQL_HOST=os.environ.get("MYSQL_HOST", "127.0.0.1"),
        MYSQL_PORT=int(os.environ.get("MYSQL_PORT", "3306")),
        MYSQL_USER=os.environ.get("MYSQL_USER", "pentashop"),
        MYSQL_PASSWORD=os.environ.get("MYSQL_PASSWORD", ""),
        MYSQL_DB=os.environ.get("MYSQL_DB", "pentashop"),
        DB_POOL_SIZE=int(os.environ.get("DB_POOL_SIZE", "10")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=_env_bool("SESSION_COOKIE_SECURE", True),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.environ.get("SESSION_HOURS", "8"))),
        RATELIMIT_STORAGE_URI=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
        LOGIN_RATE_LIMIT=os.environ.get("LOGIN_RATE_LIMIT", "5 per minute"),
        GEOCODING_ENABLED=_env_bool("GEOCODING_ENABLED", True),
        GEOCODER_USER_AGENT=os.environ.get("GEOCODER_USER_AGENT", "pentashop"),
    )
    if overrides:
        app.config.update(overrides)
    if not app.config["SECRET_KEY"] or len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("SECRET_KEY must be set (at least 32 characters)")

    csrf.init_app(app)
    limiter.init_app(app)
    init_pool(app)
    register_routes(app)
    register_cli(app)

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp

    return app


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("iduser"):
            return render_template("nicetry.html"), 401
        return view(*args, **kwargs)

    return wrapper


def _int_field(name, minimum=0, maximum=10**9):
    try:
        value = int(request.form.get(name, "").strip())
    except ValueError:
        abort(400)
    if value < minimum or value > maximum:
        abort(400)
    return value


def _text_field(name, max_len, required=True):
    value = request.form.get(name, "").strip()
    if (required and not value) or len(value) > max_len:
        abort(400)
    return value


def _photo_field(name):
    value = _text_field(name, 500, required=False)
    if value and urlparse(value).scheme not in {"http", "https"}:
        abort(400)
    return value


def find_coords(address, user_agent):
    from geopy.geocoders import Nominatim

    location = Nominatim(user_agent=user_agent, timeout=5).geocode(address)
    if location is None:
        return None
    return (location.latitude, location.longitude)


def shipping_fee(distance_km):
    fee = distance_km * 50
    if fee < MIN_SHIPPING_FEE:
        return MIN_SHIPPING_FEE
    return math.ceil(fee / 1000) * 1000


def register_routes(app):
    @app.route("/")
    @app.route("/start")
    def start():
        return render_template("Start.html")

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit(lambda: app.config["LOGIN_RATE_LIMIT"], methods=["POST"])
    def login():
        if request.method != "POST":
            return render_template("login.html")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT IdUser, Username, Password FROM user_accounts WHERE Username=%s", (username,))
            user = cur.fetchone()
        try:
            ph.verify(user["Password"] if user else DUMMY_HASH, password)
            ok = user is not None
        except (VerificationError, InvalidHashError):
            ok = False
        if not ok:
            return render_template("login.html", msg="Wrong username or password", username=username), 401
        if ph.check_needs_rehash(user["Password"]):
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE user_accounts SET Password=%s WHERE IdUser=%s", (ph.hash(password), user["IdUser"])
                )
            conn.commit()
        session.clear()
        session.permanent = True
        session["iduser"] = user["IdUser"]
        session["username"] = user["Username"]
        return redirect(url_for("home"))

    @app.route("/home")
    @login_required
    def home():
        with get_db().cursor() as cur:
            cur.execute(
                "SELECT IdProduct, photo, product_name, price, rating FROM product_details "
                "ORDER BY dates DESC LIMIT 10"
            )
            rv = cur.fetchall()
            cur.execute("SELECT Name FROM user_accounts WHERE IdUser=%s", (session["iduser"],))
            us = cur.fetchall()
        return render_template("home.html", data=rv, user=us)

    @app.route("/register", methods=["POST", "GET"])
    def register():
        if request.method != "POST":
            return render_template("register.html")
        form = {k: request.form.get(k, "").strip() for k in ("name", "username", "email", "alamat", "nohp")}
        password = request.form.get("password", "")
        birthdate = request.form.get("birthdate", "").strip()
        error = None
        try:
            birth = date.fromisoformat(birthdate)
        except ValueError:
            birth = None
        if not all(form.values()) or birth is None:
            error = "All fields are required"
        elif not USERNAME_RE.match(form["username"]):
            error = "Username must be 3-32 characters (letters, digits, . _ -)"
        elif not EMAIL_RE.match(form["email"]) or len(form["email"]) > 255:
            error = "Invalid email address"
        elif len(form["name"]) > 64 or len(form["alamat"]) > 255 or len(form["nohp"]) > 20:
            error = "One of the fields is too long"
        elif not 8 <= len(password) <= 128:
            error = "Password must be 8-128 characters"
        if error:
            return render_template("register.html", msg=error, **form), 400

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO user_accounts (Name, Username, Email, Alamat, NoHP, Birthdate, Password) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (form["name"], form["username"], form["email"], form["alamat"], form["nohp"], birth,
                     ph.hash(password)),
                )
                cur.execute("INSERT INTO cart (IdUser) VALUES (%s)", (cur.lastrowid,))
            conn.commit()
        except pymysql.err.IntegrityError as exc:
            conn.rollback()
            if "uq_user_email" in str(exc):
                msg = "Email already registered,try another email"
                return render_template("register.html", msg=msg, name=form["name"], username=form["username"]), 409
            msg = "Username already exists,try another username"
            return render_template("register.html", msg=msg, name=form["name"], email=form["email"]), 409
        return render_template("login.html")

    @app.route("/forgot-password")
    def forget_password():
        return render_template("forget_password.html")

    @app.route("/forget password")
    def forget_password_legacy():
        return redirect(url_for("forget_password"), code=301)

    def _product_with_seller(where, params):
        with get_db().cursor() as cur:
            cur.execute(
                "SELECT p.IdProduct, p.photo, p.product_name, p.price, p.total_buy, p.weight, p.description, "
                "p.rating, p.stock, u.Name AS seller_name FROM product_details p "
                "JOIN user_accounts u ON p.IdUser=u.IdUser WHERE " + where,  # noqa: S608
                params,
            )
            return cur.fetchall()

    @app.route("/details/<string:id_data>", methods=["GET"])
    @login_required
    def details(id_data):
        return render_template("details.html", det=_product_with_seller("p.product_name=%s", (id_data,)))

    @app.route("/detailprofile", methods=["GET"])
    @login_required
    def detailsprofile():
        with get_db().cursor() as cur:
            cur.execute(
                "SELECT Name, Username, Email, Alamat, NoHP, Birthdate FROM user_accounts WHERE IdUser=%s",
                (session["iduser"],),
            )
            det = cur.fetchall()
        return render_template("detailprofile.html", user=det)

    @app.route("/update", methods=["POST"])
    @login_required
    def update():
        nama = _text_field("nama", 64)
        alamat = _text_field("alamat", 255)
        email = _text_field("email", 255)
        hp = _text_field("hp", 20)
        if not EMAIL_RE.match(email):
            abort(400)
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE user_accounts SET Name=%s, Alamat=%s, Email=%s, NoHP=%s WHERE IdUser=%s",
                    (nama, alamat, email, hp, session["iduser"]),
                )
            conn.commit()
        except pymysql.err.IntegrityError:
            conn.rollback()
            abort(409)
        return redirect(url_for("detailsprofile"))

    @app.route("/updateitem", methods=["POST"])
    @login_required
    def updateitem():
        id_data = _int_field("id", 1)
        params = (
            _text_field("nama", 255),
            _int_field("harga"),
            _int_field("berat"),
            _text_field("desc", 1000, required=False),
            _photo_field("foto"),
            id_data,
            session["iduser"],
        )
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE product_details SET product_name=%s, price=%s, weight=%s, description=%s, photo=%s "
                "WHERE IdProduct=%s AND IdUser=%s",
                params,
            )
            cur.execute("SELECT 1 FROM product_details WHERE IdProduct=%s AND IdUser=%s",
                        (id_data, session["iduser"]))
            owned = cur.fetchone()
        if not owned:
            conn.rollback()
            abort(404)
        conn.commit()
        return redirect(url_for("prodlist"))

    @app.route("/prodlist", methods=["GET"])
    @login_required
    def prodlist():
        with get_db().cursor() as cur:
            cur.execute(
                "SELECT IdProduct, photo, product_name, price, weight, description, rating FROM product_details "
                "WHERE IdUser=%s ORDER BY product_name ASC",
                (session["iduser"],),
            )
            item = cur.fetchall()
            cur.execute("SELECT IdUser FROM user_accounts WHERE IdUser=%s", (session["iduser"],))
            user = cur.fetchall()
        return render_template("productlist.html", item=item, user=user)

    @app.route("/hapus/<int:id_data>", methods=["POST"])
    @login_required
    def hapus(id_data):
        conn = get_db()
        with conn.cursor() as cur:
            deleted = cur.execute(
                "DELETE FROM product_details WHERE IdProduct=%s AND IdUser=%s", (id_data, session["iduser"])
            )
        conn.commit()
        if not deleted:
            abort(404)
        return redirect(url_for("prodlist"))

    @app.route("/simpan", methods=["POST"])
    @login_required
    def simpan():
        params = (
            session["iduser"],
            session["username"],
            _photo_field("foto"),
            _text_field("nama", 255),
            _int_field("harga"),
            _int_field("berat"),
            _text_field("deskripsi", 1000, required=False),
        )
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO product_details (IdUser, Username, photo, product_name, price, weight, description) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                params,
            )
        conn.commit()
        return redirect(url_for("prodlist"))

    @app.route("/cart")
    @login_required
    def cart():
        with get_db().cursor() as cur:
            cur.execute(
                "SELECT dc.IdDetailCart, dc.amount, p.IdUser AS seller_id, p.photo, p.product_name, p.price "
                "FROM detail_cart dc JOIN cart c ON c.IdCart=dc.IdCart "
                "JOIN product_details p ON p.IdProduct=dc.IdProduct "
                "WHERE c.IdUser=%s ORDER BY p.IdUser, dc.IdDetailCart",
                (session["iduser"],),
            )
            rows = cur.fetchall()
        grouped = {}
        for row in rows:
            grouped.setdefault(row["seller_id"], []).append(row)
        return render_template("cart.html", cart=list(grouped.values()))

    @app.route("/addCart", methods=["POST"])
    @login_required
    def addCart():  # noqa: N802
        id_data = _int_field("id", 1)
        quantity = _int_field("items", 1, 10_000)
        conn = get_db()
        with conn.cursor() as cur:
            reserved = cur.execute(
                "UPDATE product_details SET stock=stock-%s WHERE IdProduct=%s AND stock>=%s",
                (quantity, id_data, quantity),
            )
            if reserved:
                cur.execute(
                    "INSERT INTO detail_cart (IdCart, IdProduct, amount) "
                    "SELECT IdCart, %s, %s FROM cart WHERE IdUser=%s",
                    (id_data, quantity, session["iduser"]),
                )
                if cur.rowcount == 1:
                    conn.commit()
                    return redirect(url_for("cart"))
        conn.rollback()
        det = _product_with_seller("p.IdProduct=%s", (id_data,))
        return render_template("details.html", msg="Stock tidak mencukupi", det=det), 409

    @app.route("/hapuscart/<int:id_data>", methods=["POST"])
    @login_required
    def hapuscart(id_data):
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT dc.IdProduct, dc.amount FROM detail_cart dc JOIN cart c ON c.IdCart=dc.IdCart "
                "WHERE dc.IdDetailCart=%s AND c.IdUser=%s FOR UPDATE",
                (id_data, session["iduser"]),
            )
            row = cur.fetchone()
            if row is None:
                conn.rollback()
                abort(404)
            cur.execute("DELETE FROM detail_cart WHERE IdDetailCart=%s", (id_data,))
            cur.execute(
                "UPDATE product_details SET stock=stock+%s WHERE IdProduct=%s", (row["amount"], row["IdProduct"])
            )
        conn.commit()
        return redirect(url_for("cart"))

    @app.route("/checkout", methods=["POST"])
    @login_required
    def checkout():
        idowner = _int_field("id", 1)
        iduser = session["iduser"]
        with get_db().cursor() as cur:
            cur.execute(
                "SELECT dc.amount, p.product_name, p.price FROM detail_cart dc "
                "JOIN cart c ON c.IdCart=dc.IdCart JOIN product_details p ON p.IdProduct=dc.IdProduct "
                "WHERE c.IdUser=%s AND p.IdUser=%s",
                (iduser, idowner),
            )
            items = cur.fetchall()
            cur.execute("SELECT IdUser, Alamat FROM user_accounts WHERE IdUser IN (%s, %s)", (iduser, idowner))
            addresses = {r["IdUser"]: r["Alamat"] for r in cur.fetchall()}
            cur.execute("SELECT IdCourier, name FROM courier ORDER BY name")
            kurir = cur.fetchall()
        if not items:
            return redirect(url_for("cart"))
        subtotal = sum(i["amount"] * i["price"] for i in items)
        ongkir = MIN_SHIPPING_FEE
        if app.config["GEOCODING_ENABLED"]:
            try:
                ua = app.config["GEOCODER_USER_AGENT"]
                buyer = find_coords(addresses.get(iduser, ""), ua)
                seller = find_coords(addresses.get(idowner, ""), ua)
                if buyer and seller:
                    import geopy.distance

                    ongkir = shipping_fee(geopy.distance.geodesic(buyer, seller).km)
            except Exception:
                app.logger.warning("Geocoding failed, using minimum shipping fee")
        return render_template(
            "checkout.html", cart=items, sum=subtotal, ongkir=ongkir, total=subtotal + ongkir, kurir=kurir
        )


def register_cli(app):
    @app.cli.command("init-db")
    def init_db():
        run_sql_file(SCHEMA_PATH)
        click.echo("Schema created")

    @app.cli.command("seed-demo")
    def seed_demo():
        password = os.environ.get("DEMO_PASSWORD")
        if not password or len(password) < 8:
            raise click.ClickException("Set DEMO_PASSWORD (at least 8 characters)")
        conn = get_db()
        with conn.cursor() as cur:
            for i, (name, city) in enumerate(
                [("Demo Seller A", "Mataram"), ("Demo Seller B", "Jakarta"), ("Demo Seller C", "Bandung")], 1
            ):
                username = f"seller{i}"
                cur.execute(
                    "INSERT IGNORE INTO user_accounts (Name, Username, Email, Alamat, NoHP, Birthdate, Password) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (name, username, f"{username}@example.com", city, "080000000000", date(2000, 1, 1),
                     ph.hash(password)),
                )
                cur.execute(
                    "INSERT IGNORE INTO cart (IdUser) SELECT IdUser FROM user_accounts WHERE Username=%s",
                    (username,),
                )
        conn.commit()
        run_sql_file(SEED_PATH)
        click.echo("Demo data seeded (users seller1..seller3)")


if __name__ == "__main__":
    create_app().run(debug=_env_bool("FLASK_DEBUG", False))
