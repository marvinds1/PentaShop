from pathlib import Path

import pymysql
from dbutils.pooled_db import PooledDB
from flask import current_app, g

SCHEMA_PATH = Path(__file__).parent / "mysql" / "database.sql"
SEED_PATH = Path(__file__).parent / "mysql" / "seed.sql"


def init_pool(app):
    cfg = app.config
    app.extensions["db_pool"] = PooledDB(
        creator=pymysql,
        maxconnections=cfg["DB_POOL_SIZE"],
        mincached=0,
        blocking=True,
        reset=True,
        host=cfg["MYSQL_HOST"],
        port=cfg["MYSQL_PORT"],
        user=cfg["MYSQL_USER"],
        password=cfg["MYSQL_PASSWORD"],
        database=cfg["MYSQL_DB"],
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )
    app.teardown_appcontext(close_db)


def get_db():
    if "db" not in g:
        g.db = current_app.extensions["db_pool"].connection()
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def run_sql_file(path):
    statements = [s.strip() for s in Path(path).read_text().split(";") if s.strip()]
    conn = get_db()
    with conn.cursor() as cur:
        for stmt in statements:
            cur.execute(stmt)
    conn.commit()
