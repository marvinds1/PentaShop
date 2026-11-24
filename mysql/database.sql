CREATE TABLE IF NOT EXISTS user_accounts (
    IdUser INT NOT NULL AUTO_INCREMENT,
    Name VARCHAR(64) NOT NULL,
    Username VARCHAR(32) NOT NULL,
    Email VARCHAR(255) NOT NULL,
    Password VARCHAR(255) NOT NULL,
    Alamat VARCHAR(255) NOT NULL,
    NoHP VARCHAR(20) NOT NULL,
    Birthdate DATE NOT NULL,
    registration_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (IdUser),
    UNIQUE KEY uq_user_username (Username),
    UNIQUE KEY uq_user_email (Email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS product_details (
    IdProduct INT NOT NULL AUTO_INCREMENT,
    IdUser INT NOT NULL,
    Username VARCHAR(32) NOT NULL,
    dates DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    photo VARCHAR(500),
    product_name VARCHAR(255) NOT NULL,
    price INT NOT NULL,
    total_buy INT NOT NULL DEFAULT 0,
    weight INT NOT NULL,
    description VARCHAR(1000),
    rating DECIMAL(2, 1) NOT NULL DEFAULT 0,
    stock INT NOT NULL DEFAULT 0,
    PRIMARY KEY (IdProduct),
    KEY ix_product_user (IdUser),
    KEY ix_product_dates (dates),
    KEY ix_product_name (product_name),
    CONSTRAINT fk_product_user FOREIGN KEY (IdUser) REFERENCES user_accounts (IdUser) ON DELETE CASCADE,
    CONSTRAINT ck_product_stock CHECK (stock >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS cart (
    IdCart INT NOT NULL AUTO_INCREMENT,
    IdUser INT NOT NULL,
    PRIMARY KEY (IdCart),
    UNIQUE KEY uq_cart_user (IdUser),
    CONSTRAINT fk_cart_user FOREIGN KEY (IdUser) REFERENCES user_accounts (IdUser) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS detail_cart (
    IdDetailCart INT NOT NULL AUTO_INCREMENT,
    IdCart INT NOT NULL,
    IdProduct INT NOT NULL,
    amount INT NOT NULL,
    PRIMARY KEY (IdDetailCart),
    KEY ix_detail_cart_cart (IdCart),
    KEY ix_detail_cart_product (IdProduct),
    CONSTRAINT fk_detail_cart_cart FOREIGN KEY (IdCart) REFERENCES cart (IdCart) ON DELETE CASCADE,
    CONSTRAINT fk_detail_cart_product FOREIGN KEY (IdProduct) REFERENCES product_details (IdProduct) ON DELETE CASCADE,
    CONSTRAINT ck_detail_cart_amount CHECK (amount > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS courier (
    IdCourier INT NOT NULL AUTO_INCREMENT,
    name VARCHAR(64) NOT NULL,
    PRIMARY KEY (IdCourier)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
