CREATE TABLE IF NOT EXISTS users (
    id       BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    role     VARCHAR(16) NOT NULL,
    email    VARCHAR(128) NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(128) NOT NULL,
    price       DECIMAL(10, 2) NOT NULL,
    description VARCHAR(512) NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    quantity   INT NOT NULL,
    address    VARCHAR(256) NOT NULL,
    total      DECIMAL(10, 2) NOT NULL
);

CREATE TABLE IF NOT EXISTS comments (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    product_id BIGINT NOT NULL,
    author     VARCHAR(64) NOT NULL,
    body       VARCHAR(2000) NOT NULL
);
