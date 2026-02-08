

CREATE TABLE users
(
    id       BIGINT AUTO_INCREMENT NOT NULL,
    name     VARCHAR(255) NOT NULL,
    email    VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role varchar(20) default 'USER' not null,
    CONSTRAINT `PRIMARY` PRIMARY KEY (id)
);

