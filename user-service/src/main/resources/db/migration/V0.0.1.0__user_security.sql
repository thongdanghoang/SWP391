-- NOTE: base entity
-- id                 UUID         NOT NULL,
-- version            INTEGER      NOT NULL,
-- NOTE: auditable entity
-- created_by         VARCHAR(64)  NOT NULL,
-- created_date       TIMESTAMP    NOT NULL,
-- last_modified_by   VARCHAR(64)  NOT NULL,
-- last_modified_date TIMESTAMP    NOT NULL,
CREATE TABLE IF NOT EXISTS users
(
    id                 UUID         NOT NULL,
    version            INTEGER      NOT NULL,
    created_by         VARCHAR(64)  NOT NULL,
    created_date       TIMESTAMP    NOT NULL,
    last_modified_by   VARCHAR(64)  NOT NULL,
    last_modified_date TIMESTAMP    NOT NULL,
    username           VARCHAR(64)  NOT NULL,
    password           VARCHAR(72)  NOT NULL,
    email              VARCHAR(320) NOT NULL,
    enabled            BOOLEAN      NOT NULL
);
ALTER TABLE users
    ADD CONSTRAINT users_pk PRIMARY KEY (id);
ALTER TABLE users
    ADD CONSTRAINT users_uk_username UNIQUE (username);

CREATE TABLE IF NOT EXISTS authorities
(
    id                 UUID        NOT NULL,
    version            INTEGER     NOT NULL,
    created_by         VARCHAR(64) NOT NULL,
    created_date       TIMESTAMP   NOT NULL,
    last_modified_by   VARCHAR(64) NOT NULL,
    last_modified_date TIMESTAMP   NOT NULL,
    name               VARCHAR(64) NOT NULL
);
ALTER TABLE authorities
    ADD CONSTRAINT authorities_pk PRIMARY KEY (id);

CREATE TABLE IF NOT EXISTS users_authorities
(
    user_id      UUID NOT NULL,
    authority_id UUID NOT NULL
);
ALTER TABLE users_authorities
    ADD CONSTRAINT users_authorities_pk PRIMARY KEY (user_id, authority_id);
ALTER TABLE users_authorities
    ADD CONSTRAINT users_authorities_fk_users FOREIGN KEY (user_id) REFERENCES users (id);
CREATE INDEX IF NOT EXISTS users_authorities_idx_user_id ON users_authorities (user_id);
ALTER TABLE users_authorities
    ADD CONSTRAINT users_authorities_fk_authorities FOREIGN KEY (authority_id) REFERENCES authorities (id);
CREATE INDEX IF NOT EXISTS users_authorities_idx_authority_id ON users_authorities (authority_id);
