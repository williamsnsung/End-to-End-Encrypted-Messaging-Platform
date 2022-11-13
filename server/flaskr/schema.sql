DROP TABLE IF EXISTS user;

CREATE TABLE user (
	username TEXT PRIMARY KEY,
	password TEXT NOT NULL,
	certificate TEXT NOT NULL,
    online BOOLEAN NOT NULL
);