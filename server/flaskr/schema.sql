DROP TABLE IF EXISTS user;

CREATE TABLE user (
	username TEXT PRIMARY KEY,
	password TEXT NOT NULL,
	public_key TEXT NOT NULL,
    online BOOLEAN NOT NULL
);