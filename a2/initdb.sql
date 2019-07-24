/**
 * This is the SQL schema for the password safe database.
 * You should not need to modify this script, although you may if you choose.
 * To run the script on the passwordsafe.db database, run
 *   sqlite3 passwordsafe.db < initdb.sql
 *
 * Most likely, you will not use all the fields in the schema.
 * The lack of documentation is intentional so as to not provide too many hints.
 */
CREATE TABLE IF NOT EXISTS user (
  username varchar(255) PRIMARY KEY,
  passwd varchar(255) NOT NULL,
  email varchar(255) UNIQUE NOT NULL,
  valid boolean DEFAULT false,
  modified datetime
);
CREATE TABLE IF NOT EXISTS user_login (
  username varchar(255) PRIMARY KEY,
  salt varchar(255) NOT NULL,
  challenge varchar(255),
  expires datetime,
  FOREIGN KEY (username) REFERENCES user(username) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS user_session (
  sessionid varchar(255) PRIMARY KEY,
  username varchar(255) UNIQUE NOT NULL,
  expires datetime NOT NULL,
  FOREIGN KEY (username) REFERENCES user(username) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS user_session_sessionid_expires ON user_session(sessionid, expires);
CREATE TABLE IF NOT EXISTS web_session (
  sessionid varchar(255) PRIMARY KEY,
  expires datetime NOT NULL,
  metadata varchar(255)
);
CREATE INDEX IF NOT EXISTS web_session_sessionid_expires ON web_session(sessionid, expires);
CREATE TABLE IF NOT EXISTS user_safe (
  username varchar(255),
  site varchar(255),
  siteuser varchar(255),
  sitepasswd text NOT NULL,
  siteiv varchar(255),
  modified datetime,
  PRIMARY KEY (username, site),
  FOREIGN KEY (username) REFERENCES user(username) ON DELETE CASCADE
);
