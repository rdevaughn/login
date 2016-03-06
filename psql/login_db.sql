-- In terminal:
-- createdb -O $USER login_db
-- psql -d login_db

CREATE USER login_app WITH PASSWORD 'loginapppw';
ALTER ROLE login_app SET client_encoding TO 'utf8';
ALTER ROLE login_app SET default_transaction_isolation TO 'read committed';
ALTER ROLE login_app SET timezone TO 'EST';
GRANT ALL PRIVILEGES ON DATABASE login_db TO login_app;
\q

-- psql -d login_db -U login_app

CREATE TABLE users (
  id serial NOT NULL,
  email TEXT NOT NULL,
  hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  PRIMARY KEY(email));
