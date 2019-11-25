
-- +migrate Up
CREATE TABLE IF NOT EXISTS login (
	id UUID DEFAULT uuid_generate_v1mc(),
	
	email TEXT UNIQUE NOT NULL,

	-- Authenticatable.
	encrypted_password TEXT NOT NULL DEFAULT '',

	-- Confirmable.
	confirmation_token TEXT UNIQUE NULL,
	confirmation_sent_at TIMESTAMP WITH TIME ZONE NULL,
	confirmed_at TIMESTAMP WITH TIME ZONE NULL,
	unconfirmed_email TEXT NOT NULL DEFAULT '',

	-- Recoverable.
	reset_password_token TEXT UNIQUE NULL,
	reset_password_sent_at TIMESTAMP WITH TIME ZONE NULL,
	allow_password_change BOOLEAN NOT NULL DEFAULT false,

	-- Timestamp.
	created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
	deleted_at TIMESTAMP WITH TIME ZONE NULL,

	PRIMARY KEY (id)
);

CREATE TRIGGER update_login_timestamp BEFORE UPDATE
ON login FOR EACH ROW EXECUTE PROCEDURE
  update_timestamp();

-- +migrate Down
DROP TRIGGER IF EXISTS update_login_timestamp
ON login;

DROP TABLE login;
