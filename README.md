[![](https://godoc.org/github.com/alextanhongpin/passport?status.svg)](http://godoc.org/github.com/alextanhongpin/passport)
[![CircleCI](https://circleci.com/gh/alextanhongpin/passport.svg?style=svg)](https://circleci.com/gh/alextanhongpin/passport)
##  passport


**WORK IN PROGRESS**

Reusable authentication module for golang. Setting up authentication for any golang microservice should be easy.

## Installation

```bash
$ go get github.com/alextanhongpin/passport
```

## Migrations

The following columns is required in order to use this package. This can be added to an existing table or a new one.

Postgres:

```sql
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
```

## Provider

You just need to implement a Repository to read and write data to the database of your choice. __Passport__ only implements the business logic and does not assume the choice of storage. And example of the repository implementation can be seen in `postgres.go`.
