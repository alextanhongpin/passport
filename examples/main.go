package main

import (
	"context"
	"database/sql"
)

func main() {
	// passport.New(&repository{db})
}

type repository struct {
	db *sql.DB
}

func (r *repository) WithEmail(ctx context.Context, email string) (passport.User, error) {
	stmt := `
		SELECT 	email_verified, 
			encrypted_password 
		FROM 	login
		WHERE   email = $1
	`
	var u passport.User
	if err := r.db.QueryRow(stmt, email).Scan(
		&u.EmailVerified,
		&u.EncryptedPassword,
	); err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *repository) Create(ctx context.Context, email, encryptedPassword string) (*passport.User, error) {
	stmt := `
		INSERT INTO 
			login (email, encrypted_password)
		VALUES 	($1, $2)
		RETURNING id
	`
	var u passport.User
	if err := r.db.QueryRow(stmt, email, encryptedPassword).Scan(&u.ID); err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *repository) UpdateRecoverable(ctx context.Context, user passport.User, recoverable passport.Recoverable) (bool, error) {
	stmt := `
		UPDATE login
		SET 	reset_password_token = $1,
			reset_password_sent_at = $2,
			allow_password_change = $3
		WHERE 	id = $4
	`
	res, err := r.db.Exec(stmt, recoverable.ResetPasswordToken,
		recoverable.ResetPasswordSentAt,
		recoverable.AllowPasswordChange,
		user.ID,
	)
	if err != nil {
		return nil, err
	}
	rows, err := res.RowsAffected()
	return rows > 0, err
}

func (r *repository) WithResetPasswordToken(ctx context.Context, token string) (*passport.User, error) {
	stmt := `
		SELECT  id,
			reset_password_sent_at,
			allow_password_change,
			encrypted_password
		FROM 	login
		WHERE 	reset_password_token = $1
	`
	var u passport.User
	if err := r.db.QueryRow(stmt, token).Scan(
		&u.ID,
		&u.Recoverable.ResetPasswordSentAt,
		&u.Recoverable.AllowPasswordChange,
		&u.EncryptedPassword,
	); err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *repository) UpdatePassword(ctx context.Context, user *passport.User, encryptedPassword string) (bool, error) {
	stmt := `
		UPDATE 	login
		SET 	encrypted_password = $1
		WHERE 	id = $2
	`
	res, err := r.db.Exec(stmt, encryptedPassword, user.ID)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	return rows > 0, err
}

func (r *repository) UpdateConfirmable(ctx context.Context, user passport.User, confirmable passport.Confirmable, emailVerified bool) (bool, error) {
	stmt := `
		UPDATE 	login
		SET 	email = unconfirmed_email,
			email_verified = $1,
			confirmation_token = $2,
			confirmation_sent_at = $3,
			confirmed_at = $4,
			unconfirmed_email = $5
		WHERE 	id = $6
	`

	res, err := r.db.Exec(stmt,
		emailVerified,
		confirmable.ConfirmationToken,
		confirmable.ConfirmationSentAt,
		confirmable.ConfirmedAt,
		confirmable.UnconfirmedEmail,
		user.ID,
	)
	if err != nil {
		return nil, err
	}
	rows, err := res.RowsAffected()
	return rows > 0, err
}

func (r *repository) WithConfirmationToken(ctx context.Context, token string) (*passport.User, error) {
	stmt := `
		SELECT 	email_verified,
			confirmation_sent_at,
			confirmed_at,
		FROM 	login
		WHERE 	confirmation_token = $1
	`

	var u passport.User
	if err := r.db.QueryRow(stmt, token).Scan(
		&u.EmailVerified,
		&u.Confirmable.ConfirmationSentAt,
		&u.Confirmable.ConfirmedAt,
	); err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *repository) HasEmail(ctx context.Context, email string) (bool, error) {
	stmt := `
		SELECT 	1
		FROM 	login
		WHERE 	EXISTS (SELECT 1 FROM login WHERE email = $1)
	`
	var exists bool
	if err := r.db.QueryRow(stmt, email).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}
