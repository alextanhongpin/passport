package passport

import (
	"context"
	"database/sql"
	"time"
)

// Postgres represents an implementation of the repository for User.
type Postgres struct {
	db *sql.DB
}

// NewPostgres returns a new pointer to Postgres struct.
func NewPostgres(db *sql.DB) *Postgres {
	return &Postgres{db}
}

func (p *Postgres) WithEmail(ctx context.Context, email string) (*User, error) {
	stmt := `
		SELECT 	id,
			created_at,
			email,
			encrypted_password,
			reset_password_token,
			reset_password_sent_at,
			allow_password_change,
			confirmation_token,
			confirmation_sent_at,
			confirmed_at,
			unconfirmed_email
		FROM 	login
		WHERE   email = $1	
	`
	return getUser(p.db, stmt, email)
}

func (p *Postgres) Create(ctx context.Context, email, encryptedPassword string) (*User, error) {
	stmt := `
		INSERT INTO login 
			(email, encrypted_password, unconfirmed_email)
		VALUES 	($1, $2, $1)
		RETURNING id
	`
	var u User
	if err := p.db.QueryRow(stmt, email, encryptedPassword).Scan(&u.ID); err != nil {
		return nil, err
	}
	return &u, nil
}

func (p *Postgres) UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error) {
	stmt := `
		UPDATE  login
		SET 	reset_password_token = $1,
			reset_password_sent_at = $2,
			allow_password_change = $3
		WHERE 	email = $4
	`

	var resetPasswordToken *string
	if recoverable.ResetPasswordToken != "" {
		resetPasswordToken = &recoverable.ResetPasswordToken
	}

	var resetPasswordSentAt *time.Time
	if !recoverable.ResetPasswordSentAt.IsZero() {
		resetPasswordSentAt = &recoverable.ResetPasswordSentAt
	}
	res, err := p.db.Exec(stmt,
		resetPasswordToken,
		resetPasswordSentAt,
		recoverable.AllowPasswordChange,
		email,
	)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	return rows > 0, err
}

func (p *Postgres) WithResetPasswordToken(ctx context.Context, token string) (*User, error) {
	stmt := `
		SELECT 	id,
			created_at,
			email,
			encrypted_password,
			reset_password_token,
			reset_password_sent_at,
			allow_password_change,
			confirmation_token,
			confirmation_sent_at,
			confirmed_at,
			unconfirmed_email
		FROM 	login
		WHERE   reset_password_token = $1	
	`
	return getUser(p.db, stmt, token)
}

func (p *Postgres) UpdatePassword(ctx context.Context, userID string, encryptedPassword string) (bool, error) {
	stmt := `
		UPDATE 	login
		SET 	encrypted_password = $1
		WHERE 	id = $2
	`
	res, err := p.db.Exec(stmt, encryptedPassword, userID)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	return rows > 0, err
}

func (p *Postgres) UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error) {
	stmt := `
		UPDATE 	login
		SET 	email = COALESCE(NULLIF($4, ''), email),
			confirmation_token = $1,
			confirmation_sent_at = $2,
			confirmed_at = COALESCE($3, now()),
			unconfirmed_email = $4
		WHERE 	email = $5
	`

	var confirmationToken *string
	if confirmable.ConfirmationToken != "" {
		confirmationToken = &confirmable.ConfirmationToken
	}
	var confirmationTokenSentAt *time.Time
	if !confirmable.ConfirmationSentAt.IsZero() {
		confirmationTokenSentAt = &confirmable.ConfirmationSentAt
	}
	var confirmedAt *time.Time
	if !confirmable.ConfirmedAt.IsZero() {
		confirmedAt = &confirmable.ConfirmedAt
	}
	res, err := p.db.Exec(stmt,
		confirmationToken,
		confirmationTokenSentAt,
		confirmedAt,
		confirmable.UnconfirmedEmail,
		email,
	)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	return rows > 0, err
}

func (p *Postgres) WithConfirmationToken(ctx context.Context, token string) (*User, error) {
	stmt := `
		SELECT 	id,
			created_at,
			email,
			encrypted_password,
			reset_password_token,
			reset_password_sent_at,
			allow_password_change,
			confirmation_token,
			confirmation_sent_at,
			confirmed_at,
			unconfirmed_email
		FROM 	login
		WHERE   confirmation_token = $1	
	`
	return getUser(p.db, stmt, token)
}

func (p *Postgres) HasEmail(ctx context.Context, email string) (bool, error) {
	stmt := `
		SELECT EXISTS (SELECT 1 FROM login WHERE email = $1)
	`
	var exists bool
	if err := p.db.QueryRow(stmt, email).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func (p *Postgres) Find(ctx context.Context, id string) (*User, error) {
	stmt := `
		SELECT 	id,
			created_at,
			email,
			encrypted_password,
			reset_password_token,
			reset_password_sent_at,
			allow_password_change,
			confirmation_token,
			confirmation_sent_at,
			confirmed_at,
			unconfirmed_email
		FROM 	login
		WHERE   id = $1	
	`
	return getUser(p.db, stmt, id)
}

func getUser(db *sql.DB, stmt string, arguments ...interface{}) (*User, error) {
	var u User
	var resetPasswordToken, confirmationToken sql.NullString
	var resetPasswordSentAt, confirmationSentAt, confirmedAt sql.NullTime
	if err := db.QueryRow(stmt, arguments...).Scan(
		&u.ID,
		&u.CreatedAt,
		&u.Email,
		&u.EncryptedPassword,
		&resetPasswordToken,
		&resetPasswordSentAt,
		&u.Recoverable.AllowPasswordChange,
		&confirmationToken,
		&confirmationSentAt,
		&confirmedAt,
		&u.Confirmable.UnconfirmedEmail,
	); err != nil {
		return nil, err
	}

	if resetPasswordToken.Valid {
		u.Recoverable.ResetPasswordToken = resetPasswordToken.String
	}
	if confirmationToken.Valid {
		u.Confirmable.ConfirmationToken = confirmationToken.String
	}
	if resetPasswordSentAt.Valid {
		u.Recoverable.ResetPasswordSentAt = resetPasswordSentAt.Time
	}
	if confirmationSentAt.Valid {
		u.Confirmable.ConfirmationSentAt = confirmationSentAt.Time
	}
	if confirmedAt.Valid {
		u.Confirmable.ConfirmedAt = confirmedAt.Time
	}
	return &u, nil
}
