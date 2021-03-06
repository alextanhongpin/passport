package connector

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/alextanhongpin/passport"
)

// Postgres represents an implementation of the repository for User.
type Postgres struct {
	tx Tx
}

// NewPostgres returns a new pointer to Postgres struct.
func NewPostgres(tx Tx) *Postgres {
	return &Postgres{tx}
}

func (p *Postgres) WithTx(tx Tx) *Postgres {
	return &Postgres{tx}
}

func (p *Postgres) WithEmail(ctx context.Context, email string) (*passport.User, error) {
	stmt := selectUserStmt(table, "email = $1")
	return getUser(p.tx, stmt, email)
}

func (p *Postgres) Create(ctx context.Context, email, encryptedPassword string) (*passport.User, error) {
	stmt := fmt.Sprintf(`
		INSERT INTO %s
			(email, encrypted_password, unconfirmed_email)
		VALUES 	($1, $2, $1)
		RETURNING id
	`, table)
	var u passport.User
	if err := p.tx.QueryRow(stmt, email, encryptedPassword).Scan(&u.ID); err != nil {
		return nil, err
	}
	return &u, nil
}

func (p *Postgres) UpdateRecoverable(ctx context.Context, email string, recoverable passport.Recoverable) (bool, error) {
	stmt := fmt.Sprintf(`
		UPDATE  %s
		SET 	reset_password_token = $1,
			reset_password_sent_at = $2,
			allow_password_change = $3
		WHERE 	email = $4
	`, table)
	res, err := p.tx.Exec(stmt,
		NewNullString(recoverable.ResetPasswordToken),
		NewNullTime(recoverable.ResetPasswordSentAt),
		recoverable.AllowPasswordChange,
		email,
	)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	return rows > 0, err
}

func (p *Postgres) WithResetPasswordToken(ctx context.Context, token string) (*passport.User, error) {
	stmt := selectUserStmt(table, "reset_password_token = $1")
	return getUser(p.tx, stmt, token)
}

func (p *Postgres) UpdatePassword(ctx context.Context, userID string, encryptedPassword string) (bool, error) {
	stmt := fmt.Sprintf(`
		UPDATE  %s
		SET 	encrypted_password = $1
		WHERE 	id = $2
	`, table)
	res, err := p.tx.Exec(stmt, encryptedPassword, userID)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	return rows > 0, err
}

func (p *Postgres) UpdateConfirmable(ctx context.Context, email string, confirmable passport.Confirmable) (bool, error) {
	stmt := fmt.Sprintf(`
		UPDATE  %s
		SET 	email = COALESCE(NULLIF($4, ''), email),
			confirmation_token = $1,
			confirmation_sent_at = $2,
			confirmed_at = COALESCE($3, now()),
			unconfirmed_email = $4
		WHERE 	email = $5
	`, table)

	res, err := p.tx.Exec(stmt,
		NewNullString(confirmable.ConfirmationToken),
		NewNullTime(confirmable.ConfirmationSentAt),
		NewNullTime(confirmable.ConfirmedAt),
		confirmable.UnconfirmedEmail,
		email,
	)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	return rows > 0, err
}

func (p *Postgres) WithConfirmationToken(ctx context.Context, token string) (*passport.User, error) {
	stmt := selectUserStmt(table, "confirmation_token = $1")
	return getUser(p.tx, stmt, token)
}

func (p *Postgres) HasEmail(ctx context.Context, email string) (bool, error) {
	stmt := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %s WHERE email = $1
		)
	`, table)
	var exists bool
	if err := p.tx.QueryRow(stmt, email).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func (p *Postgres) Find(ctx context.Context, id string) (*passport.User, error) {
	stmt := selectUserStmt(table, "id = $1")
	return getUser(p.tx, stmt, id)
}

func getUser(tx Tx, stmt string, arguments ...interface{}) (*passport.User, error) {
	var u passport.User
	var resetPasswordToken, confirmationToken sql.NullString
	var resetPasswordSentAt, confirmationSentAt, confirmedAt sql.NullTime
	var encryptedPassword string
	if err := tx.QueryRow(stmt, arguments...).Scan(
		&u.ID,
		&u.CreatedAt,
		&u.Email,
		&encryptedPassword,
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
	u.EncryptedPassword = passport.NewPassword(encryptedPassword)
	return &u, nil
}
