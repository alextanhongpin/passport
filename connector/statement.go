package connector

import "fmt"

func selectUserStmt(table, where string) string {
	return fmt.Sprintf(`
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
		FROM 	%s
		WHERE   %s
	`, table, where)
}
