package mailer

import (
	"fmt"
)

const (
	from = "company@mail.com"
)

type Mail struct {
	From    string
	To      string
	Subject string
	Body    string
}

type sender interface {
	Send(Mail) error
}

type NoopMailer struct {
}

func NewNoopMailer() *NoopMailer {
	return &NoopMailer{}
}

func (n *NoopMailer) Send(mail Mail) error {
	fmt.Printf(`From: %s
To: %s
Subject: %s
Body:
%s`,
		mail.From,
		mail.To,
		mail.Subject,
		mail.Body,
	)
	return nil
}

func NewChangeEmail(to, token string) Mail {
	return Mail{
		From:    from,
		To:      to,
		Subject: "Change your Email",
		Body: fmt.Sprintf(`Confirm your email to change by clicking on this link:

Token: %s
		`, token),
	}
}

func NewSendConfirmation(to, token string) Mail {
	return Mail{
		From:    from,
		To:      to,
		Subject: "Confirm your email",
		Body:    fmt.Sprintf(`Confirm your email address: %s`, token),
	}
}

func NewResetPassword(to, token string) Mail {
	return Mail{
		From:    from,
		To:      to,
		Subject: "Reset your password",
		Body:    fmt.Sprintf(`Reset your password: %s`, token),
	}
}
