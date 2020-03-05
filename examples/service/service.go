package service

import (
	"context"
	"database/sql"
	"errors"

	"github.com/alextanhongpin/passport"
	"github.com/alextanhongpin/passport/connector"
	"github.com/alextanhongpin/passport/examples/database"
	"github.com/alextanhongpin/passport/examples/mailer"
	"github.com/alextanhongpin/passport/usecase"

	"github.com/alextanhongpin/pkg/gojwt"
)

type stdoutMailer interface {
	Send(mailer.Mail) error
}
type encoderComparer interface {
	Compare(cipherText, plainText []byte) error
	Encode(plainText []byte) (string, error)
}

type Auth struct {
	login          *usecase.Login
	register       *usecase.Register
	changeEmail    *usecase.ChangeEmail
	changePassword *usecase.ChangePassword
	confirm        *usecase.Confirm
	// resetPassword        *usecase.ResetPassword
	sendConfirmation     *usecase.SendConfirmation
	requestResetPassword *usecase.RequestResetPassword

	mailer stdoutMailer
	signer gojwt.Signer
	db     *sql.DB
	ec     encoderComparer
}

func New(db *sql.DB, signer gojwt.Signer) *Auth {
	r := connector.NewPostgres(db)
	ec := passport.NewArgon2Password()
	tokenGenerator := passport.NewTokenGenerator()
	m := mailer.NewNoopMailer()

	return &Auth{
		db:     db,
		ec:     ec,
		mailer: m,
		signer: signer,
		login: usecase.NewLogin(
			usecase.LoginOptions{
				Repository: r,
				Comparer:   ec,
			},
		),
		register: usecase.NewRegister(
			usecase.RegisterOptions{
				Repository: r,
				Encoder:    ec,
			},
		),
		changeEmail: usecase.NewChangeEmail(
			usecase.ChangeEmailOptions{
				Repository:     r,
				TokenGenerator: tokenGenerator,
			},
		),
		changePassword: usecase.NewChangePassword(
			usecase.ChangePasswordOptions{
				Repository:      r,
				EncoderComparer: ec,
			},
		),
		confirm: usecase.NewConfirm(
			usecase.ConfirmOptions{
				Repository:                r,
				ConfirmationTokenValidity: passport.ConfirmationTokenValidity,
			},
		),
		// resetPassword: usecase.NewResetPassword(
		//         usecase.ResetPasswordOptions{
		//                 Repository:               r,
		//                 EncoderComparer:          ec,
		//                 RecoverableTokenValidity: passport.RecoverableTokenValidity,
		//         },
		// ),
		sendConfirmation: usecase.NewSendConfirmation(
			usecase.SendConfirmationOptions{
				Repository:     r,
				TokenGenerator: tokenGenerator,
			},
		),
		requestResetPassword: usecase.NewRequestResetPassword(
			usecase.RequestResetPasswordOptions{
				Repository:     r,
				TokenGenerator: tokenGenerator,
			},
		),
	}
}

type (
	LoginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	LoginResponse struct {
		Token string `json:"token"`
	}
)

func (a *Auth) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	user, err := a.login.Exec(ctx, passport.NewCredential(req.Email, req.Password))
	if errors.Is(passport.ErrConfirmationRequired, err) {
		_, err = a.SendConfirmation(ctx, SendConfirmationRequest{
			Email: req.Email,
		})
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	token, err := a.signer.Sign(func(c *gojwt.Claims) error {
		c.StandardClaims.Subject = user.ID
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &LoginResponse{
		Token: token,
	}, nil
}

type (
	RegisterRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	RegisterResponse struct {
		Token string `json:"token"`
	}
)

func (a *Auth) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	user, err := a.register.Exec(ctx, passport.NewCredential(req.Email, req.Password))
	if err != nil {
		return nil, err
	}
	token, err := a.signer.Sign(func(c *gojwt.Claims) error {
		c.StandardClaims.Subject = user.ID
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &RegisterResponse{
		Token: token,
	}, nil
}

type (
	ChangeEmailRequest struct {
		CurrentUserID string `json:"-"`
		Email         string `json:"email"`
	}
	ChangeEmailResponse struct {
	}
)

func (a *Auth) ChangeEmail(ctx context.Context, req ChangeEmailRequest) (*ChangeEmailResponse, error) {
	token, err := a.changeEmail.Exec(ctx, passport.NewUserID(req.CurrentUserID), passport.NewEmail(req.Email))
	if err != nil {
		return nil, err
	}

	mail := mailer.NewChangeEmail(req.Email, token)
	if err := a.mailer.Send(mail); err != nil {
		return nil, err
	}

	return &ChangeEmailResponse{}, nil
}

type (
	ChangePasswordRequest struct {
		CurrentUserID   string `json:"-"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	ChangePasswordResponse struct {
	}
)

func (a *Auth) ChangePassword(ctx context.Context, req ChangePasswordRequest) (*ChangePasswordResponse, error) {
	err := a.changePassword.Exec(ctx,
		passport.NewUserID(req.CurrentUserID),
		passport.NewPassword(req.Password),
		passport.NewPassword(req.ConfirmPassword))
	if err != nil {
		return nil, err
	}
	return &ChangePasswordResponse{}, nil
}

type (
	ConfirmRequest struct {
		Token string `json:"token"`
	}
	ConfirmResponse struct {
	}
)

func (a *Auth) Confirm(ctx context.Context, req ConfirmRequest) (*ConfirmResponse, error) {
	err := a.confirm.Exec(ctx, passport.NewToken(req.Token))
	if err != nil {
		return nil, err
	}
	return &ConfirmResponse{}, nil
}

type (
	ResetPasswordRequest struct {
		Token           string `json:"token"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	ResetPasswordResponse struct {
		ID string `json:"id"`
	}
)

func (a *Auth) ResetPassword(ctx context.Context, req ResetPasswordRequest) (*ResetPasswordResponse, error) {
	var user *passport.User
	err := database.WithTransaction(a.db, func(tx connector.Tx) error {
		resetPassword := usecase.NewResetPassword(
			usecase.ResetPasswordOptions{
				Repository:               connector.NewPostgres(tx),
				EncoderComparer:          a.ec,
				RecoverableTokenValidity: passport.RecoverableTokenValidity,
			},
		)
		var err error
		user, err = resetPassword.Exec(
			ctx,
			passport.NewToken(req.Token),
			passport.NewPassword(req.Password),
			passport.NewPassword(req.ConfirmPassword),
		)
		return err
	})
	if err != nil {
		return nil, err
	}

	return &ResetPasswordResponse{
		ID: user.ID,
	}, nil
}

type (
	SendConfirmationRequest struct {
		Email string `json:"email"`
	}
	SendConfirmationResponse struct {
	}
)

func (a *Auth) SendConfirmation(ctx context.Context, req SendConfirmationRequest) (*SendConfirmationResponse, error) {
	token, err := a.sendConfirmation.Exec(ctx, passport.NewEmail(req.Email))
	if err != nil {
		return nil, err
	}
	mail := mailer.NewSendConfirmation(req.Email, token)
	if err := a.mailer.Send(mail); err != nil {
		return nil, err
	}
	return &SendConfirmationResponse{}, nil
}

type (
	RequestResetPasswordRequest struct {
		Email string `json:"email"`
	}
	RequestResetPasswordResponse struct {
	}
)

func (a *Auth) RequestResetPassword(ctx context.Context, req RequestResetPasswordRequest) (*RequestResetPasswordResponse, error) {
	token, err := a.requestResetPassword.Exec(ctx, passport.NewEmail(req.Email))
	if err != nil {
		return nil, err
	}

	mail := mailer.NewResetPassword(req.Email, token)
	if err := a.mailer.Send(mail); err != nil {
		return nil, err
	}

	return &RequestResetPasswordResponse{}, nil
}
