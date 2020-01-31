package service

import (
	"context"
	"database/sql"

	"github.com/alextanhongpin/passport"
)

type Auth struct {
	login                *passport.Login
	register             *passport.Register
	changeEmail          *passport.ChangeEmail
	changePassword       *passport.ChangePassword
	confirm              *passport.Confirm
	resetPassword        *passport.ResetPassword
	sendConfirmation     *passport.SendConfirmation
	requestResetPassword *passport.RequestResetPassword
}

func NewAuth(db *sql.DB) *Auth {
	r := passport.NewPostgres(db)
	ec := passport.NewArgon2Password()
	tokenGenerator := passport.NewTokenGenerator()
	return &Auth{
		login: passport.NewLogin(
			passport.LoginOptions{
				Repository: r,
				Comparer:   ec,
			},
		),
		register: passport.NewRegister(
			passport.RegisterOptions{
				Repository: r,
				Encoder:    ec,
			},
		),
		changeEmail: passport.NewChangeEmail(
			passport.ChangeEmailOptions{
				Repository:     r,
				TokenGenerator: tokenGenerator,
			},
		),
		changePassword: passport.NewChangePassword(
			passport.ChangePasswordOptions{
				Repository:      r,
				EncoderComparer: ec,
			},
		),
		confirm: passport.NewConfirm(
			passport.ConfirmOptions{
				Repository:                r,
				ConfirmationTokenValidity: passport.ConfirmationTokenValidity,
			},
		),
		resetPassword: passport.NewResetPassword(
			passport.ResetPasswordOptions{
				Repository:               r,
				EncoderComparer:          ec,
				RecoverableTokenValidity: passport.RecoverableTokenValidity,
			},
		),
		sendConfirmation: passport.NewSendConfirmation(
			passport.SendConfirmationOptions{
				Repository:     r,
				TokenGenerator: tokenGenerator,
			},
		),
		requestResetPassword: passport.NewRequestResetPassword(
			passport.RequestResetPasswordOptions{
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
		User passport.User `json:"user"`
	}
)

func (a *Auth) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	user, err := a.login.Exec(ctx, passport.NewCredential(req.Email, req.Password))
	if err != nil {
		return nil, err
	}
	return &LoginResponse{
		User: *user,
	}, nil
}

type (
	RegisterRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	RegisterResponse struct {
		User passport.User `json:"user"`
	}
)

func (a *Auth) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	user, err := a.register.Exec(ctx, passport.NewCredential(req.Email, req.Password))
	if err != nil {
		return nil, err
	}
	return &RegisterResponse{
		User: *user,
	}, nil
}

type (
	ChangeEmailRequest struct {
		CurrentUserID string `json:"-"`
		Email         string `json:"email"`
	}
	ChangeEmailResponse struct {
		Token string `json:"token"`
	}
)

func (a *Auth) ChangeEmail(ctx context.Context, req ChangeEmailRequest) (*ChangeEmailResponse, error) {
	token, err := a.changeEmail.Exec(ctx, passport.NewUserID(req.CurrentUserID), passport.NewEmail(req.Email))
	if err != nil {
		return nil, err
	}
	return &ChangeEmailResponse{
		Token: token,
	}, nil
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
	user, err := a.resetPassword.Exec(
		ctx,
		passport.NewToken(req.Token),
		passport.NewPassword(req.Password),
		passport.NewPassword(req.ConfirmPassword),
	)
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
		Token string `json:"token"`
	}
)

func (a *Auth) SendConfirmation(ctx context.Context, req SendConfirmationRequest) (*SendConfirmationResponse, error) {
	token, err := a.sendConfirmation.Exec(ctx, passport.NewEmail(req.Email))
	if err != nil {
		return nil, err
	}
	return &SendConfirmationResponse{
		Token: token,
	}, nil
}

type (
	RequestResetPasswordRequest struct {
		Email string `json:"email"`
	}
	RequestResetPasswordResponse struct {
		Token string `json:"token"`
	}
)

func (a *Auth) RequestResetPassword(ctx context.Context, req RequestResetPasswordRequest) (*RequestResetPasswordResponse, error) {
	token, err := a.requestResetPassword.Exec(ctx, passport.NewEmail(req.Email))
	if err != nil {
		return nil, err
	}
	return &RequestResetPasswordResponse{
		Token: token,
	}, nil
}
