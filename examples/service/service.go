package service

import (
	"context"
	"database/sql"

	"github.com/alextanhongpin/passport"
)

type Auth struct {
	login             passport.Login
	register          passport.Register
	changeEmail       passport.ChangeEmail
	changePassword    passport.ChangePassword
	confirm           passport.Confirm
	resetPassword     passport.ResetPassword
	sendConfirmation  passport.SendConfirmation
	sendResetPassword passport.SendResetPassword
}

func NewAuth(db *sql.DB) *Auth {
	repo := passport.NewPostgres(db)
	return &Auth{
		login:             passport.NewLogin(repo),
		register:          passport.NewRegister(repo),
		changeEmail:       passport.NewChangeEmail(repo),
		changePassword:    passport.NewChangePassword(repo),
		confirm:           passport.NewConfirm(repo),
		resetPassword:     passport.NewResetPassword(repo),
		sendConfirmation:  passport.NewSendConfirmation(repo),
		sendResetPassword: passport.NewSendResetPassword(repo),
	}
}

func (a *Auth) Login(ctx context.Context, req passport.LoginRequest) (*passport.LoginResponse, error) {
	return a.login(ctx, req)
}

func (a *Auth) Register(ctx context.Context, req passport.RegisterRequest) (*passport.RegisterResponse, error) {
	return a.register(ctx, req)
}

func (a *Auth) ChangeEmail(ctx context.Context, req passport.ChangeEmailRequest) (*passport.ChangeEmailResponse, error) {
	return a.changeEmail(ctx, req)
}

func (a *Auth) ChangePassword(ctx context.Context, req passport.ChangePasswordRequest) (*passport.ChangePasswordResponse, error) {
	return a.changePassword(ctx, req)
}

func (a *Auth) Confirm(ctx context.Context, req passport.ConfirmRequest) (*passport.ConfirmResponse, error) {
	return a.confirm(ctx, req)
}

func (a *Auth) ResetPassword(ctx context.Context, req passport.ResetPasswordRequest) (*passport.ResetPasswordResponse, error) {
	return a.resetPassword(ctx, req)
}

func (a *Auth) SendConfirmation(ctx context.Context, req passport.SendConfirmationRequest) (*passport.SendConfirmationResponse, error) {
	return a.sendConfirmation(ctx, req)
}

func (a *Auth) SendResetPassword(ctx context.Context, req passport.SendResetPasswordRequest) (*passport.SendResetPasswordResponse, error) {
	return a.sendResetPassword(ctx, req)
}
