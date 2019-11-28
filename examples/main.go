package main

import (
	"context"
	"net/http"

	"github.com/alextanhongpin/passport"
	"github.com/alextanhongpin/passport/examples/database"
)

type AuthService struct {
	login             passport.Login
	register          passport.Register
	changeEmail       passport.ChangeEmail
	changePassword    passport.ChangePassword
	confirm           passport.Confirm
	resetPassword     passport.ResetPassword
	sendConfirmation  passport.SendConfirmation
	sendResetPassword passport.SendResetPassword
}

func NewAuthService(db) *AuthService {
	repo := passport.NewPostgres(db)
	return &AuthService{
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
func (a *AuthService) Login(ctx context.Context, req *passport.LoginRequest) (*passport.LoginResponse, error) {
	return a.login(ctx, req)
}

func (a *AuthService) Register(ctx context.Context, req *passport.RegisterRequest) (*passport.RegisterResponse, error) {
	return a.register(ctx, req)
}

func (a *AuthService) ChangeEmail(ctx context.Context, req *passport.ChangeEmailRequest) (*passport.ChangeEmailResponse, error) {
	return a.changeEmail(ctx, req)
}

func (a *AuthService) ChangePassword(ctx context.Context, req *passport.ChangePasswordRequest) (*passport.ChangePasswordResponse, error) {
	return a.changePassword(ctx, req)
}

func (a *AuthService) Confirm(ctx context.Context, req *passport.ConfirmRequest) (*passport.ConfirmResponse, error) {
	return a.confirm(ctx, req)
}

func (a *AuthService) ResetPassword(ctx context.Context, req *passport.ResetPasswordRequest) (*passport.ResetPasswordResponse, error) {
	return a.resetPassword(ctx, req)
}

func (a *AuthService) SendConfirmation(ctx context.Context, req *passport.SendConfirmationRequest) (*passport.SendConfirmationResponse, error) {
	return a.sendConfirmation(ctx, req)
}

func (a *AuthService) SendResetPassword(ctx context.Context, req *passport.SendResetPasswordRequest) (*passport.SendResetPasswordResponse, error) {
	return a.sendResetPassword(ctx, req)
}

func main() {
	db, err := database.Setup()
	if err != nil {
		panic(err)
	}
	defer db.Close()

	authsvc := NewAuthService(db)

	router := httprouter.New()
	router.POST("/login", ctl.PostLogin)
	router.POST("/register", ctl.PostRegister)
	router.POST("/me/emails", ctl.PostChangeEmail)
	router.PUT("/me/passwords", ctl.PutChangePasswords)
	router.GET("/user/confirmations", ctl.GetConfirm)
	router.POST("/user/confirmations", ctl.SendConfirmation)
	router.POST("/user/passwords", ctl.ResetPassword)
	router.POST("/user/passwords", ctl.SendResetPassword)

	http.ListenAndServe(":8080", router)
}

type Controller struct {
	service *AuthService
}

// func( ctl *Controller ) GetLogin()
