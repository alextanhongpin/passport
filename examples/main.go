package main

import (
	"context"
	"encoding/json"
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
	router.POST("/user/emails", ctl.PostChangeEmail)
	router.PUT("/user/passwords", ctl.PutChangePassword)
	router.GET("/user/confirmations", ctl.GetConfirm)
	router.POST("/confirmations", ctl.PostSendConfirmation)
	router.PUT("/passwords", ctl.PutResetPassword)
	router.POST("/passwords", ctl.PostSendResetPassword)

	http.ListenAndServe(":8080", router)
}

type Controller struct {
	service *AuthService
}

func (ctl *Controller) PostLogin(w http.Response, r *http.Request, ps httprouter.Params) {
	var req passport.LoginRequest
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.login(r.Context(), req)
	if err != nil {
		// Send confirmation email here if required.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Build JWT Token here
	// res.User.ID
	json.NewEncoder(w).Encode(res)
}

func (ctl *Controller) PostRegister(w http.Response, r *http.Request, ps httprouter.Params) {
	var req passport.RegisterRequest
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.register(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(res)
}

func (ctl *Controller) PostChangeEmail(w http.Response, r *http.Request, ps httprouter.Params) {
	var req passport.ChangeEmailRequest
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.changeEmail(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(res)
}

func (ctl *Controller) PostChangePassword(w http.Response, r *http.Request, ps httprouter.Params) {
	var req passport.ChangePasswordRequest
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.changePassword(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(res)
}

func (ctl *Controller) GetConfirm(w http.Response, r *http.Request, ps httprouter.Params) {
	var req passport.ConfirmRequest
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.confirm(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(res)
}

func (ctl *Controller) PostSendConfirmation(w http.Response, r *http.Request, ps httprouter.Params) {
	var req passport.SendConfirmationRequest
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.sendConfirmation(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// TODO: Send email here.
	json.NewEncoder(w).Encode(res)
}

func (ctl *Controller) PutResetPassword(w http.Response, r *http.Request, ps httprouter.Params) {
	var req passport.ResetPasswordRequest
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.resetPassword(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// TODO: Send email here.
	json.NewEncoder(w).Encode(res)
}

func (ctl *Controller) PostSendResetPassword(w http.Response, r *http.Request, ps httprouter.Params) {
	var req passport.SendResetPassword
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.sendResetPassword(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// TODO: Send email here.
	json.NewEncoder(w).Encode(res)
}
