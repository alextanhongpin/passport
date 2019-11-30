package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/alextanhongpin/passport"
	"github.com/alextanhongpin/passport/examples/database"
	"github.com/alextanhongpin/pkg/authhdr"
	"github.com/alextanhongpin/pkg/gojwt"

	"github.com/julienschmidt/httprouter"
)

type Service interface {
	Login(ctx context.Context, req passport.LoginRequest) (*passport.LoginResponse, error)
	Register(ctx context.Context, req passport.RegisterRequest) (*passport.RegisterResponse, error)
	ChangeEmail(ctx context.Context, req passport.ChangeEmailRequest) (*passport.ChangeEmailResponse, error)
	ChangePassword(ctx context.Context, req passport.ChangePasswordRequest) (*passport.ChangePasswordResponse, error)
	Confirm(ctx context.Context, req passport.ConfirmRequest) (*passport.ConfirmResponse, error)
	ResetPassword(ctx context.Context, req passport.ResetPasswordRequest) (*passport.ResetPasswordResponse, error)
	SendConfirmation(ctx context.Context, req passport.SendConfirmationRequest) (*passport.SendConfirmationResponse, error)
	SendResetPassword(ctx context.Context, req passport.SendResetPasswordRequest) (*passport.SendResetPasswordResponse, error)
}

type M map[string]interface{}

func withAuth(signer gojwt.Signer, next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		validator := authhdr.New()
		if err := validator.Extract(r); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims, err := signer.Verify(validator.Token())
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		// Insert into context...
		fmt.Println(claims)

		next(w, r, ps)
		// do stuff
	}
}

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

func NewAuthService(db *sql.DB) *AuthService {
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

func (a *AuthService) Login(ctx context.Context, req passport.LoginRequest) (*passport.LoginResponse, error) {
	return a.login(ctx, req)
}

func (a *AuthService) Register(ctx context.Context, req passport.RegisterRequest) (*passport.RegisterResponse, error) {
	return a.register(ctx, req)
}

func (a *AuthService) ChangeEmail(ctx context.Context, req passport.ChangeEmailRequest) (*passport.ChangeEmailResponse, error) {
	return a.changeEmail(ctx, req)
}

func (a *AuthService) ChangePassword(ctx context.Context, req passport.ChangePasswordRequest) (*passport.ChangePasswordResponse, error) {
	return a.changePassword(ctx, req)
}

func (a *AuthService) Confirm(ctx context.Context, req passport.ConfirmRequest) (*passport.ConfirmResponse, error) {
	return a.confirm(ctx, req)
}

func (a *AuthService) ResetPassword(ctx context.Context, req passport.ResetPasswordRequest) (*passport.ResetPasswordResponse, error) {
	return a.resetPassword(ctx, req)
}

func (a *AuthService) SendConfirmation(ctx context.Context, req passport.SendConfirmationRequest) (*passport.SendConfirmationResponse, error) {
	return a.sendConfirmation(ctx, req)
}

func (a *AuthService) SendResetPassword(ctx context.Context, req passport.SendResetPasswordRequest) (*passport.SendResetPasswordResponse, error) {
	return a.sendResetPassword(ctx, req)
}

func main() {
	db, err := database.Setup()
	if err != nil {
		panic(err)
	}
	defer db.Close()
	signer := gojwt.New(gojwt.Option{
		Secret:       []byte("secret"),
		ExpiresAfter: 1 * time.Hour,
	})
	authsvc := NewAuthService(db)

	router := httprouter.New()
	ctl := NewController(authsvc, signer)
	router.GET("/", indexHandler)
	router.GET("/private", withAuth(signer, indexHandler))
	router.POST("/login", ctl.PostLogin)
	router.POST("/register", ctl.PostRegister)
	router.POST("/user/emails", withAuth(signer, ctl.PostChangeEmail))
	router.PUT("/user/passwords", withAuth(signer, ctl.PutChangePassword))
	router.PUT("/confirmations", ctl.PutConfirm)
	router.POST("/confirmations", ctl.PostSendConfirmation)
	router.PUT("/passwords", ctl.PutResetPassword)
	router.POST("/passwords", ctl.PostSendResetPassword)

	log.Println("Listening to port *:8080. Press ctrl + c to cancel.")
	http.ListenAndServe(":8080", router)
}

func writeJSON(w http.ResponseWriter, res interface{}, code int) {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(res)
}

func indexHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	writeJSON(w, M{"ok": true}, http.StatusOK)
}

type Controller struct {
	service Service
	signer  gojwt.Signer
}

func NewController(service Service, signer gojwt.Signer) *Controller {
	return &Controller{service, signer}
}

func (ctl *Controller) PostLogin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req passport.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	res, err := ctl.service.Login(ctx, req)
	if errors.Is(passport.ErrConfirmationRequired, err) {
		// Send confirmation error.
		res, err := ctl.service.SendConfirmation(ctx, passport.SendConfirmationRequest{
			Email: req.Email,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Printf(`
Hi %s,

Confirm your email address here:
%s
		`, req.Email, res.Token)

		json.NewEncoder(w).Encode(M{
			"success": true,
			"message": "confirmation email sent",
		})
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token, err := ctl.signer.Sign(func(c *gojwt.Claims) error {
		c.StandardClaims.Subject = res.User.ID
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(M{
		"access_token": token,
	})
}

func (ctl *Controller) PostRegister(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req passport.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.Register(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Build JWT Token here. Allow login for the first time even if the
	// email is not confirmed.
	token, err := ctl.signer.Sign(func(c *gojwt.Claims) error {
		c.StandardClaims.Subject = res.User.ID
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(M{
		"access_token": token,
	})
}

func (ctl *Controller) PostChangeEmail(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req passport.ChangeEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.ChangeEmail(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(res)
}

func (ctl *Controller) PutChangePassword(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req passport.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.ChangePassword(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(res)
}

func (ctl *Controller) PutConfirm(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req passport.ConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.Confirm(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(res)
}

func (ctl *Controller) PostSendConfirmation(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req passport.SendConfirmationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.SendConfirmation(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// TODO: Send email here.
	fmt.Printf("Confirm your email address: %s", res.Token)
	json.NewEncoder(w).Encode(res)
}

func (ctl *Controller) PutResetPassword(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req passport.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.ResetPassword(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(res)
}

func (ctl *Controller) PostSendResetPassword(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req passport.SendResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.SendResetPassword(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// TODO: Send email here.
	fmt.Printf(`Reset your password: %s`, res.Token)
	json.NewEncoder(w).Encode(res)
}
