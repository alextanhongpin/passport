package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/alextanhongpin/passport"
	"github.com/alextanhongpin/passport/examples/api"
	"github.com/alextanhongpin/pkg/gojwt"

	"github.com/julienschmidt/httprouter"
)

type Service interface {
	Login(ctx context.Context, req LoginRequest) (*LoginResponse, error)
	Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error)
	ChangeEmail(ctx context.Context, req ChangeEmailRequest) (*ChangeEmailResponse, error)
	ChangePassword(ctx context.Context, req ChangePasswordRequest) (*ChangePasswordResponse, error)
	Confirm(ctx context.Context, req ConfirmRequest) (*ConfirmResponse, error)
	ResetPassword(ctx context.Context, req ResetPasswordRequest) (*ResetPasswordResponse, error)
	SendConfirmation(ctx context.Context, req SendConfirmationRequest) (*SendConfirmationResponse, error)
	SendResetPassword(ctx context.Context, req SendResetPasswordRequest) (*SendResetPasswordResponse, error)
}

type Controller struct {
	service Service
	signer  gojwt.Signer
}

func New(service Service, signer gojwt.Signer) *Controller {
	return &Controller{service, signer}
}

func (ctl *Controller) PostLogin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	res, err := ctl.service.Login(ctx, passport.NewCredential(req.Email, req.Password))
	if errors.Is(passport.ErrConfirmationRequired, err) {
		// Send confirmation error.
		res, err := ctl.service.SendConfirmation(ctx, SendConfirmationRequest{
			Email: req.Email,
		})
		if err != nil {
			api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
			return
		}
		fmt.Printf(`
Hi %s,

Confirm your email address here:
%s
		`, req.Email, res.Token)
		api.ResponseJSON(w, api.M{
			"success": true,
			"message": "confirmation email sent",
		}, http.StatusOK)
		return
	}
	if err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	token, err := ctl.signer.Sign(func(c *gojwt.Claims) error {
		c.StandardClaims.Subject = res.User.ID
		return nil
	})
	if err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	api.ResponseJSON(w, api.M{
		"access_token": token,
	}, http.StatusOK)
}

func (ctl *Controller) PostRegister(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.Register(r.Context(), req)
	if err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	// Build JWT Token here. Allow login for the first time even if the
	// email is not confirmed.
	token, err := ctl.signer.Sign(func(c *gojwt.Claims) error {
		c.StandardClaims.Subject = res.User.ID
		return nil
	})
	if err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	api.ResponseJSON(w, api.M{
		"access_token": token,
	}, http.StatusOK)
}

func (ctl *Controller) PostChangeEmail(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req ChangeEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.ChangeEmail(r.Context(), req)
	if err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	api.ResponseJSON(w, res, http.StatusOK)
}

func (ctl *Controller) PutChangePassword(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.ChangePassword(r.Context(), req)
	if err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	api.ResponseJSON(w, res, http.StatusOK)
}

func (ctl *Controller) PutConfirm(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req ConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.Confirm(r.Context(), req)
	if err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	api.ResponseJSON(w, res, http.StatusBadRequest)
}

func (ctl *Controller) PostSendConfirmation(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req SendConfirmationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.SendConfirmation(r.Context(), req)
	if err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	// TODO: Send email here.
	fmt.Printf("Confirm your email address: %s", res.Token)
	api.ResponseJSON(w, res, http.StatusBadRequest)
}

func (ctl *Controller) PutResetPassword(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.ResetPassword(r.Context(), req)
	if err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	api.ResponseJSON(w, res, http.StatusBadRequest)
}

func (ctl *Controller) PostSendResetPassword(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req SendResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.SendResetPassword(r.Context(), req)
	if err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	// TODO: Send email here.
	fmt.Printf(`Reset your password: %s`, res.Token)
	api.ResponseJSON(w, res, http.StatusBadRequest)
}
