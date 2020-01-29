package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/alextanhongpin/passport"
	"github.com/alextanhongpin/passport/examples/api"
	"github.com/alextanhongpin/passport/examples/service"
	"github.com/alextanhongpin/pkg/gojwt"

	"github.com/julienschmidt/httprouter"
)

type Service interface {
	ChangeEmail(ctx context.Context, req service.ChangeEmailRequest) (*service.ChangeEmailResponse, error)
	ChangePassword(ctx context.Context, req service.ChangePasswordRequest) (*service.ChangePasswordResponse, error)
	Confirm(ctx context.Context, req service.ConfirmRequest) (*service.ConfirmResponse, error)
	Login(ctx context.Context, req service.LoginRequest) (*service.LoginResponse, error)
	Register(ctx context.Context, req service.RegisterRequest) (*service.RegisterResponse, error)
	RequestResetPassword(ctx context.Context, req service.RequestResetPasswordRequest) (*service.RequestResetPasswordResponse, error)
	ResetPassword(ctx context.Context, req service.ResetPasswordRequest) (*service.ResetPasswordResponse, error)
	SendConfirmation(ctx context.Context, req service.SendConfirmationRequest) (*service.SendConfirmationResponse, error)
}

type Controller struct {
	service Service
	signer  gojwt.Signer
}

func New(service Service, signer gojwt.Signer) *Controller {
	return &Controller{service, signer}
}

func (ctl *Controller) PostLogin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req service.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	res, err := ctl.service.Login(ctx, req)
	if errors.Is(passport.ErrConfirmationRequired, err) {
		// Send confirmation error.
		res, err := ctl.service.SendConfirmation(ctx, service.SendConfirmationRequest{
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
	var req service.RegisterRequest
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
	var req service.ChangeEmailRequest
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
	var req service.ChangePasswordRequest
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
	var req service.ConfirmRequest
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
	var req service.SendConfirmationRequest
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
	var req service.ResetPasswordRequest
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

func (ctl *Controller) PostRequestResetPassword(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req service.RequestResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.RequestResetPassword(r.Context(), req)
	if err != nil {
		api.ResponseJSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	// TODO: Send email here.
	fmt.Printf(`Reset your password: %s`, res.Token)
	api.ResponseJSON(w, res, http.StatusBadRequest)
}
