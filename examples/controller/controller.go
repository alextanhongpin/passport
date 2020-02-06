package controller

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/alextanhongpin/passport/examples/api"
	"github.com/alextanhongpin/passport/examples/service"

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
}

func New(service Service) *Controller {
	return &Controller{service}
}

func (ctl *Controller) PostLogin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req service.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}
	res, err := ctl.service.Login(r.Context(), req)
	if err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	if res == nil {
		api.JSON(w, api.M{
			"message": "Please confirm your email",
		}, http.StatusOK)
		return
	}

	api.JSON(w, res, http.StatusOK)
}

func (ctl *Controller) PostRegister(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req service.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	res, err := ctl.service.Register(r.Context(), req)
	if err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	api.JSON(w, res, http.StatusOK)
}

func (ctl *Controller) PostChangeEmail(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req service.ChangeEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	res, err := ctl.service.ChangeEmail(r.Context(), req)
	if err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	api.JSON(w, res, http.StatusOK)
}

func (ctl *Controller) PutChangePassword(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req service.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	res, err := ctl.service.ChangePassword(r.Context(), req)
	if err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	api.JSON(w, res, http.StatusOK)
}

func (ctl *Controller) PutConfirm(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req service.ConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	res, err := ctl.service.Confirm(r.Context(), req)
	if err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	api.JSON(w, res, http.StatusBadRequest)
}

func (ctl *Controller) PostSendConfirmation(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req service.SendConfirmationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	res, err := ctl.service.SendConfirmation(r.Context(), req)
	if err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	api.JSON(w, res, http.StatusBadRequest)
}

func (ctl *Controller) PutResetPassword(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req service.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	res, err := ctl.service.ResetPassword(r.Context(), req)
	if err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	api.JSON(w, res, http.StatusBadRequest)
}

func (ctl *Controller) PostRequestResetPassword(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var req service.RequestResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	res, err := ctl.service.RequestResetPassword(r.Context(), req)
	if err != nil {
		api.JSON(w, api.NewError(err), http.StatusBadRequest)
		return
	}

	api.JSON(w, res, http.StatusBadRequest)
}
