package passport

import "context"

type Service interface {
	Login(context.Context, LoginRequest) (*LoginResponse, error)
	Logout(context.context, LogoutRequest) (*LogoutResponse, error)
	Register(context.Context, RegisterRequest) (*RegisterResponse, error)
	SendResetPassword(context.Context, SendResetPasswordRequest) (*SendResetPasswordResponse, error)
	ResetPassword(context.Context, ResetPasswordRequest) (*ResetPasswordResponse, error)
	ChangePassword(context.Context, ChangePasswordRequest) (*ChangePasswordResponse, error)
	Confirm(context.Context, ConfirmRequest) (*ConfirmEmailResponse, error)
	SendConfirmation(context.Context, SendConfirmationRequest) (*SendConfirmationResponse, error)
	ChangeEmail(context.Context, ChangeEmailRequest) (*ChangeEmailResponse, error)
}

type (
	LoginRequest struct {
		Email     string
		Password  string
		ClientIP  string
		UserAgent string
	}

	LoginResponse struct {
		User User
	}
)
type (
	LogoutRequest struct {
		UserID string `validate:"required" conform:"trim"`
	}
	LogoutResponse struct {
		Success bool
	}
)

type (
	RegisterRequest struct {
		Email     string `validate:"required,email" conform:"trim"`
		Password  string `validate:"required,min=6" conform:"trim"`
		ClientIP  string
		UserAgent string
	}
	RegisterResponse struct {
		User User
	}
)

type (
	SendResetPasswordRequest struct {
		Email string
	}
	SendResetPasswordResponse struct {
		User User
	}
)

type (
	ResetPasswordRequest struct {
		Token           string
		Password        string
		ConfirmPassword string
	}
	ResetPasswordResponse struct {
		User User
	}
)
type (
	SendConfirmationRequest struct {
		Email string
	}
	SendConfirmationResponse struct {
		Token string
	}
)

type (
	ConfirmRequest struct {
		Token string `json:"token"`
	}
	ConfirmResponse struct {
		Success bool `json:"success"`
	}
)

type (
	ChangeEmailRequest struct {
		ContextUserID string
		Email         string
	}
	ChangeEmailResponse struct {
		Token string
	}
)
