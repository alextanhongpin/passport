package passport

import "context"

type Service interface {
	ChangeEmail(context.Context, ChangeEmailRequest) (*ChangeEmailResponse, error)
	ChangePassword(context.Context, ChangePasswordRequest) (*ChangePasswordResponse, error)
	Confirm(context.Context, ConfirmRequest) (*ConfirmEmailResponse, error)
	Login(context.Context, LoginRequest) (*LoginResponse, error)
	Register(context.Context, RegisterRequest) (*RegisterResponse, error)
	ResetPassword(context.Context, ResetPasswordRequest) (*ResetPasswordResponse, error)
	SendConfirmation(context.Context, SendConfirmationRequest) (*SendConfirmationResponse, error)
	SendResetPassword(context.Context, SendResetPasswordRequest) (*SendResetPasswordResponse, error)
}

type (
	ChangeEmailRequest struct {
		ContextUserID string
		Email         string
	}
	ChangeEmailResponse struct {
		Token string
	}
)

type (
	ChangePasswordRequest struct {
		ContextUserID   string
		Password        string
		ConfirmPassword string
	}
	ChangePasswordResponse struct {
		Success bool
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
	LoginRequest struct {
		Email    string
		Password string
		// ClientIP  string
		// UserAgent string
	}

	LoginResponse struct {
		User User
	}
)

type (
	RegisterRequest struct {
		Email    string
		Password string
		// ClientIP  string
		// UserAgent string
	}
	RegisterResponse struct {
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
	SendResetPasswordRequest struct {
		Email string
	}
	SendResetPasswordResponse struct {
		User User
	}
)
