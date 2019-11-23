package passport

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alextanhongpin/passwd"
)

var (
	ErrConfirmationRequired   = errors.New("confirmation required")
	ErrEmailNotFound          = errors.New("email not found")
	ErrPasswordRequired       = errors.New("password required")
	ErrEmailRequired          = errors.New("email required")
	ErrEmailOrPasswordInvalid = errors.New("email or password is invalid")
	ErrPasswordUsed           = errors.New("password cannot be reused")
)
var (
	ConfirmationTokenValidity = 1 * time.Hour
	RecoverableTokenValidity  = 1 * time.Hour
)

type Service interface {
	Login(context.Context, LoginRequest) (*LoginResponse, error)
	Logout(context.context, LogoutRequest) (*LogoutResponse, error)
	Register(context.Context, RegisterRequest) (*RegisterResponse, error)
	SendResetPassword(context.Context, SendResetPasswordRequest) (*SendResetPasswordResponse, error)
	ResetPassword(context.Context, ResetPasswordRequest) (*ResetPasswordResponse, error)
	ChangePassword(context.Context, ChangePasswordRequest) (*ChangePasswordResponse, error)
	Confirm(context.Context, ConfirmRequest) (*ConfirmEmailResponse, error)
	SendConfirmation(context.Context, SendConfirmationRequest) (*SendConfirmationResponse, error)
}

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

type serviceImpl struct {
	sessions SessionRepository
	users    UserRepository
}

func validateEmailPassword(email, password string) error {
	if email == "" {
		return ErrEmailRequired
	}
	if !ValidateEmail(email) {
		return ErrInvalidEmail
	}

	if len(password) < 6 {
		return ErrPasswordRequired
	}
	return nil
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

func (s *serviceImpl) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	var (
		email    = strings.TrimSpace(req.Email)
		password = strings.TrimSpace(req.Password)
	)
	if err := validateEmailPassword(email, password); err != nil {
		return nil, err
	}

	user, err := s.users.WithEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if !user.EmailVerified {
		// TODO: ResendConfirmationEmail.
		return nil, ErrConfirmationRequired
	}
	match, err := user.ComparePassword(password)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, ErrEmailOrPasswordInvalid
	}
	// if err := s.sessions.Create(user, req); err != nil {
	//         return nil, err
	// }
	return user, err
}

func (s *serviceImpl) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var (
		email    = strings.TrimSpace(req.Email)
		password = strings.TrimSpace(req.Password)
	)
	if err := validateEmailPassword(email, password); err != nil {
		return nil, err
	}
	encrypted, err := passwd.Encrypt(req.Password)
	if err != nil {
		return nil, fmt.Errorf("encrypt password failed: %w", err)
	}
	user, err := s.users.Create(ctx, email, encrypted)
	if err != nil {
		return nil, fmt.Errorf("create user failed: %w", err)
	}
	// if err := s.sessions.Create(user, req); err != nil {
	//         return nil, err
	// }
	return user, nil
}

func (s *serviceImpl) Logout(ctx context.Context, req LogoutRequest) (*LogoutResponse, error) {
	// if req.ClearAllDeviceSessions {
	//         s.sessions.Delete(req.ContextUserID)
	// } else {
	//         s.sessions.Delete(req.ContextUserID, req.ContextJTI)
	// }

	return nil, nil
}

type (
	SendResetPasswordRequest struct {
		Email string
	}
	SendResetPasswordResponse struct {
		User User
	}
)

func (s *ServiceImpl) SendResetPassword(ctx context.Context, req SendResetPasswordRequest) (*SendResetPasswordResponse, error) {
	email := strings.TrimSpace(req.Email)
	if email == "" {
		return nil, ErrEmailRequired
	}
	if err := ValidateEmail(email); err != nil {
		return nil, ErrInvalidEmail
	}
	//user, err := s.users.WithEmail(req.Email)
	//if err != nil {
	//	return nil, err
	//}
	// This should replace the old token if multiple reset password is invoked.
	recoverable := Recoverable{
		// Instead of using the Postgres UUID, we set it here.
		// This allows us to change the implementation at the
		// application level.
		ResetPasswordToken:  uuid.Must(uuid.NewV4()),
		ResetPasswordSentAt: time.Now(),
		AllowPasswordChange: true,
	}
	user, err := s.users.ResetPassword(email, recoverable)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEmailNotFound
	}
	if err != nil {
		return nil, err
	}

	// Clear older sessions when changing password.
	// return s.Logout(ctx, req)

	// Return enough data for us to send the email.
	return &ResetPasswordResponse{
		Success: true,
		User:    user,
	}, nil
}

type (
	ResetPasswordRequest struct {
		Token           string
		Password        string
		ConfirmPassword string
	}
	ResetPasswordResponse struct {
	}
)

func (s *ServiceImpl) ResetPassword(ctx context.Context, req ResetPasswordRequest) (*ResetPasswordResponse, error) {
	var (
		token           = strings.TrimSpace(req.Token)
		password        = strings.TrimSpace(req.Password)
		confirmPassword = strings.TrimSpace(req.ConfirmPassword)
	)
	if token == "" {
		return nil, ErrTokenInvalid
	}
	if password == "" || confirmPassword == "" {
		return nil, ErrPasswordRequired
	}

	// Password must be equal.
	if !passwd.ConstantTimeCompare(password, confirmPassword) {
		return nil, ErrPasswordInvalid
	}
	user, err := s.users.WithResetPasswordToken(token)
	if err != nil {
		return nil, err
	}
	recoverable := user.Recoverable
	if time.Since(recoverable.ResetPasswordSentAt) > RecoverableTokenValidity {
		return nil, ErrTokenExpired
	}
	if !recoverable.AllowPasswordChange {
		return nil, ErrPasswordChangeNotAllowed
	}
	// Email must be verified first. Not really...user might not verified
	// their account for a long time.
	// if user.EmailVerified {
	//         return nil, ErrConfirmationRequired
	// }
	// Password must not be the same as the old passwords.
	match, _ := user.ComparePassword(password)
	if match {
		return nil, ErrPasswordUsed
	}

	encrypted, err := passwd.Encrypt(password)
	if err != nil {
		return nil, fmt.Errorf("encrypt password failed: %w", err)
	}
	success, err := s.users.ChangePassword(user, encrypted)
	if err != nil {
		return nil, err
	}
	// Clear older sessions when changing password.
	// return s.Logout(ctx, req)
}

func (s *serviceImpl) ResendConfirmation(ctx context.Context, req ResendConfirmationRequest) (*ResendConfirmationResponse, error) {
	var (
		email = strings.TrimSpace(req.Email)
	)
	user, err := s.users.WithEmail(email)
	if err != nil {
		return nil, err
	}

	// Don't resend for users whose email is already confirmed.
	if user.EmailVerified {
		return nil, errors.New("user is verified")
	}

	confirmable := Confirmable{
		ConfirmationToken:  uuid.Must(uuid.NewV4()),
		ConfirmationSentAt: time.Now(),
		UnconfirmedEmail:   email,
	}
	ok, err := s.users.CreateConfirmation(user, confirmable)
	if err != nil {
		return nil, err
	}
	// Return the confirmable in order to send the email.
	return &ResendConfirmationResponse{
		User:        user,
		Confirmable: confirmable,
	}, nil

}

type (
	ConfirmRequest struct {
		Token string `json:"token"`
	}
	ConfirmResponse struct {
		Success bool `json:"success"`
	}
)

func (s *serviceImpl) Confirm(ctx context.Context, req ConfirmRequest) (*ConfirmResponse, error) {
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return nil, ErrTokenRequired
	}
	user, err := s.users.FindConfirmationToken(token)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}

	// Skip if verified.
	if user.EmailVerified {
		return nil, nil
	}

	if time.Since(user.Confirmable.ConfirmationSentAt) > ConfirmationTokenValidity {
		return nil, ErrTokenExpired
	}

	success, err := s.users.UpdateConfirmation(token)
	if err != nil {
		return nil, err
	}

	// Return if user is already verified.
	// Check if the confirmation sent at expired.
	// Update confirmedAt email.
	// Set email to confirmed email.
	// Clear unconfirmed email.
	// https://stackoverflow.com/questions/26306188/storing-unconfirmed-email-column-on-the-sign-up
}
