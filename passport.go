package passport

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/alextanhongpin/passwd"
)

type Passport struct {
	users Repository
}

func New(users Repository) *Passport {
	return &Passport{users: users}
}

func (p *Passport) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	var (
		email    = strings.TrimSpace(req.Email)
		password = strings.TrimSpace(req.Password)
	)
	if err := validateEmailAndPassword(email, password); err != nil {
		return nil, err
	}

	user, err := p.users.WithEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEmailNotFound
	}
	if err != nil {
		return nil, err
	}

	if !user.EmailVerified {
		// TODO: ResendConfirmationEmail, either through:
		// 1. callback (too coupled)
		// 2. match errors and handle it yourself.
		return nil, ErrConfirmationRequired
	}

	match, err := passwd.Compare(user.EncryptedPassword, password)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, ErrEmailOrPasswordInvalid
	}
	return &LoginResponse{
		User: user,
	}, err
}

func (s *Passport) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var (
		email    = strings.TrimSpace(req.Email)
		password = strings.TrimSpace(req.Password)
	)
	if err := validateEmailAndPassword(email, password); err != nil {
		return nil, err
	}

	encrypted, err := passwd.Encrypt(password)
	if err != nil {
		return nil, fmt.Errorf("encrypt password failed: %w", err)
	}

	user, err := p.users.Create(ctx, email, encrypted)
	if err != nil {
		return nil, fmt.Errorf("create user failed: %w", err)
	}

	return &RegisterResponse{
		User: user,
	}, nil
}

func (s *ServiceImpl) SendResetPassword(ctx context.Context, req SendResetPasswordRequest) (*SendResetPasswordResponse, error) {
	email := strings.TrimSpace(req.Email)
	if err := validateEmail(email); err != nil {
		return nil, err
	}

	user, err := p.users.WithEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEmailNotFound
	}
	if err != nil {
		return nil, err
	}

	// This should replace the old token if multiple reset password is invoked.
	recoverable := NewRecoverable()
	success, err := p.users.UpdateRecoverable(ctx, user, recoverable)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEmailNotFound
	}
	if err != nil {
		return nil, err
	}

	// Return enough data for us to send the email.
	return &ResetPasswordResponse{
		Token: recoverable.ResetPasswordToken,
	}, nil
}

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
	if err := validatePassword(password); err != nil {
		return nil, err
	}

	user, err := p.users.WithResetPasswordToken(ctx, token)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEmailNotFound
	}
	if err != nil {
		return nil, err
	}

	recoverable := user.Recoverable
	if !recoverable.IsValid() {
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
	match, err := passwd.Compare(user.EncryptedPassword, password)
	if err != nil {
		return nil, err
	}
	if match {
		return nil, ErrPasswordUsed
	}

	encrypted, err := passwd.Encrypt(password)
	if err != nil {
		return nil, fmt.Errorf("encrypt password failed: %w", err)
	}

	success, err := p.users.UpdatePassword(ctx, user, encrypted)
	if err != nil {
		return nil, err
	}

	var recoverable Recoverable
	success, err := p.users.UpdateRecoverable(ctx, user, recoverable)
	if err != nil {
		return nil, err
	}

	// Clear older sessions when changing password.
	return &ResetPasswordResponse{
		Success: success,
	}, nil
}

func (s *Passport) SendConfirmation(ctx context.Context, req SendConfirmationRequest) (*SendConfirmationResponse, error) {
	var (
		email = strings.TrimSpace(req.Email)
	)
	if err := validateEmail(email); err != nil {
		return nil, err
	}

	user, err := p.users.WithEmail(ctx, email)
	// NOTE: Should just fail silently - you should receive an email if
	// your email exists.
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEmailNotFound
	}
	if err != nil {
		return nil, err
	}

	// Don't resend for users whose email is already confirmed.
	if user.EmailVerified {
		return nil, ErrEmailVerified
	}

	confirmable := NewConfirmable(email)
	// This will set email verified to false.
	emailVerified := false
	ok, err := p.users.UpdateConfirmable(ctx, user, confirmable, emailVerified)
	if err != nil {
		return nil, err
	}
	// Return the confirmable in order to send the email.
	return &SendConfirmationResponse{
		Token: confirmable.ConfirmationToken,
	}, nil

}

func (s *Passport) Confirm(ctx context.Context, req ConfirmRequest) (*ConfirmResponse, error) {
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return nil, ErrTokenRequired
	}
	user, err := p.users.WithConfirmationToken(ctx, token)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenNotFound
	}
	if err != nil {
		return nil, err
	}

	// Skip if verified.
	if user.EmailVerified {
		return nil, nil
	}

	if !user.Confirmable.IsValid() {
		return nil, ErrTokenExpired
	}
	emailVerified := true
	var confirmable Confirmable
	success, err := p.users.UpdateConfirmable(ctx, user, confirmable, emailVerified)
	if err != nil {
		return nil, err
	}

	return &ConfirmationResponse{
		Success: success,
	}, nil
}

func (s *Passport) ChangeEmail(ctx context.Context, req ChangeEmailRequest) (*ChangeEmailResponse, error) {
	email = strings.TrimSpace(req.Email)
	if err := validateEmail(email); err != nil {
		return nil, err
	}

	exists, err := p.users.HasEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrEmailExists
	}

	confirmable := NewConfirmable(email)
	ok, err := p.users.UpdateConfirmable(ctx, user, confirmable)
	if err != nil {
		return nil, err
	}

	// Return the confirmable in order to send the email.
	return &SendConfirmationResponse{
		Token: confirmable.ConfirmationToken,
	}, nil
}

func (s *Passport) ChangePassword(ctx context.Context, req ChangePasswordRequest) (*ChangePasswordResponse, error) {
	var (
		userID          = strings.TrimSpace(req.ContextUserID)
		password        = strings.TrimSpace(req.Password)
		confirmPassword = strings.TrimSpace(req.ConfirmPassword)
	)
	if password == "" || confirmPassword == "" {
		return nil, ErrPasswordRequired
	}
	if password != confirmPassword {
		return nil, ErrPasswordDoNotMatch
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}

	user, err := p.users.Find(userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	match, err := passwd.Compare(user.EncryptedPassword, password)
	if err != nil {
		return nil, err
	}
	if match {
		return nil, ErrPasswordUsed
	}

	encrypted, err := passwd.Encrypt(password)
	if err != nil {
		return nil, fmt.Errorf("encrypt password failed: %w", err)
	}

	success, err := p.users.UpdatePassword(ctx, user, encrypted)
	if err != nil {
		return nil, err
	}
	return &ChangePasswordResponse{
		Success: success,
	}, nil
}
