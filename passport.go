package passport

import (
	"context"
	"database/sql"
	"errors"
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

	match, err := passwd.Compare(user.EncryptedPassword, password)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, ErrEmailOrPasswordInvalid
	}

	if !user.IsConfirmationRequired() {
		return nil, ErrConfirmationRequired
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
		return nil, err
	}

	user, err := p.users.Create(ctx, email, encrypted)
	if err != nil {
		return nil, err
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

	recoverable := NewRecoverable()
	success, err := p.users.UpdateRecoverable(ctx, email, recoverable)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEmailNotFound
	}
	if err != nil {
		return nil, err
	}

	// Return enough data for us to send the email.
	return &ResetPasswordResponse{
		Success: success,
		Token:   recoverable.ResetPasswordToken,
	}, nil
}

func (s *ServiceImpl) ResetPassword(ctx context.Context, req ResetPasswordRequest) (*ResetPasswordResponse, error) {
	var (
		token           = strings.TrimSpace(req.Token)
		password        = strings.TrimSpace(req.Password)
		confirmPassword = strings.TrimSpace(req.ConfirmPassword)
	)
	if token == "" {
		return nil, ErrTokenRequired
	}
	if password != confirmPassword {
		return nil, ErrPasswordDoNotMatch
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
	// NOTE: Must email be verified first? Not really...user might not
	// verified their account for a long time.
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
		return nil, err
	}

	success, err := p.users.UpdatePassword(ctx, user.ID, encrypted)
	if err != nil {
		return nil, err
	}
	if !success {
		return &ResetPasswordResponse{
			Success: success,
		}
	}

	var recoverable Recoverable
	success, err := p.users.UpdateRecoverable(ctx, user.Email, recoverable)
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
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEmailNotFound
	}
	if err != nil {
		return nil, err
	}

	// Don't resend for users whose email is already confirmed.
	if user.Confirmable.IsVerified() {
		return nil, ErrEmailVerified
	}

	confirmable := NewConfirmable(email)
	ok, err := p.users.UpdateConfirmable(ctx, email, confirmable)
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

	if user.Confirmable.IsVerified() {
		return nil, ErrEmailVerified
	}

	if !user.Confirmable.IsValid() {
		return nil, ErrTokenExpired
	}

	// Reset confirmable.
	var confirmable Confirmable
	success, err := p.users.UpdateConfirmable(ctx, user.Email, confirmable)
	if err != nil {
		return nil, err
	}

	return &ConfirmationResponse{
		Success: success,
	}, nil
}

func (s *Passport) ChangeEmail(ctx context.Context, req ChangeEmailRequest) (*ChangeEmailResponse, error) {
	var (
		email  = strings.TrimSpace(req.Email)
		userID = strings.TrimSpace(req.ContextUserID)
	)

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
	user, err := p.users.Find(userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, UserNotFound
	}
	if err != nil {
		return nil, err
	}

	if !user.Confirmable.IsVerified() {
		return nil, ErrConfirmationRequired
	}

	var confirmable = NewConfirmable(email)
	success, err := p.users.UpdateConfirmable(ctx, user.Email, confirmable)
	if err != nil {
		return nil, err
	}

	// Return the confirmable in order to send the email.
	return &SendConfirmationResponse{
		Success: success,
		Token:   confirmable.ConfirmationToken,
	}, nil
}

func (s *Passport) ChangePassword(ctx context.Context, req ChangePasswordRequest) (*ChangePasswordResponse, error) {
	var (
		userID          = strings.TrimSpace(req.ContextUserID)
		password        = strings.TrimSpace(req.Password)
		confirmPassword = strings.TrimSpace(req.ConfirmPassword)
	)
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
		return nil, err
	}

	success, err := p.users.UpdatePassword(ctx, user.ID, encrypted)
	if err != nil {
		return nil, err
	}
	return &ChangePasswordResponse{
		Success: success,
	}, nil
}
