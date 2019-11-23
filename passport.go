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

type serviceImpl struct {
	users Repository
}

func (s *serviceImpl) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	var (
		email    = strings.TrimSpace(req.Email)
		password = strings.TrimSpace(req.Password)
	)
	if err := validateEmailAndPassword(email, password); err != nil {
		return nil, err
	}

	user, err := s.users.WithEmail(ctx, email)
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

func (s *serviceImpl) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var (
		email    = strings.TrimSpace(req.Email)
		password = strings.TrimSpace(req.Password)
	)
	if err := validateEmailAndPassword(email, password); err != nil {
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

	return &RegisterResponse{
		User: user,
	}, nil
}

func (s *ServiceImpl) SendResetPassword(ctx context.Context, req SendResetPasswordRequest) (*SendResetPasswordResponse, error) {
	email := strings.TrimSpace(req.Email)
	if err := validateEmail(email); err != nil {
		return nil, err
	}

	user, err := s.users.WithEmail(email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEmailNotFound
	}
	if err != nil {
		return nil, err
	}
	// This should replace the old token if multiple reset password is invoked.
	recoverable := Recoverable{
		// Instead of using the Postgres UUID, we set it here.
		// This allows us to change the implementation at the
		// application level.
		ResetPasswordToken:  uuid.Must(uuid.NewV4()),
		ResetPasswordSentAt: time.Now(),
		AllowPasswordChange: true,
	}

	success, err := s.users.UpdateRecoverable(user, recoverable)
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
	user, err := s.users.WithResetPasswordToken(token)
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
	success, err := s.users.UpdatePassword(user, encrypted)
	if err != nil {
		return nil, err
	}

	recoverable := Recoverable{
		// Instead of using the Postgres UUID, we set it here.
		// This allows us to change the implementation at the
		// application level.
		ResetPasswordToken:  "",
		ResetPasswordSentAt: nil,
		AllowPasswordChange: false,
	}
	success, err := s.users.UpdateRecoverable(user, recoverable)
	if err != nil {
		return nil, err
	}

	// Clear older sessions when changing password.
	return &ResetPasswordResponse{
		Success: success,
	}, nil
}

func (s *serviceImpl) SendConfirmation(ctx context.Context, req SendConfirmationRequest) (*SendConfirmationResponse, error) {
	var (
		email = strings.TrimSpace(req.Email)
	)
	if err := validateEmail(email); err != nil {
		return nil, err
	}

	user, err := s.users.WithEmail(email)
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

	confirmable := Confirmable{
		ConfirmationToken:  uuid.Must(uuid.NewV4()),
		ConfirmationSentAt: time.Now(),
		UnconfirmedEmail:   email,
	}
	// This will set email verified to false.
	ok, err := s.users.UpdateConfirmable(user, confirmable)
	if err != nil {
		return nil, err
	}
	// Return the confirmable in order to send the email.
	return &SendConfirmationResponse{
		Token: confirmable.ConfirmationToken,
	}, nil

}

func (s *serviceImpl) Confirm(ctx context.Context, req ConfirmRequest) (*ConfirmResponse, error) {
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return nil, ErrTokenRequired
	}
	user, err := s.users.WithConfirmationToken(token)
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

	confirmable := Confirmable{
		ConfirmationToken:  "",
		ConfirmationSentAt: nil,
		UnconfirmedEmail:   "",
	}

	success, err := s.users.UpdateConfirmable(user, confirmable)
	if err != nil {
		return nil, err
	}
	return &ConfirmationResponse{
		Success: true,
	}, nil
}

func (s *serviceImpl) ChangeEmail(ctx context.Context, req ChangeEmailRequest) (*ChangeEmailResponse, error) {
	email = strings.TrimSpace(req.Email)
	if err := validateEmail(email); err != nil {
		return nil, err
	}
	exists, err := s.users.HasEmail(email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrEmailExists
	}
	confirmable := Confirmable{
		ConfirmationToken:  uuid.Must(uuid.NewV4()),
		ConfirmationSentAt: time.Now(),
		UnconfirmedEmail:   email,
	}
	ok, err := s.users.UpdateConfirmable(user, confirmable)
	if err != nil {
		return nil, err
	}
	// Return the confirmable in order to send the email.
	return &SendConfirmationResponse{
		Token: confirmable.ConfirmationToken,
	}, nil
}
