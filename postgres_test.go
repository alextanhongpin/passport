package passport_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/alextanhongpin/passport"
	"github.com/alextanhongpin/passport/examples/database"

	"github.com/stretchr/testify/suite"
)

func TestMain(m *testing.M) {
	if os.Getenv("ENV") == "ci" {
		database.TestCI(m)
	} else {
		database.TestMain(m)
	}
}

type TestPostgresSuite struct {
	suite.Suite
	db         *sql.DB
	repository *passport.Postgres
	user       *passport.User
}

func (suite *TestPostgresSuite) SetupSuite() {
	suite.db = database.DB()
	suite.repository = passport.NewPostgres(suite.db)
}

func (suite *TestPostgresSuite) SetupTest() {
	// Create a mock user.
	var (
		email    = "john.doe@mail.com"
		password = "123456"
		err      error
	)
	suite.user, err = suite.repository.Create(context.TODO(), email, password)
	suite.Nil(err)
	suite.True(len(suite.user.ID) > 0)

	suite.user.Email = email
}

func (suite *TestPostgresSuite) TearDownTest() {
	_, err := suite.db.Exec("TRUNCATE TABLE login")
	suite.Nil(err)
}

func (suite *TestPostgresSuite) TestCreate() {
	var (
		email    = "jane@mail.com"
		password = "123456"
	)
	user, err := suite.repository.Create(context.TODO(), email, password)
	suite.Nil(err)
	suite.NotNil(user)
	suite.True(len(user.ID) > 0)
}

func (suite *TestPostgresSuite) TestWithEmailNoRows() {
	user, err := suite.repository.WithEmail(context.TODO(), "jane@mail.com")
	suite.Nil(user)
	suite.Equal(sql.ErrNoRows, err)
}

func (suite *TestPostgresSuite) TestWithEmailSuccess() {
	user, err := suite.repository.WithEmail(context.TODO(), suite.user.Email)
	suite.Nil(err)
	suite.Equal(suite.user.Email, user.Email)
}

func (suite *TestPostgresSuite) TestUpdateRecoverableNoRows() {
	updated, err := suite.repository.UpdateRecoverable(context.TODO(), "jane@mail.com", passport.Recoverable{})
	suite.False(updated)
	suite.Nil(err)
}

func (suite *TestPostgresSuite) TestUpdateRecoverableSuccess() {
	updated, err := suite.repository.UpdateRecoverable(context.TODO(), suite.user.Email, passport.Recoverable{
		ResetPasswordToken:  "token_1",
		AllowPasswordChange: true,
	})
	suite.True(updated)
	suite.Nil(err)
}

func (suite *TestPostgresSuite) TestWithResetPasswordTokenNoRows() {
	user, err := suite.repository.WithResetPasswordToken(context.TODO(), "abc")
	suite.Nil(user)
	suite.Equal(sql.ErrNoRows, err)
}

func (suite *TestPostgresSuite) TestUpdatePasswordSuccess() {
	updated, err := suite.repository.UpdatePassword(context.TODO(), suite.user.ID, "abc")
	suite.Nil(err)
	suite.True(updated)
}

func (suite *TestPostgresSuite) TestUpdateConfirmableSuccess() {
	updated, err := suite.repository.UpdateConfirmable(
		context.TODO(),
		suite.user.Email,
		passport.Confirmable{},
	)
	suite.Nil(err)
	suite.True(updated)
}

func (suite *TestPostgresSuite) TestWithConfirmationTokenNoRows() {
	user, err := suite.repository.WithConfirmationToken(context.TODO(), "abc")
	suite.Nil(user)
	suite.Equal(sql.ErrNoRows, err)
}

func (suite *TestPostgresSuite) TestHasEmailSuccess() {
	exists, err := suite.repository.HasEmail(context.TODO(), suite.user.Email)
	suite.Nil(err)
	suite.True(exists)
}

func (suite *TestPostgresSuite) TestFind() {
	user, err := suite.repository.Find(context.TODO(), suite.user.ID)
	suite.Nil(err)
	suite.NotNil(user)
	suite.Equal(suite.user.ID, user.ID)
}

func TestPostgresTestSuite(t *testing.T) {
	suite.Run(t, new(TestPostgresSuite))
}

// NEW

type TestAuthenticateSuite struct {
	suite.Suite
	db               *sql.DB
	repository       *passport.Postgres
	id               string
	confirm          passport.Confirm
	login            passport.Login
	register         passport.Register
	sendConfirmation passport.SendConfirmation

	// Password.
	changePassword       passport.ChangePassword
	requestResetPassword passport.RequestResetPassword
	resetPassword        passport.ResetPassword
	changeEmail          passport.ChangeEmail
}

func (suite *TestAuthenticateSuite) SetupSuite() {
	suite.db = database.DB()
	suite.repository = passport.NewPostgres(suite.db)
	suite.confirm = passport.NewConfirm(suite.repository)
	suite.login = passport.NewLogin(suite.repository)
	suite.register = passport.NewRegister(suite.repository)
	suite.sendConfirmation = passport.NewSendConfirmation(suite.repository)
	suite.changePassword = passport.NewChangePassword(suite.repository)
	suite.requestResetPassword = passport.NewRequestResetPassword(suite.repository)
	suite.resetPassword = passport.NewResetPassword(suite.repository)
	suite.changeEmail = passport.NewChangeEmail(suite.repository)
}

func (suite *TestAuthenticateSuite) SetupTest() {
	// Clear db before each tests.
	_, err := suite.db.Exec(`TRUNCATE TABLE login`)
	suite.Nil(err)

	req := passport.RegisterRequest{
		Email:    "john.doe@mail.com",
		Password: "123456",
	}
	res, err := suite.register(context.TODO(), req)
	suite.Nil(err)
	suite.NotNil(res)
	suite.True(len(res.User.ID) > 0)
	suite.id = res.User.ID
}

func (suite *TestAuthenticateSuite) TestLoginNewUser() {
	var (
		email    = "jane.doe@mail.com"
		password = "124356"
	)
	cred := passport.NewCredential(email, password)

	res, err := suite.login(context.TODO(), cred)
	suite.Nil(res)
	suite.Equal(passport.ErrUserNotFound, err)
}

func (suite *TestAuthenticateSuite) TestRegisterNewUser() {
	res, err := suite.register(context.TODO(), passport.RegisterRequest{
		Email:    "jane.doe@mail.com",
		Password: "124356",
	})
	suite.Nil(err)
	suite.NotNil(res)
	suite.True(len(res.User.ID) > 0)
}

func (suite *TestAuthenticateSuite) TestRegisterExistingUser() {
	req := passport.RegisterRequest{
		Email:    "john.doe@mail.com",
		Password: "124356",
	}
	res, err := suite.register(context.TODO(), req)
	suite.Nil(res)
	suite.NotNil(err)
}

func (suite *TestAuthenticateSuite) TestLoginRegisteredUserUnconfirmed() {
	var (
		email    = "john.doe@mail.com"
		password = "123456"
	)
	cred := passport.NewCredential(email, password)
	res, err := suite.login(context.TODO(), cred)
	suite.Nil(res)
	suite.NotNil(err)
	suite.Equal(passport.ErrConfirmationRequired, err)
}

func (suite *TestAuthenticateSuite) TestLoginRegisteredUserConfirmed() {
	var (
		email    = "john.doe@mail.com"
		password = "123456"
	)
	confirmFn(suite, email)
	loginFn(suite, email, password)
}

func (suite *TestAuthenticateSuite) TestLoginWrongPassword() {
	res, err := suite.login(context.TODO(), passport.Credential{
		Email:    "john.doe@mail.com",
		Password: "654321",
	})
	suite.Nil(res)
	suite.NotNil(err)
	suite.Equal(passport.ErrEmailOrPasswordInvalid, err)
}

func (suite *TestAuthenticateSuite) TestChangePassword() {
	var (
		email    = "john.doe@mail.com"
		password = "newpass"
	)
	confirmFn(suite, email)
	res, err := suite.changePassword(context.TODO(), passport.ChangePasswordRequest{
		UserID:          suite.id,
		Password:        password,
		ConfirmPassword: password,
	})
	suite.Nil(err)
	suite.True(res.Success)

	loginFn(suite, email, password)
}

func (suite *TestAuthenticateSuite) TestResetPassword() {
	var (
		email    = "john.doe@mail.com"
		password = "newpass"
	)
	confirmFn(suite, email)
	requestResetPasswordRes, err := suite.requestResetPassword(context.TODO(), passport.RequestResetPasswordRequest{
		Email: email,
	})
	suite.Nil(err)
	suite.True(requestResetPasswordRes.Success)
	suite.True(len(requestResetPasswordRes.Token) > 0)

	resetPasswordRes, err := suite.resetPassword(context.TODO(), passport.ResetPasswordRequest{
		Token:           requestResetPasswordRes.Token,
		Password:        password,
		ConfirmPassword: password,
	})
	suite.Nil(err)
	suite.True(resetPasswordRes.Success)

	loginFn(suite, email, password)
}

func (suite *TestAuthenticateSuite) TestChangeEmail() {
	var (
		newEmail = "jane.doe@mail.com"
		password = "123456"
	)
	changeEmailRes, err := suite.changeEmail(context.TODO(), passport.ChangeEmailRequest{
		UserID: suite.id,
		Email:  newEmail,
	})
	suite.Nil(err)
	suite.True(changeEmailRes.Success)
	suite.True(len(changeEmailRes.Token) > 0)

	confirmRes, err := suite.confirm(context.TODO(), passport.ConfirmRequest{
		Token: changeEmailRes.Token,
	})
	suite.Nil(err)
	suite.True(confirmRes.Success)

	loginFn(suite, newEmail, password)
}

func confirmFn(suite *TestAuthenticateSuite, email string) {
	sendConfirmationRes, err := suite.sendConfirmation(context.TODO(), passport.SendConfirmationRequest{
		Email: email,
	})
	suite.Nil(err)
	suite.True(sendConfirmationRes.Success)
	suite.True(len(sendConfirmationRes.Token) > 0)

	confirmRes, err := suite.confirm(context.TODO(), passport.ConfirmRequest{
		Token: sendConfirmationRes.Token,
	})
	suite.Nil(err)
	suite.True(confirmRes.Success)
}

func loginFn(suite *TestAuthenticateSuite, email, password string) {
	cred := passport.NewCredential(email, password)

	user, err := suite.login(context.TODO(), cred)
	suite.Nil(err)
	suite.Equal(suite.id, user.ID)
}

func TestAuthenticateTestSuite(t *testing.T) {
	suite.Run(t, new(TestAuthenticateSuite))
}
