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
		password = "12345678"
	)
	var err error
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
		password = "12345678"
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
	confirm          *passport.Confirm
	login            *passport.Login
	register         *passport.Register
	sendConfirmation *passport.SendConfirmation
	cred             passport.Credential

	// Password.
	changePassword       *passport.ChangePassword
	requestResetPassword *passport.RequestResetPassword
	resetPassword        *passport.ResetPassword
	changeEmail          *passport.ChangeEmail
}

func (suite *TestAuthenticateSuite) SetupSuite() {
	suite.db = database.DB()

	a2 := passport.NewArgon2Password()
	tg := passport.NewTokenGenerator()

	suite.repository = passport.NewPostgres(suite.db)
	suite.confirm = passport.NewConfirm(passport.ConfirmOptions{
		Repository:                suite.repository,
		ConfirmationTokenValidity: passport.ConfirmationTokenValidity,
	})
	suite.login = passport.NewLogin(
		passport.LoginOptions{
			Repository: suite.repository,
			Comparer:   a2,
		},
	)
	suite.register = passport.NewRegister(
		passport.RegisterOptions{Repository: suite.repository, Encoder: a2},
	)
	suite.sendConfirmation = passport.NewSendConfirmation(
		passport.SendConfirmationOptions{
			Repository:     suite.repository,
			TokenGenerator: tg,
		},
	)
	suite.changePassword = passport.NewChangePassword(
		passport.ChangePasswordOptions{
			Repository:      suite.repository,
			EncoderComparer: a2,
		},
	)
	suite.requestResetPassword = passport.NewRequestResetPassword(
		passport.RequestResetPasswordOptions{
			Repository:     suite.repository,
			TokenGenerator: tg,
		},
	)
	suite.resetPassword = passport.NewResetPassword(
		passport.ResetPasswordOptions{
			Repository:               suite.repository,
			EncoderComparer:          a2,
			RecoverableTokenValidity: passport.RecoverableTokenValidity,
		},
	)
	suite.changeEmail = passport.NewChangeEmail(
		passport.ChangeEmailOptions{
			Repository:     suite.repository,
			TokenGenerator: tg,
		},
	)
}

func (suite *TestAuthenticateSuite) SetupTest() {
	// Clear db before each tests.
	_, err := suite.db.Exec(`TRUNCATE TABLE login`)
	suite.Nil(err)

	var (
		email    = "john.doe@mail.com"
		password = "12345678"
	)
	suite.cred = passport.NewCredential(email, password)
	user, err := suite.register.Exec(context.TODO(), suite.cred)
	suite.Nil(err)
	suite.NotNil(user)
	suite.True(user.ID != "")
	suite.id = user.ID
}

func (suite *TestAuthenticateSuite) TestLoginNewUser() {
	res, err := suite.login.Exec(context.TODO(), suite.cred)
	suite.Nil(res)
	suite.Equal(passport.ErrConfirmationRequired, err)
}

func (suite *TestAuthenticateSuite) TestRegisterNewUser() {
	var (
		email    = "jane.doe@mail.com"
		password = "12435678"
	)
	cred := passport.NewCredential(email, password)
	user, err := suite.register.Exec(context.TODO(), cred)
	suite.Nil(err)
	suite.NotNil(user)
	suite.True(user.ID != "")
}

func (suite *TestAuthenticateSuite) TestRegisterExistingUser() {
	user, err := suite.register.Exec(context.TODO(), suite.cred)
	suite.Nil(user)
	suite.NotNil(err)
}

func (suite *TestAuthenticateSuite) TestLoginRegisteredUserUnconfirmed() {
	user, err := suite.login.Exec(context.TODO(), suite.cred)
	suite.Nil(user)
	suite.NotNil(err)
	suite.Equal(passport.ErrConfirmationRequired, err)
}

func (suite *TestAuthenticateSuite) TestLoginRegisteredUserConfirmed() {
	var (
		email    = suite.cred.Email
		password = suite.cred.Password
	)
	confirmFn(suite, email)
	loginFn(suite, email, password)
}

func (suite *TestAuthenticateSuite) TestLoginWrongPassword() {
	cred := suite.cred
	cred.Password = passport.NewPassword("87654321")
	user, err := suite.login.Exec(context.TODO(), cred)
	suite.Nil(user)
	suite.NotNil(err)
	suite.Equal(passport.ErrEmailOrPasswordInvalid, err)
}

func (suite *TestAuthenticateSuite) TestChangePassword() {
	var (
		email    = passport.NewEmail("john.doe@mail.com")
		password = passport.NewPassword("newpass12")
	)
	confirmFn(suite, email)
	err := suite.changePassword.Exec(
		context.TODO(),
		passport.NewUserID(suite.id),
		password,
		password,
	)
	suite.Nil(err)

	loginFn(suite, email, password)
}

func (suite *TestAuthenticateSuite) TestResetPassword() {
	var (
		email    = passport.NewEmail("john.doe@mail.com")
		password = passport.NewPassword("87654321")
	)
	confirmFn(suite, email)
	token, err := suite.requestResetPassword.Exec(
		context.TODO(),
		email,
	)
	suite.Nil(err)
	suite.True(token != "")

	user, err := suite.resetPassword.Exec(
		context.TODO(),
		passport.NewToken(token),
		password,
		password,
	)
	suite.Nil(err)
	suite.NotNil(user)

	loginFn(suite, email, password)
}

func (suite *TestAuthenticateSuite) TestChangeEmail() {
	var (
		newEmail = passport.NewEmail("jane.doe@mail.com")
		password = passport.NewPassword("12345678")
	)
	token, err := suite.changeEmail.Exec(
		context.TODO(),
		passport.NewUserID(suite.id),
		newEmail,
	)
	suite.Nil(err)
	suite.True(token != "")

	err = suite.confirm.Exec(
		context.TODO(),
		passport.NewToken(token),
	)
	suite.Nil(err)
	loginFn(suite, newEmail, password)
}

func confirmFn(suite *TestAuthenticateSuite, email passport.Email) {
	token, err := suite.sendConfirmation.Exec(
		context.TODO(),
		email,
	)
	suite.Nil(err)
	suite.True(token != "")

	err = suite.confirm.Exec(
		context.TODO(),
		passport.NewToken(token),
	)
	suite.Nil(err)
}

func loginFn(suite *TestAuthenticateSuite, email passport.Email, password passport.Password) {
	cred := passport.NewCredential(email.Value(), password.Value())
	user, err := suite.login.Exec(context.TODO(), cred)
	suite.Nil(err)
	suite.Equal(suite.id, user.ID)
}

func TestAuthenticateTestSuite(t *testing.T) {
	suite.Run(t, new(TestAuthenticateSuite))
}
