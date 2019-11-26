package passport_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/alextanhongpin/passport"
	"github.com/alextanhongpin/passport/examples/database"

	"github.com/stretchr/testify/suite"
)

func TestMain(m *testing.M) {
	database.TestMain(m)
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
		password = "xyz"
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
		password = "xyz"
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
}

func (suite *TestAuthenticateSuite) SetupSuite() {
	suite.db = database.DB()
	suite.repository = passport.NewPostgres(suite.db)
	suite.confirm = passport.NewConfirm(suite.repository)
	suite.login = passport.NewLogin(suite.repository)
	suite.register = passport.NewRegister(suite.repository)
	suite.sendConfirmation = passport.NewSendConfirmation(suite.repository)
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
	res, err := suite.login(context.TODO(), passport.LoginRequest{
		Email:    "jane.doe@mail.com",
		Password: "124356",
	})
	suite.Nil(res)
	suite.Equal(passport.ErrEmailNotFound, err)
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
	res, err := suite.login(context.TODO(), passport.LoginRequest{
		Email:    "john.doe@mail.com",
		Password: "123456",
	})
	suite.Nil(res)
	suite.NotNil(err)
	suite.Equal(passport.ErrConfirmationRequired, err)
}

func (suite *TestAuthenticateSuite) TestLoginRegisteredUserConfirmed() {
	sendConfirmationRes, err := suite.sendConfirmation(context.TODO(), passport.SendConfirmationRequest{
		Email: "john.doe@mail.com",
	})
	suite.Nil(err)
	suite.True(sendConfirmationRes.Success)
	suite.True(len(sendConfirmationRes.Token) > 0)

	confirmRes, err := suite.confirm(context.TODO(), passport.ConfirmRequest{
		Token: sendConfirmationRes.Token,
	})
	suite.Nil(err)
	suite.True(confirmRes.Success)
	// user, err := suite.repository.Find(context.TODO(), suite.id)
	// suite.Nil(err)

	loginRes, err := suite.login(context.TODO(), passport.LoginRequest{
		Email:    "john.doe@mail.com",
		Password: "123456",
	})
	suite.Nil(err)
	suite.NotNil(loginRes)
	suite.Equal("john.doe@mail.com", loginRes.User.Email)
}

func (suite *TestAuthenticateSuite) TestLoginWrongPassword() {
	res, err := suite.login(context.TODO(), passport.LoginRequest{
		Email:    "john.doe@mail.com",
		Password: "654321",
	})
	suite.Nil(res)
	suite.NotNil(err)
	suite.Equal(passport.ErrEmailOrPasswordInvalid, err)
}

func TestAuthenticateTestSuite(t *testing.T) {
	suite.Run(t, new(TestAuthenticateSuite))
}

// NEW

// type TestPasswordSuite struct {
//         suite.Suite
//         changePassword passport.ChangePassword
//         sendResetPassword passport.SendResetPassword
//         resetPassword passport.ResetPassport
// }
//
// func (suite *TestPasswordSuite) TestChangePassword() {
//
// }
