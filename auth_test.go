package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Mocks
var (
	testUsername     string = "testy"
	testPassword     string = "my_secret_password"
	base64TestString string = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", testUsername, testPassword)))
	bearerToken      string = "123"
)

var testUsers map[string]string = map[string]string{
	"testy": "my_secret_password",
}

var testTokens map[string]string = map[string]string{
	"123": "valid",
	"456": "expired",
}

var mockRequestBasic = http.Request{
	Header: http.Header{
		"Authorization": []string{"Basic " + base64TestString},
	},
}

var mockRequestBearer = http.Request{
	Header: http.Header{
		"Authorization": []string{"Bearer " + bearerToken},
	},
}

type testAuthenticator struct {
}

func (ta *testAuthenticator) CheckBasic(username, password string) error {
	if userPass, ok := testUsers[username]; ok {
		if password != userPass {
			return fmt.Errorf("invalid credentials")
		}
		return nil
	}

	return fmt.Errorf("user not found")
}

func (ta *testAuthenticator) CheckBearer(token string) error {
	if tokenStatus, ok := testTokens[token]; ok {
		if tokenStatus == "valid" {
			return nil
		} else {
			return fmt.Errorf("token is expired or invalid")
		}
	}

	return fmt.Errorf("invalid token")
}

func initAuth() *auth {
	ta := testAuthenticator{}
	return Init(AuthOpts{
		Authenticator:           &ta,
		Secret:                  "1c2b79719568a9ba9d3392156bcabcca",
		Domain:                  "test.local",
		TokenExpirationDuration: time.Second * 1,
	})
}

func TestInitGuard(t *testing.T) {

	a := initAuth()
	assert.NotNil(t, a, "should not be nil")
	assert.NotNil(t, Auth, "should not be nil")
}

func TestAuthenticateRequest(t *testing.T) {
	initAuth()

	// Basic Auth
	err := Auth.AuthenticateRequest(&mockRequestBasic)
	assert.Nil(t, err, "shoud be nil")

	// Bearer Auth
	err = Auth.AuthenticateRequest(&mockRequestBearer)
	assert.Nil(t, err, "shoud be nil")

	s, err := Auth.NewAccessToken(testUsername)
	assert.Nil(t, err, "shoud be nil")
	assert.NotNil(t, s, "should be not nil")
	assert.NotEmpty(t, s.AccessToken, "should be not empty")
	assert.NotEmpty(t, s.ID, "should be not empty")
	assert.Equal(t, testUsername, s.ID, "should be equal")
	assert.NotEmpty(t, s.ExpirationDate, "should be not empty")

	// Test default behavoir with built in JWT
	Auth.authenticator = nil
	mockRequestBearer.Header.Set("Authorization", "Bearer "+s.AccessToken)
	err = Auth.AuthenticateRequest(&mockRequestBearer)
	assert.Nil(t, err, "shoud be nil")
}
