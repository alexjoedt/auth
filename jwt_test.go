package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewAccessToken(t *testing.T) {
	initAuth()
	s, err := Auth.NewAccessToken(testUsername)
	if err != nil {
		t.Errorf("NewAccessToken failed: %s", err.Error())
	}
	assert.NotNil(t, s, "should not be nil")
	assert.NotEmpty(t, s.AccessToken, "should be not empty")
	assert.NotEmpty(t, s.ID, "should be not empty")
	assert.NotEmpty(t, s.ExpirationDate, "should be not empty")
	assert.Equal(t, testUsername, s.ID, "should be equal")

	_, err = Auth.ValidateAccessToken(s.AccessToken)
	if err != nil {
		t.Errorf("NewAccessToken failed: %s", err.Error())
	}
}

func TestValidateAccessToken(t *testing.T) {
	initAuth()
	s, err := Auth.NewAccessToken(testUsername)
	if err != nil {
		t.Errorf("Failed to create accesstoken: %s", err.Error())
	}

	_, err = Auth.ValidateAccessToken(s.AccessToken)
	if err != nil {
		t.Errorf("Failed to validate accesstoken: %s", err.Error())
	}

	time.Sleep(time.Second * 1)

	_, err = Auth.ValidateAccessToken(s.AccessToken)
	assert.NotNil(t, err, "error shoul be != nil")
}

func TestGenerateJWT(t *testing.T) {
	initAuth()
	s, err := Auth.generateJWT(testUsername)
	if err != nil {
		t.Errorf("generateJWT failed: %s", err.Error())
	}
	assert.NotNil(t, s, "should not be nil")
	assert.NotEmpty(t, s.AccessToken, "should be not empty")
	assert.NotEmpty(t, s.ID, "should be not empty")
	assert.NotEmpty(t, s.ExpirationDate, "should be not empty")
	assert.Equal(t, testUsername, s.ID, "should be equal")

	_, err = Auth.ValidateAccessToken(s.AccessToken)
	if err != nil {
		t.Errorf("NewAccessToken failed: %s", err.Error())
	}
}
