package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var Auth *auth

type auth struct {
	basicAuthenticator  BasicAuthenticator
	bearerAuthenticator BearerAuthenticator
	secret              string
	domain              string
	tokenExpirationTime time.Duration
}

type AuthType string

const (
	AuthTypeBasic  AuthType = "Basic"
	AuthTypeBearer AuthType = "Bearer"
)

type AuthOpts struct {
	BasicAuthenticator      BasicAuthenticator
	BearerAuthenticator     BearerAuthenticator
	Secret                  string
	Domain                  string
	TokenExpirationDuration time.Duration
}

type BasicAuthenticator interface {
	CheckBasic(username string, password string) error
}

type BearerAuthenticator interface {
	CheckBearer(token string) error
}

func Init(a AuthOpts) *auth {
	Auth = &auth{
		tokenExpirationTime: a.TokenExpirationDuration,
		secret:              a.Secret,
		domain:              a.Domain,
	}
	return Auth
}

func (a *auth) AuthenticateRequest(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return errors.New("no auth header")
	}
	headerParts := strings.Split(authHeader, " ")
	if len(headerParts) != 2 {
		return errors.New("invalid_auth_header")
	}

	authType := AuthType(headerParts[0])
	switch authType {
	case AuthTypeBasic:
		return a.authenticateBasic(headerParts[1])
	case AuthTypeBearer:
		return a.authenticateBearer(headerParts[1])
	default:
		return fmt.Errorf("auth type: %s is not supported", authType)
	}
}

func (a *auth) authenticateBasic(base64String string) error {
	data, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return err
	}

	if !strings.Contains(string(data), ":") {
		return ErrInvalidAuthHeader
	}

	creds := strings.Split(string(data), ":")

	if len(creds) < 2 {
		return ErrInvalidCredentials
	}

	if a.basicAuthenticator != nil {
		return a.basicAuthenticator.CheckBasic(creds[0], creds[1])
	}

	return ErrAuthenticatorNotInitialized
}

func (a *auth) authenticateBearer(token string) error {

	if token == "" {
		return ErrMissingToken
	}

	if a.bearerAuthenticator != nil {
		return a.bearerAuthenticator.CheckBearer(token)
	}

	// As default we use built in JWT
	if len(token) > 100 && strings.Contains(token, ".") {
		_, err := a.ValidateAccessToken(token)
		if err != nil {
			return err
		}
		return nil
	}

	return ErrNotSupported
}
