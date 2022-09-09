package auth

import (
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
		basicAuthenticator:  a.BasicAuthenticator,
		bearerAuthenticator: a.BearerAuthenticator,
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
		username, pass, ok := r.BasicAuth()
		if ok {
			return a.authenticateBasic(username, pass)
		}
		return fmt.Errorf("invalid basic auth header")
	case AuthTypeBearer:
		return a.authenticateBearer(headerParts[1])
	default:
		return fmt.Errorf("auth type: %s is not supported", authType)
	}
}

func (a *auth) authenticateBasic(username string, password string) error {
	if a.basicAuthenticator != nil {
		return a.basicAuthenticator.CheckBasic(username, password)
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
