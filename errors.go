package auth

import "errors"

var (
	ErrInvalidToken  = errors.New("token_invalid")
	ErrTokenExpired  = errors.New("token_expired")
	ErrWrongAudience = errors.New("wrong_audience")
	ErrWrongIssuer   = errors.New("wrong_issuer")

	ErrInvalidAuthHeader           = errors.New("invalid auth header")
	ErrInvalidCredentials          = errors.New("invalid credentials")
	ErrAuthenticatorNotInitialized = errors.New("authenticator is not initialized")
	ErrMissingToken                = errors.New("token is missing")
	ErrNotSupported                = errors.New("invalid token or not supported")
)
