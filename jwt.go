package auth

import (
	"fmt"
	"time"

	"github.com/pascaldekloe/jwt"
)

type Session struct {
	AccessToken    string
	ID             string
	ExpirationDate time.Time
}

func (a *auth) NewAccessToken(id string) (*Session, error) {
	session, err := a.generateJWT(id)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (a *auth) generateJWT(subject string) (*Session, error) {
	var claims jwt.Claims
	claims.Subject = fmt.Sprint(subject)
	claims.Issued = jwt.NewNumericTime(time.Now())
	claims.NotBefore = jwt.NewNumericTime(time.Now())
	claims.Expires = jwt.NewNumericTime(time.Now().Add(a.tokenExpirationTime))
	claims.Issuer = a.domain // domain name
	claims.Audiences = []string{a.domain}

	jwtBytes, err := claims.HMACSign(jwt.HS256, []byte(a.secret))
	if err != nil {
		return nil, err
	}

	return &Session{
		ID:             claims.Subject,
		AccessToken:    string(jwtBytes),
		ExpirationDate: claims.Expires.Time().Local(),
	}, nil
}

func (a *auth) ValidateAccessToken(accesstoken string) (*Session, error) {
	claims, err := jwt.HMACCheck([]byte(accesstoken), []byte(a.secret))
	if err != nil {
		return nil, ErrInvalidToken
	}

	if !claims.Valid(time.Now()) {
		return nil, ErrTokenExpired
	}

	if !claims.AcceptAudience(a.domain) {
		return nil, ErrWrongAudience
	}

	if claims.Issuer != a.domain {
		return nil, ErrWrongIssuer
	}

	return &Session{
		AccessToken:    accesstoken,
		ID:             claims.Subject,
		ExpirationDate: claims.Expires.Time(),
	}, nil
}
