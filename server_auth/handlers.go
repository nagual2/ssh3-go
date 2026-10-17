package server_auth

import (
	"net/http"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/util"
	"github.com/francoismichel/ssh3/util/unix_util"

	"github.com/rs/zerolog/log"
)

// BearerAuth returns the bearer token
// Authorization header, if the request uses HTTP Basic Authentication.
// See RFC 2617, Section 2.
func BearerAuth(r *http.Request) (bearer string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	return ParseBearerAuth(auth)
}

// ParseBearerAuth parses an HTTP Bearer Authentication string.
func ParseBearerAuth(auth string) (bearer string, ok bool) {
	const prefix = "Bearer "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !util.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}
	// TODO: maybe validate the encoding format of the JWT token (at least verify that
	// it is base64-encoded)
	return string(auth[len(prefix):]), true
}

func HandleBearerAuth(username string, base64ConversationID string, handlerFunc ssh3.UnauthenticatedBearerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerString, ok := BearerAuth(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handlerFunc(bearerString, base64ConversationID, w, r)
	}
}

// currently only supports RS256 and EdDSA signing algorithms
func HandleJWTAuth(username string, newConv *ssh3.Conversation, identities []IdentityVerifier, handlerFunc ssh3.AuthenticatedHandlerFunc) ssh3.UnauthenticatedBearerFunc {
	return func(unauthenticatedBearerString string, base64ConversationID string, w http.ResponseWriter, r *http.Request) {
		for _, identity := range identities {
			verified := identity.Verify(util.JWTTokenString{Token: unauthenticatedBearerString}, base64ConversationID)
			if verified {
				// authentication successful
				handlerFunc(username, newConv, w, r)
				return
			}
		}

		// TODO: logging
		w.WriteHeader(http.StatusUnauthorized)
	}
}

// VerifyJWT tries the identity verifiers against the request's Bearer
// token; it writes the 401 response itself when nothing verified.
func VerifyJWT(identities []IdentityVerifier, base64ConversationID string, w http.ResponseWriter, r *http.Request) bool {
	bearer, ok := BearerAuth(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	for _, identity := range identities {
		if identity.Verify(util.JWTTokenString{Token: bearer}, base64ConversationID) {
			return true
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
	return false
}

// CheckBasicAuth verifies the request's Basic password against the account:
// a locked-out account is refused with 429 without touching the password
// backend, a failed attempt books into the brute-force lockout. The root
// account is refused unconditionally (the sshd PermitRootLogin
// prohibit-password analog): root authenticates by key only.
func CheckBasicAuth(username string, w http.ResponseWriter, r *http.Request) bool {
	_, password, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	if PasswordLoginRefused(username) {
		log.Warn().Msgf("password auth for %s refused: the root account authenticates by key only (PermitRootLogin prohibit-password)", username)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	if PasswordAuthLocked(username) {
		log.Warn().Msgf("password auth for %s refused: the account is locked out", username)
		w.WriteHeader(http.StatusTooManyRequests)
		return false
	}

	verified, err := unix_util.UserPasswordAuthentication(username, password)
	if err != nil || !verified {
		if err != nil {
			log.Error().Msgf("user authentication failed: %s", err)
		}
		PasswordAuthFailure(username)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	PasswordAuthSuccess(username)
	return true
}
