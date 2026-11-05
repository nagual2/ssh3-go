package ssh3

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/francoismichel/ssh3/auth/oidc"
	client_config "github.com/francoismichel/ssh3/client/config"
	matchcfg "github.com/francoismichel/ssh3/client/config/matchcfg"
	"github.com/francoismichel/ssh3/util"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// PasswordAuthMethod is the classical password authentication. The empty
// struct is the interactive form: the client prompts on the terminal. The
// credentials form (--password user:pass) carries the user and the password
// and rides without any prompt.
type PasswordAuthMethod struct {
	username string
	password string
}
type OidcAuthMethod struct {
	doPKCE bool
	config *oidc.OIDCConfig
}

func (m *OidcAuthMethod) OIDCConfig() *oidc.OIDCConfig {
	return m.config
}

func (m *OidcAuthMethod) DoPKCE() bool {
	return m.doPKCE
}

type PrivkeyFileAuthMethod struct {
	filename string
}
type AgentAuthMethod struct {
	pubkey ssh.PublicKey
}

func NewPasswordAuthMethod() *PasswordAuthMethod {
	return &PasswordAuthMethod{}
}

// NewPasswordAuthMethodWithCredentials builds the non-interactive form of the
// password method: the identity is built from the credentials given up front
// (--password user:pass), so no terminal prompt happens. The password rides
// case-sensitively; the username joins the Basic auth of passwordIdentity.
func NewPasswordAuthMethodWithCredentials(username, password string) *PasswordAuthMethod {
	return &PasswordAuthMethod{
		username: username,
		password: password,
	}
}

// HasCredentials reports whether the method carries the credentials given up
// front: such a method authenticates without the interactive prompt.
func (m *PasswordAuthMethod) HasCredentials() bool {
	return m.password != ""
}

// Username returns the user of the credentials form (empty for the
// interactive one; the connection user serves then).
func (m *PasswordAuthMethod) Username() string {
	return m.username
}

// Password returns the password of the credentials form (empty for the
// interactive one, whose password comes from the prompt).
func (m *PasswordAuthMethod) Password() string {
	return m.password
}

func (m *PasswordAuthMethod) IntoIdentity(password string) Identity {
	return passwordIdentity(password)
}

func NewOidcAuthMethod(doPKCE bool, config *oidc.OIDCConfig) *OidcAuthMethod {
	return &OidcAuthMethod{
		doPKCE: doPKCE,
		config: config,
	}
}

func (m *OidcAuthMethod) IntoIdentity(bearerToken string) Identity {
	return rawBearerTokenIdentity(bearerToken)
}

func NewPrivkeyFileAuthMethod(filename string) *PrivkeyFileAuthMethod {
	return &PrivkeyFileAuthMethod{
		filename: util.ExpandTildeWithHomeDir(filename),
	}
}

func (m *PrivkeyFileAuthMethod) Filename() string {
	return m.filename
}

// IntoIdentityWithoutPassphrase returns an SSH3 identity stored on the provided path.
// It supports the same keys as ssh.ParsePrivateKey
// If the private key is encrypted, it returns an ssh.PassphraseMissingError.
func (m *PrivkeyFileAuthMethod) IntoIdentityWithoutPassphrase() (Identity, error) {
	return m.intoIdentity(nil)
}

// IntoIdentityPassphrase returns a passphrase-protected private key stored on the provided path.
// It supports the same keys as ssh.ParsePrivateKey
// If the passphrase is wrong, it returns an x509.IncorrectPasswordError.
func (m *PrivkeyFileAuthMethod) IntoIdentityPassphrase(passphrase string) (Identity, error) {
	return m.intoIdentity(&passphrase)
}

func (m *PrivkeyFileAuthMethod) intoIdentity(passphrase *string) (Identity, error) {

	pemBytes, err := os.ReadFile(m.filename)
	if err != nil {
		return nil, err
	}
	var cryptoSigner crypto.Signer
	var signer interface{}
	var ok bool
	if passphrase == nil {
		signer, err = ssh.ParseRawPrivateKey(pemBytes)
	} else {
		signer, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, []byte(*passphrase))
	}
	if err != nil {
		return nil, err
	}
	// transform the abstract type into a crypto.Signer that can be used with the jwt lib
	if cryptoSigner, ok = signer.(crypto.Signer); !ok {
		return nil, fmt.Errorf("the provided key file does not result in a crypto.Signer type")
	}
	signingMethod, err := util.JWTSigningMethodFromCryptoPubkey(cryptoSigner.Public())
	if err != nil {
		return nil, err
	}
	return &privkeyFileIdentity{
		privkey:       cryptoSigner,
		signingMethod: signingMethod,
	}, nil
}

func NewAgentAuthMethod(pubkey ssh.PublicKey) *AgentAuthMethod {
	return &AgentAuthMethod{
		pubkey: pubkey,
	}
}

// A prerequisite of calling this methiod is that the provided pubkey is explicitly listed by the agent
// This can be verified beforehand by calling agent.List()
func (m *AgentAuthMethod) IntoIdentity(agent agent.ExtendedAgent) Identity {
	return &agentBasedIdentity{
		pubkey: m.pubkey,
		agent:  agent,
	}
}

// a generic way to generate SSH3 identities to populate the HTTP Authorization header
type Identity interface {
	SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error
	// provides an authentication name that can be used as a hint for the server in the url query params
	AuthHint() string
	fmt.Stringer
}

// represents private keys stored in a classical file
type privkeyFileIdentity struct {
	privkey       crypto.Signer
	signingMethod jwt.SigningMethod
}

func (i *privkeyFileIdentity) SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error {
	bearerToken, err := BuildJWTBearerToken(i.signingMethod, i.privkey, username, conversation)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))
	return nil
}

func (i *privkeyFileIdentity) AuthHint() string {
	return "pubkey"
}

func (i *privkeyFileIdentity) String() string {
	return fmt.Sprintf("pubkey-identity: ALG=%s", i.signingMethod.Alg())
}

type agentSigningMethod struct {
	Agent agent.ExtendedAgent
	Key   ssh.PublicKey
}

func (m *agentSigningMethod) Verify(signingString string, sig []byte, key interface{}) error {
	panic("not implemented")
}

func (m *agentSigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	pk, ok := key.(ssh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("bad key type: %T instead of ssh.PublicKey", pk)
	}
	signature, err := m.Agent.SignWithFlags(pk, []byte(signingString), agent.SignatureFlagRsaSha256)
	if err != nil {
		return nil, err
	}
	return signature.Blob, nil
}

func (m *agentSigningMethod) Alg() string {
	switch m.Key.Type() {
	case "ssh-rsa":
		return "RS256"
	case "ssh-ed25519":
		return "EdDSA"
	}
	return ""
}

// represents an identity using a running SSH agent
type agentBasedIdentity struct {
	pubkey ssh.PublicKey
	agent  agent.ExtendedAgent
}

func (i *agentBasedIdentity) SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error {
	signingMethod := &agentSigningMethod{
		Agent: i.agent,
		Key:   i.pubkey,
	}

	bearerToken, err := BuildJWTBearerToken(signingMethod, i.pubkey, username, conversation)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))
	return nil
}

func (i *agentBasedIdentity) AuthHint() string {
	return "pubkey"
}

func (i *agentBasedIdentity) String() string {
	retval := "agent-identity"
	if stringer, ok := i.pubkey.(fmt.Stringer); ok {
		retval = fmt.Sprintf("%s: %s", retval, stringer.String())
	}
	return retval
}

type passwordIdentity string

func (i passwordIdentity) SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error {
	req.SetBasicAuth(username, string(i))
	return nil
}

func (i passwordIdentity) AuthHint() string {
	return "password"
}

func (i passwordIdentity) String() string {
	return "password-identity"
}

type rawBearerTokenIdentity string

func (i rawBearerTokenIdentity) SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(i)))
	return nil
}

func (i rawBearerTokenIdentity) AuthHint() string {
	return "jwt"
}

func (i rawBearerTokenIdentity) String() string {
	return "raw-bearer-identity"
}

func GetConfigForHost(host string, urlUser string, config *matchcfg.Resolver, pluginsOptionsParsers map[client_config.OptionName]client_config.OptionParser) (hostname string, port int, user string, urlPath string, authMethodsToTry []interface{}, pluginOptions map[client_config.OptionName]client_config.Option, err error) {
	pluginOptions = make(map[client_config.OptionName]client_config.Option)
	port = -1
	if config == nil {
		return
	}
	resolved, err := config.ConfigForHost(host, urlUser)
	if err != nil {
		// Mirror the historical behavior for unparseable configs: warn and
		// continue without any config file.
		log.Warn().Msgf("could not resolve ssh config for %s: %s, ignoring config", host, err)
		err = nil
		return
	}
	hostname, err = resolved.Get(host, "HostName")
	if err != nil {
		log.Error().Msgf("Could not get HostName from config: %s", err)
		return
	}
	portStr, err := resolved.Get(host, "Port")
	if err != nil {
		log.Error().Msgf("Could not get Port from config: %s", err)
		return
	}
	user, err = resolved.Get(host, "User")
	if err != nil {
		log.Error().Msgf("Could not get User from config: %s", err)
		return
	}
	urlPath, err = resolved.Get(host, "URLPath")
	if err != nil {
		log.Error().Msgf("Could not get URLPath from config: %s", err)
		return
	}
	if len(urlPath) > 0 && urlPath[0] != '/' {
		log.Error().Msgf("Non-empty URLPath in config file must start by a '/'")
		err = util.InvalidConfig{
			Field: "URLPath",
			Value: urlPath,
		}
		return
	}
	p, err := strconv.Atoi(portStr)
	if err == nil {
		port = p
	}
	identityFiles, err := resolved.GetAll(host, "IdentityFile")
	if err != nil {
		log.Error().Msgf("Could not get IdentityFiles from config: %s", err)
		return
	}
	for _, identityFile := range identityFiles {
		authMethodsToTry = append(authMethodsToTry, NewPrivkeyFileAuthMethod(identityFile))
	}

	log.Debug().Msgf("parsing options using option parsers: %+v", pluginsOptionsParsers)
	for optionName, optionParser := range pluginsOptionsParsers {
		log.Debug().Msgf("search for option %s (%s) in config", optionName, optionParser.OptionConfigName())
		var optionValues []string
		optionValues, err = resolved.GetAll(host, optionParser.OptionConfigName())
		if err != nil {
			log.Error().Msgf("config.Get returned an error: %s", err)
			return
		}
		if optionValues != nil {
			var option client_config.Option
			log.Debug().Msgf("found value(s) for %s: %s", optionParser.OptionConfigName(), optionValues)
			option, err = optionParser.Parse(optionValues)
			if err != nil {
				log.Error().Msgf("config option parser returned an error: %s", err)
				return
			}
			pluginOptions[optionName] = option
		}
	}

	return hostname, port, user, urlPath, authMethodsToTry, pluginOptions, nil
}

func BuildJWTBearerToken(signingMethod jwt.SigningMethod, key interface{}, username string, conversation *Conversation) (string, error) {
	convID := conversation.ConversationID()
	b64ConvID := base64.StdEncoding.EncodeToString(convID[:])
	token := jwt.NewWithClaims(signingMethod, jwt.MapClaims{
		"iss":       username,
		"iat":       jwt.NewNumericDate(time.Now()),
		"exp":       jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
		"sub":       "ssh3",
		"aud":       "unused",
		"client_id": fmt.Sprintf("ssh3-%s", username),
		"jti":       b64ConvID,
	})

	// the jwt lib handles "any kind" of crypto signer
	signedString, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("could not sign token: %s", err)
	}
	return signedString, nil
}
