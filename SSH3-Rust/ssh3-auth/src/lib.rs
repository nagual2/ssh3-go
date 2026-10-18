use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::EncodedPoint as P256EncodedPoint;
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use rsa::pkcs1v15::{
    Signature as RsaSignature, SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey,
};
use rsa::{
    BigUint as RsaBigUint, RsaPrivateKey as JwtRsaPrivateKey, RsaPublicKey as JwtRsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use signature::{SignatureEncoding, Signer, Verifier};
use ssh_key::authorized_keys::Entry as AuthorizedKeyEntry;
use ssh_key::private::{EcdsaKeypair, KeypairData, RsaKeypair};
use ssh_key::public::{EcdsaPublicKey, KeyData, RsaPublicKey};
use ssh_key::{Algorithm, EcdsaCurve, PrivateKey, PublicKey, Signature};

const TOKEN_AUDIENCE: &str = "unused";
const TOKEN_SUBJECT: &str = "ssh3";
const TOKEN_LIFETIME_SECS: u64 = 60;

#[derive(Debug)]
pub enum AuthError {
    Io(io::Error),
    Time(SystemTimeError),
    Json(serde_json::Error),
    Base64(base64::DecodeError),
    Reqwest(reqwest::Error),
    SshKey(ssh_key::Error),
    InvalidKeyMaterial(&'static str),
    InvalidToken(&'static str),
    UnsupportedAlgorithm(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Time(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
            Self::Base64(err) => write!(f, "{err}"),
            Self::Reqwest(err) => write!(f, "{err}"),
            Self::SshKey(err) => write!(f, "{err}"),
            Self::InvalidKeyMaterial(message) => write!(f, "{message}"),
            Self::InvalidToken(message) => write!(f, "{message}"),
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(f, "unsupported SSH key algorithm: {algorithm}")
            }
        }
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Time(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::Base64(err) => Some(err),
            Self::Reqwest(err) => Some(err),
            Self::SshKey(err) => Some(err),
            Self::InvalidKeyMaterial(_) => None,
            Self::InvalidToken(_) => None,
            Self::UnsupportedAlgorithm(_) => None,
        }
    }
}

impl From<io::Error> for AuthError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<SystemTimeError> for AuthError {
    fn from(value: SystemTimeError) -> Self {
        Self::Time(value)
    }
}

impl From<serde_json::Error> for AuthError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<base64::DecodeError> for AuthError {
    fn from(value: base64::DecodeError) -> Self {
        Self::Base64(value)
    }
}

impl From<reqwest::Error> for AuthError {
    fn from(value: reqwest::Error) -> Self {
        Self::Reqwest(value)
    }
}

impl From<ssh_key::Error> for AuthError {
    fn from(value: ssh_key::Error) -> Self {
        Self::SshKey(value)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
    client_id: String,
    jti: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizedIdentity {
    PublicKey(PublicKey),
    Oidc(OidcIdentity),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidcIdentity {
    pub client_id: String,
    pub issuer_url: String,
    pub email: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtAlgorithm {
    EdDsa,
    Es256,
    Rs256,
}

impl JwtAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
            Self::Rs256 => "RS256",
        }
    }
}

pub fn bearer_authorization_value(token: &str) -> String {
    format!("Bearer {token}")
}

pub fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKey, AuthError> {
    let private_key = PrivateKey::read_openssh_file(path.as_ref())?;
    if private_key.is_encrypted() {
        return Err(AuthError::InvalidToken(
            "encrypted private keys are not supported yet",
        ));
    }
    Ok(private_key)
}

pub fn load_authorized_public_keys_from_paths(
    paths: &[PathBuf],
) -> Result<Vec<PublicKey>, AuthError> {
    Ok(load_authorized_identities_from_paths(paths)?
        .into_iter()
        .filter_map(|identity| match identity {
            AuthorizedIdentity::PublicKey(public_key) => Some(public_key),
            AuthorizedIdentity::Oidc(_) => None,
        })
        .collect())
}

pub fn load_authorized_identities_from_paths(
    paths: &[PathBuf],
) -> Result<Vec<AuthorizedIdentity>, AuthError> {
    let mut identities = Vec::new();
    for path in paths {
        match std::fs::read_to_string(path) {
            Ok(contents) => identities.extend(parse_authorized_identities(&contents)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(AuthError::Io(err)),
        }
    }
    Ok(identities)
}

pub fn parse_authorized_public_keys(contents: &str) -> Vec<PublicKey> {
    parse_authorized_identities(contents)
        .into_iter()
        .filter_map(|identity| match identity {
            AuthorizedIdentity::PublicKey(public_key) => Some(public_key),
            AuthorizedIdentity::Oidc(_) => None,
        })
        .collect()
}

pub fn parse_authorized_identities(contents: &str) -> Vec<AuthorizedIdentity> {
    contents
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            parse_oidc_identity(trimmed)
                .map(AuthorizedIdentity::Oidc)
                .or_else(|| {
                    trimmed
                        .parse::<AuthorizedKeyEntry>()
                        .ok()
                        .map(|entry| AuthorizedIdentity::PublicKey(entry.public_key().clone()))
                })
        })
        .collect()
}

fn parse_oidc_identity(line: &str) -> Option<OidcIdentity> {
    let mut parts = line.split_whitespace();
    match parts.next()? {
        "oidc" => {
            let client_id = parts.next()?;
            let issuer_url = parts.next()?;
            let email = parts.next()?;
            if parts.next().is_some() {
                return None;
            }
            Some(OidcIdentity {
                client_id: client_id.to_string(),
                issuer_url: issuer_url.to_string(),
                email: email.to_string(),
            })
        }
        _ => None,
    }
}

pub fn build_bearer_token(
    private_key: &PrivateKey,
    username: &str,
    conversation_id: &[u8; 32],
) -> Result<String, AuthError> {
    build_bearer_token_with_signer(
        private_key.public_key(),
        username,
        conversation_id,
        |jwt_algorithm, signing_input| {
            sign_jwt_signature(private_key, jwt_algorithm, signing_input)
        },
    )
}

pub fn build_bearer_token_with_signer<E>(
    public_key: &PublicKey,
    username: &str,
    conversation_id: &[u8; 32],
    signer: impl FnOnce(JwtAlgorithm, &[u8]) -> Result<Vec<u8>, E>,
) -> Result<String, E>
where
    E: From<AuthError>,
{
    let jwt_algorithm = jwt_algorithm_for_public_key(public_key).map_err(E::from)?;

    let now = unix_timestamp_now().map_err(E::from)?;
    let header = JwtHeader {
        alg: jwt_algorithm.as_str().to_string(),
        typ: "JWT".to_string(),
    };
    let claims = JwtClaims {
        iss: username.to_string(),
        sub: TOKEN_SUBJECT.to_string(),
        aud: TOKEN_AUDIENCE.to_string(),
        iat: now,
        exp: now + TOKEN_LIFETIME_SECS,
        client_id: format!("ssh3-{username}"),
        jti: conversation_id_base64(conversation_id),
    };

    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|err| E::from(AuthError::from(err)))?);
    let claims_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&claims).map_err(|err| E::from(AuthError::from(err)))?);
    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature = signer(jwt_algorithm, signing_input.as_bytes())?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);
    Ok(format!("{signing_input}.{signature_b64}"))
}

pub fn verify_bearer_token(
    public_key: &PublicKey,
    token: &str,
    expected_username: &str,
    conversation_id: &[u8; 32],
) -> Result<(), AuthError> {
    let jwt_algorithm = jwt_algorithm_for_public_key(public_key)?;

    let (signing_input, signature_part) = token
        .rsplit_once('.')
        .ok_or(AuthError::InvalidToken("malformed bearer token"))?;
    let (header_part, claims_part) = signing_input
        .split_once('.')
        .ok_or(AuthError::InvalidToken("malformed bearer token"))?;

    let header: JwtHeader = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_part)?)?;
    if header.alg != jwt_algorithm.as_str() {
        return Err(AuthError::InvalidToken("unexpected JWT alg"));
    }

    let claims: JwtClaims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims_part)?)?;
    let now = unix_timestamp_now()?;
    if claims.iss != expected_username {
        return Err(AuthError::InvalidToken("unexpected JWT issuer"));
    }
    if claims.sub != TOKEN_SUBJECT {
        return Err(AuthError::InvalidToken("unexpected JWT subject"));
    }
    if claims.aud != TOKEN_AUDIENCE {
        return Err(AuthError::InvalidToken("unexpected JWT audience"));
    }
    if claims.client_id != format!("ssh3-{expected_username}") {
        return Err(AuthError::InvalidToken("unexpected JWT client_id"));
    }
    if claims.jti != conversation_id_base64(conversation_id) {
        return Err(AuthError::InvalidToken("unexpected JWT jti"));
    }
    if claims.iat > now {
        return Err(AuthError::InvalidToken("JWT issued-at is in the future"));
    }
    if claims.exp < now {
        return Err(AuthError::InvalidToken("JWT is expired"));
    }

    verify_jwt_signature(
        public_key,
        jwt_algorithm,
        signing_input.as_bytes(),
        &URL_SAFE_NO_PAD.decode(signature_part)?,
    )
}

pub fn conversation_id_base64(conversation_id: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(conversation_id)
}

pub async fn verify_oidc_identity_token(
    identity: &OidcIdentity,
    token: &str,
    expected_nonce: Option<&str>,
) -> Result<(), AuthError> {
    let (signing_input, signature_part) = token
        .rsplit_once('.')
        .ok_or(AuthError::InvalidToken("malformed bearer token"))?;
    let (header_part, claims_part) = signing_input
        .split_once('.')
        .ok_or(AuthError::InvalidToken("malformed bearer token"))?;

    let header: OidcJwtHeader = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_part)?)?;
    let claims: OidcClaims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims_part)?)?;
    let now = unix_timestamp_now()?;
    if claims.iss != identity.issuer_url {
        return Err(AuthError::InvalidToken("unexpected OIDC issuer"));
    }
    if !claims.aud.contains(&identity.client_id) {
        return Err(AuthError::InvalidToken("unexpected OIDC audience"));
    }
    if claims.exp < now {
        return Err(AuthError::InvalidToken("OIDC token is expired"));
    }
    if claims.email.as_deref() != Some(identity.email.as_str()) {
        return Err(AuthError::InvalidToken("unexpected OIDC email"));
    }
    if !claims.email_verified {
        return Err(AuthError::InvalidToken("OIDC email is not verified"));
    }
    if let Some(expected_nonce) = expected_nonce
        && claims.nonce.as_deref() != Some(expected_nonce)
    {
        return Err(AuthError::InvalidToken("unexpected OIDC nonce"));
    }

    let client = reqwest::Client::new();
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        identity.issuer_url.trim_end_matches('/')
    );
    let discovery: OidcDiscoveryDocument = client
        .get(discovery_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if discovery.issuer != identity.issuer_url {
        return Err(AuthError::InvalidToken("unexpected OIDC discovery issuer"));
    }

    let jwks: OidcJwks = client
        .get(discovery.jwks_uri)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let jwk = select_oidc_jwk(&jwks, &header)?;
    verify_oidc_jwk_signature(
        jwk,
        &header.alg,
        signing_input.as_bytes(),
        &URL_SAFE_NO_PAD.decode(signature_part)?,
    )
}

fn unix_timestamp_now() -> Result<u64, AuthError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn jwt_algorithm_for_public_key(public_key: &PublicKey) -> Result<JwtAlgorithm, AuthError> {
    match public_key.key_data() {
        KeyData::Ed25519(_) => Ok(JwtAlgorithm::EdDsa),
        KeyData::Ecdsa(EcdsaPublicKey::NistP256(_)) => Ok(JwtAlgorithm::Es256),
        KeyData::Rsa(_) => Ok(JwtAlgorithm::Rs256),
        _ => Err(AuthError::UnsupportedAlgorithm(
            public_key.algorithm().as_str().to_string(),
        )),
    }
}

fn sign_jwt_signature(
    private_key: &PrivateKey,
    jwt_algorithm: JwtAlgorithm,
    signing_input: &[u8],
) -> Result<Vec<u8>, AuthError> {
    match jwt_algorithm {
        JwtAlgorithm::EdDsa => {
            let signature = Signer::try_sign(private_key, signing_input)
                .map_err(|_| AuthError::InvalidToken("could not sign bearer token"))?;
            Ok(signature.as_bytes().to_vec())
        }
        JwtAlgorithm::Es256 => {
            let signing_key = match private_key.key_data() {
                KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) => {
                    P256SigningKey::from_slice(private.as_ref())
                        .map_err(|_| AuthError::InvalidKeyMaterial("invalid P-256 private key"))?
                }
                _ => {
                    return Err(AuthError::UnsupportedAlgorithm(
                        private_key.public_key().algorithm().as_str().to_string(),
                    ));
                }
            };
            let signature: P256Signature = Signer::try_sign(&signing_key, signing_input)
                .map_err(|_| AuthError::InvalidToken("could not sign bearer token"))?;
            Ok(signature.to_bytes().to_vec())
        }
        JwtAlgorithm::Rs256 => {
            let signing_key = match private_key.key_data() {
                KeypairData::Rsa(keypair) => {
                    RsaSigningKey::<Sha256>::new(rsa_private_key(keypair)?)
                }
                _ => {
                    return Err(AuthError::UnsupportedAlgorithm(
                        private_key.public_key().algorithm().as_str().to_string(),
                    ));
                }
            };
            let signature: RsaSignature = Signer::try_sign(&signing_key, signing_input)
                .map_err(|_| AuthError::InvalidToken("could not sign bearer token"))?;
            Ok(signature.to_vec())
        }
    }
}

fn verify_jwt_signature(
    public_key: &PublicKey,
    jwt_algorithm: JwtAlgorithm,
    signing_input: &[u8],
    signature_bytes: &[u8],
) -> Result<(), AuthError> {
    match jwt_algorithm {
        JwtAlgorithm::EdDsa => {
            let signature = Signature::new(Algorithm::Ed25519, signature_bytes.to_vec())?;
            Verifier::verify(public_key, signing_input, &signature)
                .map_err(|_| AuthError::InvalidToken("JWT signature verification failed"))
        }
        JwtAlgorithm::Es256 => {
            let verifying_key = match public_key.key_data() {
                KeyData::Ecdsa(ecdsa_public_key)
                    if ecdsa_public_key.curve() == EcdsaCurve::NistP256 =>
                {
                    P256VerifyingKey::try_from(ecdsa_public_key)
                        .map_err(|_| AuthError::InvalidKeyMaterial("invalid P-256 public key"))?
                }
                _ => {
                    return Err(AuthError::UnsupportedAlgorithm(
                        public_key.algorithm().as_str().to_string(),
                    ));
                }
            };
            let signature = P256Signature::from_slice(signature_bytes)
                .map_err(|_| AuthError::InvalidToken("malformed ES256 signature"))?;
            verifying_key
                .verify(signing_input, &signature)
                .map_err(|_| AuthError::InvalidToken("JWT signature verification failed"))
        }
        JwtAlgorithm::Rs256 => {
            let verifying_key = match public_key.key_data() {
                KeyData::Rsa(ssh_rsa_public_key) => {
                    RsaVerifyingKey::<Sha256>::new(rsa_public_key(ssh_rsa_public_key)?)
                }
                _ => {
                    return Err(AuthError::UnsupportedAlgorithm(
                        public_key.algorithm().as_str().to_string(),
                    ));
                }
            };
            let signature = RsaSignature::try_from(signature_bytes)
                .map_err(|_| AuthError::InvalidToken("malformed RS256 signature"))?;
            verifying_key
                .verify(signing_input, &signature)
                .map_err(|_| AuthError::InvalidToken("JWT signature verification failed"))
        }
    }
}

fn rsa_private_key(keypair: &RsaKeypair) -> Result<JwtRsaPrivateKey, AuthError> {
    let private_key = JwtRsaPrivateKey::from_components(
        rsa_biguint(keypair.public.n.as_positive_bytes())?,
        rsa_biguint(keypair.public.e.as_positive_bytes())?,
        rsa_biguint(keypair.private.d.as_positive_bytes())?,
        vec![
            rsa_biguint(keypair.private.p.as_positive_bytes())?,
            rsa_biguint(keypair.private.q.as_positive_bytes())?,
        ],
    )
    .map_err(|_| AuthError::InvalidKeyMaterial("invalid RSA private key"))?;
    private_key
        .validate()
        .map_err(|_| AuthError::InvalidKeyMaterial("invalid RSA private key"))?;
    Ok(private_key)
}

fn rsa_public_key(public_key: &RsaPublicKey) -> Result<JwtRsaPublicKey, AuthError> {
    JwtRsaPublicKey::new(
        rsa_biguint(public_key.n.as_positive_bytes())?,
        rsa_biguint(public_key.e.as_positive_bytes())?,
    )
    .map_err(|_| AuthError::InvalidKeyMaterial("invalid RSA public key"))
}

fn rsa_biguint(bytes: Option<&[u8]>) -> Result<RsaBigUint, AuthError> {
    let bytes = bytes.ok_or(AuthError::InvalidKeyMaterial("invalid RSA key component"))?;
    Ok(RsaBigUint::from_bytes_be(bytes))
}

#[derive(Debug, Deserialize)]
struct OidcJwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OidcAudience {
    One(String),
    Many(Vec<String>),
}

impl OidcAudience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

#[derive(Debug, Deserialize)]
struct OidcClaims {
    iss: String,
    aud: OidcAudience,
    exp: u64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct OidcJwks {
    keys: Vec<OidcJwk>,
}

#[derive(Debug, Deserialize)]
struct OidcJwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

fn select_oidc_jwk<'a>(
    jwks: &'a OidcJwks,
    header: &OidcJwtHeader,
) -> Result<&'a OidcJwk, AuthError> {
    jwks.keys
        .iter()
        .find(|jwk| {
            header
                .kid
                .as_deref()
                .is_none_or(|expected| jwk.kid.as_deref() == Some(expected))
                && jwk
                    .alg
                    .as_deref()
                    .is_none_or(|expected| expected == header.alg)
                && oidc_jwk_supports_algorithm(jwk, &header.alg)
        })
        .ok_or(AuthError::InvalidToken("no matching OIDC JWK found"))
}

fn oidc_jwk_supports_algorithm(jwk: &OidcJwk, alg: &str) -> bool {
    match alg {
        "RS256" => jwk.kty == "RSA" && jwk.n.is_some() && jwk.e.is_some(),
        "ES256" => {
            jwk.kty == "EC"
                && jwk.crv.as_deref() == Some("P-256")
                && jwk.x.is_some()
                && jwk.y.is_some()
        }
        _ => false,
    }
}

fn verify_oidc_jwk_signature(
    jwk: &OidcJwk,
    alg: &str,
    signing_input: &[u8],
    signature_bytes: &[u8],
) -> Result<(), AuthError> {
    match alg {
        "RS256" => {
            let verifying_key = RsaVerifyingKey::<Sha256>::new(
                JwtRsaPublicKey::new(
                    rsa_biguint(Some(
                        &URL_SAFE_NO_PAD.decode(
                            jwk.n
                                .as_deref()
                                .ok_or(AuthError::InvalidKeyMaterial("missing RSA modulus"))?,
                        )?,
                    ))?,
                    rsa_biguint(Some(
                        &URL_SAFE_NO_PAD.decode(
                            jwk.e
                                .as_deref()
                                .ok_or(AuthError::InvalidKeyMaterial("missing RSA exponent"))?,
                        )?,
                    ))?,
                )
                .map_err(|_| AuthError::InvalidKeyMaterial("invalid RSA public key"))?,
            );
            let signature = RsaSignature::try_from(signature_bytes)
                .map_err(|_| AuthError::InvalidToken("malformed RS256 signature"))?;
            verifying_key
                .verify(signing_input, &signature)
                .map_err(|_| AuthError::InvalidToken("JWT signature verification failed"))
        }
        "ES256" => {
            let x = URL_SAFE_NO_PAD.decode(
                jwk.x
                    .as_deref()
                    .ok_or(AuthError::InvalidKeyMaterial("missing EC x coordinate"))?,
            )?;
            let y = URL_SAFE_NO_PAD.decode(
                jwk.y
                    .as_deref()
                    .ok_or(AuthError::InvalidKeyMaterial("missing EC y coordinate"))?,
            )?;
            if x.len() != 32 || y.len() != 32 {
                return Err(AuthError::InvalidKeyMaterial(
                    "invalid P-256 public key coordinates",
                ));
            }
            let point = P256EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                y.as_slice().into(),
                false,
            );
            let verifying_key = P256VerifyingKey::from_encoded_point(&point)
                .map_err(|_| AuthError::InvalidKeyMaterial("invalid P-256 public key"))?;
            let signature = P256Signature::from_slice(signature_bytes)
                .map_err(|_| AuthError::InvalidToken("malformed ES256 signature"))?;
            verifying_key
                .verify(signing_input, &signature)
                .map_err(|_| AuthError::InvalidToken("JWT signature verification failed"))
        }
        _ => Err(AuthError::UnsupportedAlgorithm(alg.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::SecretKey as P256SecretKey;
    use rand_core::OsRng;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
    use rsa::traits::PublicKeyParts;
    use sha2::Sha256;
    use signature::{SignatureEncoding, Signer};
    use ssh_key::LineEnding;
    use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, RsaKeypair};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        AuthorizedIdentity, OidcIdentity, build_bearer_token, parse_authorized_identities,
        parse_authorized_public_keys, verify_bearer_token, verify_oidc_identity_token,
    };

    struct OidcTestFixture {
        identity: OidcIdentity,
        nonce: String,
        token: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for OidcTestFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn start_oidc_fixture() -> OidcTestFixture {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let issuer_url = format!("http://{}", listener.local_addr().unwrap());
        let client_id = "ssh3-client-id".to_string();
        let email = "alice@example.com".to_string();
        let nonce = "expected-ssh3-conversation".to_string();
        let signing_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = signing_key.to_public_key();
        let discovery_body =
            format!(r#"{{"issuer":"{issuer_url}","jwks_uri":"{issuer_url}/keys"}}"#);
        let jwks_body = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"test-key","alg":"RS256","n":"{}","e":"{}"}}]}}"#,
            URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        );
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let discovery_body = discovery_body.clone();
                let jwks_body = jwks_body.clone();
                tokio::spawn(async move {
                    let path = read_http_request_path(&mut stream).await.unwrap();
                    let (status_line, body) = match path.as_str() {
                        "/.well-known/openid-configuration" => ("HTTP/1.1 200 OK", discovery_body),
                        "/keys" => ("HTTP/1.1 200 OK", jwks_body),
                        _ => ("HTTP/1.1 404 Not Found", "{}".to_string()),
                    };
                    let response = format!(
                        "{status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        OidcTestFixture {
            identity: OidcIdentity {
                client_id: client_id.clone(),
                issuer_url: issuer_url.clone(),
                email: email.clone(),
            },
            nonce: nonce.clone(),
            token: build_oidc_token(&issuer_url, &client_id, &email, Some(&nonce), &signing_key),
            task,
        }
    }

    async fn read_http_request_path(
        stream: &mut tokio::net::TcpStream,
    ) -> Result<String, std::io::Error> {
        let mut buffer = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        Ok(String::from_utf8_lossy(&buffer)
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_string())
    }

    fn build_oidc_token(
        issuer_url: &str,
        client_id: &str,
        email: &str,
        nonce: Option<&str>,
        private_key: &RsaPrivateKey,
    ) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"test-key","typ":"JWT"}"#);
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + Duration::from_secs(60).as_secs();
        let nonce_claim = nonce
            .map(|nonce| format!(r#","nonce":"{nonce}""#))
            .unwrap_or_default();
        let claims = URL_SAFE_NO_PAD.encode(
            format!(
                r#"{{"iss":"{issuer_url}","aud":"{client_id}","exp":{exp},"email":"{email}","email_verified":true{nonce_claim}}}"#
            )
            .as_bytes(),
        );
        let signing_input = format!("{header}.{claims}");
        let signing_key = RsaSigningKey::<Sha256>::new(private_key.clone());
        let signature: RsaSignature =
            Signer::try_sign(&signing_key, signing_input.as_bytes()).unwrap();
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_vec())
        )
    }

    #[test]
    fn ed25519_bearer_tokens_round_trip() {
        let private_key = ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
        let public_key = private_key.public_key().clone();
        let conversation_id = [9u8; 32];

        let token = build_bearer_token(&private_key, "alice", &conversation_id).unwrap();
        verify_bearer_token(&public_key, &token, "alice", &conversation_id).unwrap();
    }

    #[test]
    fn nist_p256_bearer_tokens_round_trip() {
        let secret_key = P256SecretKey::from_slice(&[11; 32]).unwrap();
        let private_key = ssh_key::PrivateKey::from(EcdsaKeypair::NistP256 {
            public: secret_key.public_key().into(),
            private: secret_key.into(),
        });
        let public_key = private_key.public_key().clone();
        let conversation_id = [5u8; 32];

        let token = build_bearer_token(&private_key, "alice", &conversation_id).unwrap();
        verify_bearer_token(&public_key, &token, "alice", &conversation_id).unwrap();
    }

    #[test]
    fn rsa_bearer_tokens_round_trip() {
        let rsa_private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let private_key =
            ssh_key::PrivateKey::from(RsaKeypair::try_from(&rsa_private_key).unwrap());
        let public_key = private_key.public_key().clone();
        let conversation_id = [13u8; 32];

        let token = build_bearer_token(&private_key, "alice", &conversation_id).unwrap();
        verify_bearer_token(&public_key, &token, "alice", &conversation_id).unwrap();
    }

    #[test]
    fn authorized_keys_lines_are_parsed() {
        let private_key = ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[3; 32]));
        let p256_secret_key = P256SecretKey::from_slice(&[17; 32]).unwrap();
        let p256_private_key = ssh_key::PrivateKey::from(EcdsaKeypair::NistP256 {
            public: p256_secret_key.public_key().into(),
            private: p256_secret_key.into(),
        });
        let rsa_private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let rsa_private_key =
            ssh_key::PrivateKey::from(RsaKeypair::try_from(&rsa_private_key).unwrap());
        let contents = format!(
            "# comment\noidc oidc-client https://issuer.example alice@example.com\n{}\n{}\n{}\n",
            private_key.public_key().to_openssh().unwrap(),
            p256_private_key.public_key().to_openssh().unwrap(),
            rsa_private_key.public_key().to_openssh().unwrap(),
        );

        let identities = parse_authorized_identities(&contents);
        assert_eq!(identities.len(), 4);
        assert_eq!(
            identities[0],
            AuthorizedIdentity::Oidc(OidcIdentity {
                client_id: "oidc-client".to_string(),
                issuer_url: "https://issuer.example".to_string(),
                email: "alice@example.com".to_string(),
            })
        );

        let parsed = parse_authorized_public_keys(&contents);
        assert_eq!(parsed.len(), 3);
        assert_eq!(
            parsed[0].to_openssh().unwrap(),
            private_key.public_key().to_openssh().unwrap()
        );
        assert_eq!(
            parsed[1].to_openssh().unwrap(),
            p256_private_key.public_key().to_openssh().unwrap()
        );
        assert_eq!(
            parsed[2].to_openssh().unwrap(),
            rsa_private_key.public_key().to_openssh().unwrap()
        );

        let private_key_str = private_key.to_openssh(LineEnding::LF).unwrap();
        assert!(private_key_str.contains("OPENSSH PRIVATE KEY"));
    }

    #[tokio::test]
    async fn oidc_tokens_round_trip_against_a_mock_issuer() {
        let fixture = start_oidc_fixture().await;
        verify_oidc_identity_token(&fixture.identity, &fixture.token, Some(&fixture.nonce))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn oidc_tokens_reject_the_wrong_nonce() {
        let fixture = start_oidc_fixture().await;
        let err =
            verify_oidc_identity_token(&fixture.identity, &fixture.token, Some("wrong-nonce"))
                .await
                .unwrap_err();
        assert_eq!(err.to_string(), "unexpected OIDC nonce");
    }
}
