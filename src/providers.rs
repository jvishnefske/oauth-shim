//! OAuth provider definitions and userinfo retrieval.

use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Google,
    Microsoft,
    Github,
}

impl Provider {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "google" => Some(Self::Google),
            "microsoft" => Some(Self::Microsoft),
            "github" => Some(Self::Github),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Microsoft => "microsoft",
            Self::Github => "github",
        }
    }

    pub fn auth_url(self) -> &'static str {
        match self {
            Self::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            Self::Microsoft => "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            Self::Github => "https://github.com/login/oauth/authorize",
        }
    }

    pub fn token_url(self) -> &'static str {
        match self {
            Self::Google => "https://oauth2.googleapis.com/token",
            Self::Microsoft => "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            Self::Github => "https://github.com/login/oauth/access_token",
        }
    }

    pub fn scopes(self) -> &'static [&'static str] {
        match self {
            Self::Google | Self::Microsoft => &["openid", "email", "profile"],
            Self::Github => &["read:user", "user:email"],
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub client_id: String,
    pub client_secret: String,
}

/// Build an oauth2 client for `provider` with the given redirect URI.
pub fn build_client(
    provider: Provider,
    cfg: &ProviderConfig,
    redirect_uri: &str,
) -> Result<BasicClient, oauth2::url::ParseError> {
    Ok(BasicClient::new(
        ClientId::new(cfg.client_id.clone()),
        Some(ClientSecret::new(cfg.client_secret.clone())),
        AuthUrl::new(provider.auth_url().to_string())?,
        Some(TokenUrl::new(provider.token_url().to_string())?),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string())?))
}

/// Normalized identity returned by every provider.
#[derive(Debug, Clone)]
pub struct Identity {
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

#[derive(Deserialize)]
struct OidcUserInfo {
    sub: String,
    email: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct GithubUser {
    id: i64,
    login: String,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

/// Fetch the user's identity from the provider using the access token.
pub async fn fetch_identity(
    http: &reqwest::Client,
    provider: Provider,
    access_token: &str,
) -> Result<Identity, String> {
    match provider {
        Provider::Google | Provider::Microsoft => {
            let url = match provider {
                Provider::Google => "https://openidconnect.googleapis.com/v1/userinfo",
                Provider::Microsoft => "https://graph.microsoft.com/oidc/userinfo",
                Provider::Github => unreachable!(),
            };
            let info: OidcUserInfo = http
                .get(url)
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|e| format!("userinfo request failed: {e}"))?
                .error_for_status()
                .map_err(|e| format!("userinfo returned error: {e}"))?
                .json()
                .await
                .map_err(|e| format!("userinfo parse failed: {e}"))?;
            Ok(Identity {
                subject: info.sub,
                email: info.email.map(|e| e.to_lowercase()),
                name: info.name,
            })
        }
        Provider::Github => {
            let user: GithubUser = http
                .get("https://api.github.com/user")
                .bearer_auth(access_token)
                .header("User-Agent", "oauth-shim")
                .header("Accept", "application/vnd.github+json")
                .send()
                .await
                .map_err(|e| format!("github user request failed: {e}"))?
                .error_for_status()
                .map_err(|e| format!("github user returned error: {e}"))?
                .json()
                .await
                .map_err(|e| format!("github user parse failed: {e}"))?;

            // The public profile email is often null; fall back to the
            // verified primary address from /user/emails.
            let mut email = user.email;
            if email.is_none() {
                if let Ok(resp) = http
                    .get("https://api.github.com/user/emails")
                    .bearer_auth(access_token)
                    .header("User-Agent", "oauth-shim")
                    .header("Accept", "application/vnd.github+json")
                    .send()
                    .await
                {
                    if let Ok(emails) = resp.json::<Vec<GithubEmail>>().await {
                        email = emails
                            .into_iter()
                            .find(|e| e.primary && e.verified)
                            .map(|e| e.email);
                    }
                }
            }

            Ok(Identity {
                subject: user.id.to_string(),
                email: email.map(|e| e.to_lowercase()),
                name: user.name.or(Some(user.login)),
            })
        }
    }
}
