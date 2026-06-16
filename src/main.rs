//! oauth-shim: a small containerized login shim.
//!
//! Flow: /auth/{provider}/login → provider consent → /auth/{provider}/callback
//! → user upserted into SQLite → opaque session cookie → /admin.
//!
//! Also exposes GET /auth/verify for reverse-proxy ForwardAuth (Traefik,
//! nginx auth_request): 200 + X-Auth-* headers when authorized, otherwise a
//! redirect into the login flow that returns to the original URL.

mod db;
mod providers;

use axum::{
    extract::{Path, Query, State},
    http::{header::HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use oauth2::reqwest::async_http_client;
use oauth2::url::{form_urlencoded, Url};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
};
use providers::{Provider, ProviderConfig};
use rand::RngCore;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

const SESSION_COOKIE: &str = "shim_session";
const STATE_TTL_SECS: i64 = 10 * 60;

struct PendingAuth {
    provider: Provider,
    verifier: String,
    return_to: Option<String>,
    expires_at: i64,
}

struct AppState {
    db: Mutex<Connection>,
    http: reqwest::Client,
    base_url: String,
    cookie_secure: bool,
    /// e.g. "example.com" to share the session across *.example.com.
    cookie_domain: Option<String>,
    /// If true (default), /auth/verify requires is_admin, not just a login.
    verify_requires_admin: bool,
    admin_emails: HashSet<String>,
    providers: HashMap<&'static str, ProviderConfig>,
    /// state -> pending auth. Single-instance only.
    pending: Mutex<HashMap<String, PendingAuth>>,
}

type Shared = Arc<AppState>;

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn load_state() -> Shared {
    let base_url = env_opt("BASE_URL").unwrap_or_else(|| "http://localhost:8080".to_string());
    let base_url = base_url.trim_end_matches('/').to_string();
    let db_path = env_opt("DB_PATH").unwrap_or_else(|| "/data/shim.db".to_string());
    let cookie_domain = env_opt("COOKIE_DOMAIN").map(|d| d.trim_start_matches('.').to_string());
    let verify_requires_admin = env_opt("VERIFY_REQUIRE_ADMIN")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);

    let admin_emails: HashSet<String> = env_opt("ADMIN_EMAILS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if admin_emails.is_empty() {
        tracing::warn!("ADMIN_EMAILS is empty: no account will receive admin access");
    }

    let mut providers = HashMap::new();
    for (name, id_var, secret_var) in [
        ("google", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"),
        (
            "microsoft",
            "MICROSOFT_CLIENT_ID",
            "MICROSOFT_CLIENT_SECRET",
        ),
        ("github", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"),
    ] {
        match (env_opt(id_var), env_opt(secret_var)) {
            (Some(client_id), Some(client_secret)) => {
                providers.insert(
                    name,
                    ProviderConfig {
                        client_id,
                        client_secret,
                    },
                );
                tracing::info!("provider enabled: {name}");
            }
            _ => tracing::warn!("provider disabled (missing {id_var}/{secret_var}): {name}"),
        }
    }

    let conn = db::open(&db_path).expect("failed to open sqlite database");
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("failed to build http client");

    Arc::new(AppState {
        db: Mutex::new(conn),
        http,
        cookie_secure: base_url.starts_with("https://"),
        cookie_domain,
        verify_requires_admin,
        base_url,
        admin_emails,
        providers,
        pending: Mutex::new(HashMap::new()),
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let state = load_state();
    let listen = env_opt("LISTEN_ADDR").unwrap_or_else(|| "0.0.0.0:8080".to_string());

    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(|| async { "ok" }))
        .route("/whoami", get(whoami))
        .route("/auth/verify", get(verify))
        .route("/auth/:provider/login", get(login))
        .route("/auth/:provider/callback", get(callback))
        .route("/admin", get(admin))
        .route("/logout", post(logout))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .expect("failed to bind listen address");
    tracing::info!("listening on {listen}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server error");
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn urlencode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Accept a return-to URL only if it points at our own host or a subdomain of
/// COOKIE_DOMAIN, to prevent use as an open redirector.
fn validate_return_to(state: &AppState, rd: &str) -> Option<String> {
    let url = Url::parse(rd).ok()?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return None;
    }
    let host = url.host_str()?.to_lowercase();
    let own_host = Url::parse(&state.base_url).ok()?.host_str()?.to_lowercase();
    let allowed = host == own_host
        || state
            .cookie_domain
            .as_deref()
            .map(|d| host == d || host.ends_with(&format!(".{d}")))
            .unwrap_or(false);
    if allowed {
        Some(url.to_string())
    } else {
        tracing::warn!("rejected return-to URL outside allowed domain: {rd}");
        None
    }
}

#[derive(Deserialize, Default)]
struct RdQuery {
    rd: Option<String>,
}

async fn index(State(state): State<Shared>, Query(q): Query<RdQuery>, jar: CookieJar) -> Response {
    let user = current_user(&state, &jar);
    let rd = q.rd.as_deref().and_then(|r| validate_return_to(&state, r));
    let rd_suffix = rd
        .as_deref()
        .map(|r| format!("?rd={}", urlencode(r)))
        .unwrap_or_default();
    let session_block = match user {
        Some(u) => format!(
            "<p>Signed in as <b>{}</b> via {}{}</p>\
             <p><a href=\"/admin\">Admin</a></p>\
             <form method=\"post\" action=\"/logout\"><button>Sign out</button></form>",
            html_escape(u.email.as_deref().unwrap_or("(no email)")),
            html_escape(&u.provider),
            if u.is_admin { " — admin" } else { "" },
        ),
        None => {
            let mut buttons = String::new();
            for p in ["google", "microsoft", "github"] {
                if state.providers.contains_key(p) {
                    buttons.push_str(&format!(
                        "<p><a href=\"/auth/{p}/login{}\">Sign in with {p}</a></p>",
                        html_escape(&rd_suffix)
                    ));
                }
            }
            if buttons.is_empty() {
                buttons = "<p>No providers configured.</p>".to_string();
            }
            buttons
        }
    };
    Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>oauth-shim</title>\
         <body style=\"font-family:sans-serif;max-width:32rem;margin:4rem auto\">\
         <h1>oauth-shim</h1>{session_block}</body>"
    ))
    .into_response()
}

async fn login(
    State(state): State<Shared>,
    Path(provider): Path<String>,
    Query(q): Query<RdQuery>,
) -> Result<Redirect, Response> {
    let provider = Provider::from_str(&provider)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown provider"))?;
    let cfg = state
        .providers
        .get(provider.as_str())
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "provider not configured"))?;

    let redirect_uri = format!("{}/auth/{}/callback", state.base_url, provider.as_str());
    let client = providers::build_client(provider, cfg, &redirect_uri)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "bad provider config"))?;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut req = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge);
    for s in provider.scopes() {
        req = req.add_scope(Scope::new((*s).to_string()));
    }
    let (auth_url, csrf) = req.url();

    let return_to = q.rd.as_deref().and_then(|r| validate_return_to(&state, r));

    // Remember state -> verifier, and drop anything stale.
    {
        let mut pending = state.pending.lock().expect("pending lock poisoned");
        let t = db::now();
        pending.retain(|_, p| p.expires_at >= t);
        pending.insert(
            csrf.secret().clone(),
            PendingAuth {
                provider,
                verifier: pkce_verifier.secret().clone(),
                return_to,
                expires_at: t + STATE_TTL_SECS,
            },
        );
    }

    Ok(Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback(
    State(state): State<Shared>,
    Path(provider): Path<String>,
    Query(q): Query<CallbackQuery>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), Response> {
    let provider = Provider::from_str(&provider)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown provider"))?;
    let cfg = state
        .providers
        .get(provider.as_str())
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "provider not configured"))?;

    if let Some(e) = q.error {
        tracing::warn!(
            "provider returned error: {e}: {}",
            q.error_description.unwrap_or_default()
        );
        return Err(err(StatusCode::BAD_REQUEST, "authorization was denied"));
    }
    let code = q
        .code
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing code"))?;
    let csrf = q
        .state
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing state"))?;

    // CSRF check: the state must be one we issued, unexpired, for this provider.
    let (verifier, return_to) = {
        let mut pending = state.pending.lock().expect("pending lock poisoned");
        match pending.remove(&csrf) {
            Some(p) if p.provider == provider && p.expires_at >= db::now() => {
                (p.verifier, p.return_to)
            }
            _ => return Err(err(StatusCode::BAD_REQUEST, "invalid or expired state")),
        }
    };

    let redirect_uri = format!("{}/auth/{}/callback", state.base_url, provider.as_str());
    let client = providers::build_client(provider, cfg, &redirect_uri)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "bad provider config"))?;

    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            tracing::warn!("token exchange failed: {e}");
            err(StatusCode::BAD_GATEWAY, "token exchange failed")
        })?;

    let identity = providers::fetch_identity(&state.http, provider, token.access_token().secret())
        .await
        .map_err(|e| {
            tracing::warn!("{e}");
            err(StatusCode::BAD_GATEWAY, "failed to fetch user identity")
        })?;

    let is_admin = identity
        .email
        .as_deref()
        .map(|e| state.admin_emails.contains(e))
        .unwrap_or(false);

    let session_token = random_token();
    {
        let conn = state.db.lock().expect("db lock poisoned");
        let user = db::upsert_user(
            &conn,
            provider.as_str(),
            &identity.subject,
            identity.email.as_deref(),
            identity.name.as_deref(),
            is_admin,
        )
        .map_err(|e| {
            tracing::error!("db upsert failed: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "database error")
        })?;
        db::create_session(&conn, user.id, &session_token).map_err(|e| {
            tracing::error!("session create failed: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "database error")
        })?;
        tracing::info!(
            "login ok: user={} provider={} admin={}",
            user.email.as_deref().unwrap_or("?"),
            provider.as_str(),
            user.is_admin
        );
    }

    let mut cookie = Cookie::build((SESSION_COOKIE, session_token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(state.cookie_secure)
        .max_age(time::Duration::seconds(db::SESSION_TTL_SECS));
    if let Some(domain) = &state.cookie_domain {
        cookie = cookie.domain(domain.clone());
    }

    let dest = return_to.unwrap_or_else(|| "/admin".to_string());
    Ok((jar.add(cookie.build()), Redirect::to(&dest)))
}

fn current_user(state: &AppState, jar: &CookieJar) -> Option<db::User> {
    let token = jar.get(SESSION_COOKIE)?.value().to_string();
    let conn = state.db.lock().expect("db lock poisoned");
    db::user_for_token(&conn, &token).ok().flatten()
}

/// Identity of the current session as JSON, for browser/SPA clients that can't
/// see ForwardAuth headers (e.g. a WASM single-page app served on the same
/// origin). Always 200; `authenticated` is false when there is no valid session
/// so clients can branch without treating "logged out" as an error.
///
/// Same-origin only: the shim sets no CORS headers, so deploy SPA clients
/// behind the same domain (the session cookie rides along automatically).
#[derive(Serialize)]
struct WhoAmI {
    authenticated: bool,
    email: Option<String>,
    name: Option<String>,
    provider: Option<String>,
    is_admin: bool,
}

async fn whoami(State(state): State<Shared>, jar: CookieJar) -> Response {
    let body = match current_user(&state, &jar) {
        Some(u) => WhoAmI {
            authenticated: true,
            email: u.email,
            name: u.name,
            provider: Some(u.provider),
            is_admin: u.is_admin,
        },
        None => WhoAmI {
            authenticated: false,
            email: None,
            name: None,
            provider: None,
            is_admin: false,
        },
    };
    (
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(body),
    )
        .into_response()
}

/// ForwardAuth endpoint for Traefik / nginx auth_request.
///
/// 200 + X-Auth-User / X-Auth-Name / X-Auth-Provider when authorized;
/// 303 redirect into the login flow (preserving the original URL via
/// X-Forwarded-* headers) when not logged in; 403 when logged in but not
/// permitted.
async fn verify(State(state): State<Shared>, headers: HeaderMap, jar: CookieJar) -> Response {
    match current_user(&state, &jar) {
        Some(u) if !state.verify_requires_admin || u.is_admin => {
            let mut resp = StatusCode::OK.into_response();
            let h = resp.headers_mut();
            if let Some(email) = u.email.as_deref() {
                if let Ok(v) = email.parse() {
                    h.insert("X-Auth-User", v);
                }
            }
            if let Some(name) = u.name.as_deref() {
                if let Ok(v) = name.parse() {
                    h.insert("X-Auth-Name", v);
                }
            }
            if let Ok(v) = u.provider.parse() {
                h.insert("X-Auth-Provider", v);
            }
            resp
        }
        Some(_) => err(StatusCode::FORBIDDEN, "not permitted"),
        None => {
            // Rebuild the URL the user originally requested so we can send
            // them back after login.
            let hv = |n: &str| {
                headers
                    .get(n)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let original = match (hv("x-forwarded-proto"), hv("x-forwarded-host")) {
                (Some(proto), Some(host)) => Some(format!(
                    "{proto}://{host}{}",
                    hv("x-forwarded-uri").unwrap_or_else(|| "/".to_string())
                )),
                _ => None,
            };
            let rd = original
                .as_deref()
                .and_then(|r| validate_return_to(&state, r))
                .map(|r| format!("?rd={}", urlencode(&r)))
                .unwrap_or_default();
            Redirect::to(&format!("{}/{rd}", state.base_url)).into_response()
        }
    }
}

async fn admin(State(state): State<Shared>, jar: CookieJar) -> Response {
    match current_user(&state, &jar) {
        None => Redirect::to("/").into_response(),
        Some(u) if !u.is_admin => err(StatusCode::FORBIDDEN, "not an admin"),
        Some(u) => Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>admin</title>\
             <body style=\"font-family:sans-serif;max-width:32rem;margin:4rem auto\">\
             <h1>Admin</h1><p>Hello, <b>{}</b>. You are an admin (via {}).</p>\
             <p><a href=\"/\">Home</a></p></body>",
            html_escape(u.name.as_deref().unwrap_or("admin")),
            html_escape(&u.provider),
        ))
        .into_response(),
    }
}

async fn logout(State(state): State<Shared>, jar: CookieJar) -> (CookieJar, Redirect) {
    if let Some(c) = jar.get(SESSION_COOKIE) {
        let token = c.value().to_string();
        let conn = state.db.lock().expect("db lock poisoned");
        let _ = db::delete_session(&conn, &token);
    }
    let mut removal = Cookie::build((SESSION_COOKIE, "")).path("/");
    if let Some(domain) = &state.cookie_domain {
        removal = removal.domain(domain.clone());
    }
    (jar.remove(removal.build()), Redirect::to("/"))
}

fn err(status: StatusCode, msg: &'static str) -> Response {
    (status, msg).into_response()
}
