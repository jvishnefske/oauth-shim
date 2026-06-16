//! SQLite persistence: users and sessions.
//!
//! Session tokens are never stored in plaintext — only their SHA-256 hash.

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SESSION_TTL_SECS: i64 = 8 * 60 * 60; // 8 hours

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub provider: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub is_admin: bool,
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}

pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY,
            provider   TEXT NOT NULL,
            subject    TEXT NOT NULL,
            email      TEXT,
            name       TEXT,
            is_admin   INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            last_login INTEGER NOT NULL,
            UNIQUE (provider, subject)
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);",
    )?;
    Ok(conn)
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Insert or update a user after a successful OAuth login. Returns the user row.
pub fn upsert_user(
    conn: &Connection,
    provider: &str,
    subject: &str,
    email: Option<&str>,
    name: Option<&str>,
    is_admin: bool,
) -> rusqlite::Result<User> {
    let t = now();
    conn.execute(
        "INSERT INTO users (provider, subject, email, name, is_admin, created_at, last_login)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT(provider, subject) DO UPDATE SET
            email = excluded.email,
            name = excluded.name,
            is_admin = excluded.is_admin,
            last_login = excluded.last_login",
        params![provider, subject, email, name, is_admin as i64, t],
    )?;
    let user = conn.query_row(
        "SELECT id, provider, email, name, is_admin FROM users WHERE provider = ?1 AND subject = ?2",
        params![provider, subject],
        |r| {
            Ok(User {
                id: r.get(0)?,
                provider: r.get(1)?,
                email: r.get(2)?,
                name: r.get(3)?,
                is_admin: r.get::<_, i64>(4)? != 0,
            })
        },
    )?;
    Ok(user)
}

/// Create a session for `user_id`; stores only the hash of `token`.
pub fn create_session(conn: &Connection, user_id: i64, token: &str) -> rusqlite::Result<()> {
    let t = now();
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![hash_token(token), user_id, t, t + SESSION_TTL_SECS],
    )?;
    // Opportunistic cleanup of expired sessions.
    conn.execute("DELETE FROM sessions WHERE expires_at < ?1", params![t])?;
    Ok(())
}

/// Resolve a session token to its user, if the session exists and is unexpired.
pub fn user_for_token(conn: &Connection, token: &str) -> rusqlite::Result<Option<User>> {
    conn.query_row(
        "SELECT u.id, u.provider, u.email, u.name, u.is_admin
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?1 AND s.expires_at >= ?2",
        params![hash_token(token), now()],
        |r| {
            Ok(User {
                id: r.get(0)?,
                provider: r.get(1)?,
                email: r.get(2)?,
                name: r.get(3)?,
                is_admin: r.get::<_, i64>(4)? != 0,
            })
        },
    )
    .optional()
}

pub fn delete_session(conn: &Connection, token: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM sessions WHERE token_hash = ?1",
        params![hash_token(token)],
    )?;
    Ok(())
}
