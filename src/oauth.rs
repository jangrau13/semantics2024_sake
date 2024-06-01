use std::collections::HashMap;
use std::sync::Arc;
use axum::{
    extract::{FromRequest, FromRequestParts, Query, Request, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Extension,
};
use axum::extract::Host;
use axum::middleware::Next;
use axum::response::Response;
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar};
use base64::Engine;
use base64::engine::general_purpose;
use chrono::{Duration, Local};
use oauth2::{basic::BasicClient, reqwest::async_http_client, AuthorizationCode, TokenResponse};
use serde::Deserialize;
use shuttle_runtime::__internals::serde_json::{from_str, Value};
use time::Duration as TimeDuration;

use crate::errors::ApiError;
use crate::AppState;
use crate::decrypter::{decrypt, encrypt};


#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
}

pub async fn wiser_callback(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(query): Query<AuthRequest>,
    Extension(oauth_client): Extension<BasicClient>,
) -> Result<impl IntoResponse, ApiError> {
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code))
        .request_async(async_http_client)
        .await
        .unwrap();

    let profile_response = state
        .ctx
        .get("https://auth.wiser.ehealth.hevs.ch/realms/wiser/protocol/openid-connect/userinfo")
        .bearer_auth(token.access_token().secret().to_owned())
        .send()
        .await
        .unwrap();

    let profile_json = profile_response.text().await.unwrap();

    let _profile_map: HashMap<String, Value> = from_str(&profile_json).unwrap();

    let profile: UserProfile = from_str(&profile_json).unwrap();

    //let plaintext = general_purpose::STANDARD.decode(profile.atomic_key.unwrap().clone()).unwrap();
    //let atomic_nonce = general_purpose::STANDARD.decode(profile.atomic_nonce.unwrap().clone()).unwrap();
    //let wiser_key = state.wiser_key;

    //let correct_result = "G3u3xjPMjecRCQ6eE/TBw8UKaKqUZDbFb0pndU30Bw8=";

    //let mut bytes = wiser_key.as_bytes().to_vec();

    // Pad with zero bytes if necessary
    //if bytes.len() < 32 {
    //println!("filling up the key, because the key is of length: {}", bytes.len());
    //bytes.resize(32, 0);
    //}

    // Ensure the bytes array is exactly 32 bytes
    //let first_32_bytes: [u8; 32] = bytes[..32].try_into().expect("slice with incorrect length");

    // Decrypt the ciphertext
    //let decrypted_text = decrypt(&first_32_bytes, &plaintext, &atomic_nonce.try_into().expect("invalid nonce length"));
    //println!("Decrypted text: {}", decrypted_text);
    //println!("Correct result: {}", correct_result);
    //dbg!(&profile);

    let Some(secs) = token.expires_in() else {
        return Err(ApiError::OptionError);
    };

    let secs: i64 = secs.as_secs().try_into().unwrap();

    let max_age = Local::now().naive_local() + Duration::try_seconds(secs).unwrap();
    let token_string = token.access_token().secret().to_owned();
    //println!("token: {}", &token_string);
    let cookie = Cookie::build(("sid", token_string))
        .path("/")
        .secure(true)
        .http_only(true)
        .max_age(TimeDuration::seconds(secs));

    sqlx::query("INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO NOTHING")
        .bind(profile.email.clone())
        .execute(&state.db)
        .await.unwrap();

    sqlx::query(
        "INSERT INTO sessions (user_id, session_id, expires_at) VALUES (
        (SELECT ID FROM USERS WHERE email = $1 LIMIT 1),
         $2, $3)
        ON CONFLICT (user_id) DO UPDATE SET
        session_id = excluded.session_id,
        expires_at = excluded.expires_at",
    )
        .bind(profile.email)
        .bind(token.access_token().secret().to_owned())
        .bind(max_age)
        .execute(&state.db)
        .await.unwrap();

    Ok((jar.add(cookie), Redirect::to("/v1/api/pdf/ghg")))
}

#[derive(Debug, Deserialize, Clone)]
pub struct UserProfile {
    email: String,
    preferred_username: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    atomic_agent: Option<String>,
    atomic_key: Option<String>,
    atomic_nonce: Option<String>,
}

pub async fn check_authenticated(
    Host(host): Host,
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let is_localhost = host.starts_with("localhost") || host.starts_with("127.0.0.1");
    if (is_localhost) {
        Ok(next.run(request).await)
    } else {
        // Extract the session ID cookie
        if let Some(cookie) = jar.get("sid") {
            // Validate the session ID against the database
            let email: Option<String> = sqlx::query_scalar(
                "SELECT
                    users.email
                FROM sessions
                LEFT JOIN users ON sessions.user_id = users.id
                WHERE sessions.session_id = $1
                LIMIT 1",
            )
                .bind(cookie.value())
                .fetch_optional(&state.db)
                .await
                .map_err(|_| ApiError::Unauthorized)?;

            // If a valid session is found, proceed to the next middleware/handler
            if let Some(email) = email {
                request.extensions_mut().insert(UserProfile {
                    email,
                    preferred_username: None,
                    given_name: None,
                    family_name: None,
                    atomic_agent: None,
                    atomic_key: None,
                    atomic_nonce: None,
                });
                return Ok(next.run(request).await);
            }
        }

        // If no valid session is found, return an unauthorized error
        Err(ApiError::Unauthorized)
    }
}

#[axum::async_trait]
impl FromRequest<AppState> for UserProfile {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let state = state.to_owned();

        let (mut parts, _body) = req.into_parts();

        let cookiejar: PrivateCookieJar =
            PrivateCookieJar::from_request_parts(&mut parts, &state).await.unwrap();

        let Some(cookie) = cookiejar.get("sid").map(|cookie| cookie.value().to_owned()) else {
            return Err(ApiError::Unauthorized);
        };

        let email: String = sqlx::query_scalar(
            "SELECT
                    users.email
                FROM sessions
                LEFT JOIN users ON sessions.user_id = users.id
                WHERE sessions.session_id = $1
                LIMIT 1",
        )
            .bind(cookie)
            .fetch_one(&state.db)
            .await.unwrap();

        Ok(Self { email, preferred_username: None, given_name: None, family_name: None, atomic_agent: None, atomic_key: None, atomic_nonce: None })
    }
}

pub async fn protected(profile: UserProfile) -> impl IntoResponse {
    return (StatusCode::OK, profile.email);
}
