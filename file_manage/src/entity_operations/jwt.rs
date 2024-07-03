use axum::{
    body::Body,
    extract::{Json, Request},
    http,
    http::{Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
// Define a structure for holding claims data used in JWT tokens
pub struct Claims {
    pub exp: usize,    // Expiry time of the token
    pub iat: usize,    // Issued at time of the token
    pub email: String, // Email associated with the token
}

// Define a structure for holding sign-in data
#[derive(Deserialize, Debug)]
pub struct SignInData {
    pub email: String,    // Email entered during sign-in
    pub password: String, // Password entered during sign-in
}

pub async fn sign_in(
    Json(user_data): Json<SignInData>, // JSON payload containing sign-in data
) -> Result<Json<String>, StatusCode> {
    println!("{:?}", user_data);

    let user = match retrieve_user_by_email(&user_data.email) {
        Some(user) => user, // User found, proceed with authentication
        None => return Err(StatusCode::UNAUTHORIZED), // User not found, return unauthorized status
    };

    // Verify the password provided against the stored hash
    if !verify_password(&user_data.password, &user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    // Handle bcrypt errors
    {
        return Err(StatusCode::UNAUTHORIZED); // Password verification failed, return unauthorized status
    }

    // Generate a JWT token for the authenticated user
    let token = encode_jwt(user.email).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?; // Handle JWT encoding errors

    // Return the token as a JSON-wrapped string
    Ok(Json(token))
}

#[derive(Clone)]
pub struct CurrentUser {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password_hash: String,
}

pub struct AuthError {
    pub message: String,
    status_code: StatusCode,
}

impl AuthError {
    fn new(message: &str, status_code: StatusCode) -> AuthError {
        AuthError {
            message: message.to_string(),
            status_code,
        }
    }
}

// 这里得实现IntoResponse特征 不明白的可以看看Axum文档
impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let mut res = Response::new(Body::from(self.message));
        *res.status_mut() = self.status_code;
        res
    }
}
// Function to simulate retrieving user data from a database based on email
fn retrieve_user_by_email(email: &str) -> Option<CurrentUser> {
    // For demonstration purposes, a hardcoded user is returned based on the provided email
    let current_user: CurrentUser = CurrentUser {
        email: "myemail@gmail.com".to_string(),
        first_name: "Eze".to_string(),
        last_name: "Sunday".to_string(),
        password_hash: "$2b$12$Gwf0uvxH3L7JLfo0CC/NCOoijK2vQ/wbgP.LeNup8vj6gg31IiFkm".to_string(),
    };
    Some(current_user) // Return the hardcoded user
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    let hash = hash(password, DEFAULT_COST)?;
    Ok(hash)
}

pub fn encode_jwt(email: String) -> Result<String, StatusCode> {
    let secret: String = "randomStringTypicallyFromEnv".to_string();
    let now = Utc::now();
    let expire: chrono::TimeDelta = Duration::hours(24);
    let exp: usize = (now + expire).timestamp() as usize;
    let iat: usize = now.timestamp() as usize;
    let claim = Claims { iat, exp, email };

    encode(
        &Header::default(),
        &claim,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub fn decode_jwt(jwt_token: String) -> Result<TokenData<Claims>, StatusCode> {
    let secret = "randomStringTypicallyFromEnv".to_string();
    let result: Result<TokenData<Claims>, StatusCode> = decode(
        &jwt_token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    result
}

pub async fn authorization_middleware(
    mut req: Request,
    next: Next,
) -> Result<Response<Body>, AuthError> {
    let auth_header = req.headers_mut().get(http::header::AUTHORIZATION);
    let auth_header = match auth_header {
        Some(header) => header.to_str().map_err(|_| AuthError {
            message: "Empty header is not allowed".to_string(),
            status_code: StatusCode::FORBIDDEN,
        })?,
        None => {
            return Err(AuthError {
                message: "Please add the JWT token to the header".to_string(),
                status_code: StatusCode::FORBIDDEN,
            })
        }
    };
    let mut header = auth_header.split_whitespace();
    let (bearer, token) = (header.next(), header.next());
    let token_data = match decode_jwt(token.unwrap().to_string()) {
        Ok(data) => data,
        Err(_) => {
            return Err(AuthError {
                message: "Unable to decode token".to_string(),
                status_code: StatusCode::UNAUTHORIZED,
            })
        }
    };
    // Fetch the user details from the database
    let current_user = match retrieve_user_by_email(&token_data.claims.email) {
        Some(user) => user,
        None => {
            return Err(AuthError {
                message: "You are not an authorized user".to_string(),
                status_code: StatusCode::UNAUTHORIZED,
            })
        }
    };
    req.extensions_mut().insert(current_user);
    Ok(next.run(req).await)
}
