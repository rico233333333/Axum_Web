use std::fmt;

use axum::{
    body::Body,
    extract::{Json, Request, State},
    http::{self, Response, StatusCode},
    middleware::Next,
    response::{self, IntoResponse},
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use serde_json::{json};
use sqlx::{MySql, Pool};

use super::user::{t_users::get_user_by_email, User};

// 定义一个用于在 JWT 令牌中保存声明数据的结构
#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize,    // 令牌的过期时间
    pub iat: usize,    // 令牌签发时间
    pub email: String, // 与令牌关联的电子邮件
}

// Define a structure for holding sign-in data
#[derive(Deserialize, Debug)]
pub struct SignInData {
    pub email: String,    // Email entered during sign-in
    pub password: String, // Password entered during sign-in
}

// 登录接口
pub async fn sign_in(
    state: State<Pool<MySql>>,
    Json(user_data): Json<SignInData>, // JSON payload containing sign-in data
) -> Result<Json<String>, StatusCode> {
    println!("{:?}", user_data);

    let user = match retrieve_user_by_email(state ,&user_data.email).await {
        Some(user) => user, // User found, proceed with authentication
        None => return Err(StatusCode::UNAUTHORIZED), // User not found, return unauthorized status
    };

    // Verify the password provided against the stored hash
    if !verify_password(&user_data.password, &user.password).await
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

#[derive(Clone, Debug)]
pub struct CurrentUser {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password_hash: String,
}

#[derive(Debug)]
enum JwtError {
    RequestHeaderError,         // 请求头错误
    JwtTokenNotProvided,        // 未携带JwtToken
    JwtTokenSignatureIsInvalid, // JwtToken签名无效
    UserIsNotAuthorized,        // 用户未授权
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            JwtError::RequestHeaderError => write!(f, "请求头错误"),
            JwtError::JwtTokenNotProvided => write!(f, "请求头中未携带JwtToken"),
            JwtError::JwtTokenSignatureIsInvalid => write!(f, "JwtToken签名无效"),
            JwtError::UserIsNotAuthorized => write!(f, "用户未授权"),
        }
    }
}

impl Serialize for JwtError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("JwtError", 0)?;
        let _ = match *self {
            JwtError::RequestHeaderError => {
                state.serialize_field("error", &format!("{}", JwtError::RequestHeaderError))
            }
            JwtError::JwtTokenNotProvided => {
                state.serialize_field("error", &format!("{}", JwtError::JwtTokenNotProvided))
            }
            JwtError::JwtTokenSignatureIsInvalid => state.serialize_field(
                "error",
                &format!("{}", JwtError::JwtTokenSignatureIsInvalid),
            ),
            JwtError::UserIsNotAuthorized => {
                state.serialize_field("error", &format!("{}", JwtError::UserIsNotAuthorized))
            }
        };
        state.end()
    }
}

#[derive(Debug)]
pub struct AuthError {
    pub error_type: JwtError,
    pub message: String,
    status_code: StatusCode,
}

impl AuthError {
    fn new(message: &str, status_code: StatusCode, error_type: JwtError) -> AuthError {
        AuthError {
            message: message.to_string(),
            status_code: status_code,
            error_type: error_type,
        }
    }
}

// 这里得实现IntoResponse特征 不明白的可以看看Axum文档
impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        // 创建一个 JSON 对象，包含错误信息和状态码
        let error_json = json!({
            "error_type": format!("{}", self.error_type),
            "error_message": self.message,
        });

        // 创建一个 HTTP 响应，设置状态码和主体
        let mut res = axum::response::Response::new(Body::from(error_json.to_string()));
        *res.status_mut() = self.status_code;

        res
    }
}

// 邮箱验证
async fn retrieve_user_by_email(state: State<Pool<MySql>>, email: &str) -> Option<User> {
    let user = get_user_by_email(state, email.to_string());
    Some(user)
}
// 密码验证
async fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
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
    mut req: Request<Body>,
    next: Next,
    state: State<Pool<MySql>>,
) -> Result<Response<Body>, AuthError> {
    let auth_header = req.headers().get(http::header::AUTHORIZATION);

    // 检查是否存在 Authorization 头，以及它是否不为空
    let auth_header_str = auth_header.and_then(|h| h.to_str().ok())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| AuthError::new(
            "请求头中缺少 Authorization 或其内容为空",
            StatusCode::FORBIDDEN,
            JwtError::JwtTokenNotProvided,
        ))?;

    // 解析 "Bearer [token]" 格式
    let parts: Vec<&str> = auth_header_str.splitn(2, ' ').collect();
    if parts.len() != 2 || parts[0].to_ascii_lowercase() != "bearer" {
        return Err(AuthError::new(
            "请求头中的 Authorization 必须以 'Bearer ' 开头",
            StatusCode::FORBIDDEN,
            JwtError::RequestHeaderError,
        ));
    }
    let token = parts[1].trim();

    // 这里添加你的 JWT 解码和验证逻辑...
    // 例如:
    let token_data = decode_jwt(token.to_string())
        .map_err(|_| AuthError::new(
            "Jwt Token 签名无效",
            StatusCode::UNAUTHORIZED,
            JwtError::JwtTokenSignatureIsInvalid,
        ))?;

    // 验证 JWT 令牌后，获取当前用户...
    let current_user = retrieve_user_by_email(state, &token_data.claims.email).await
        .ok_or_else(|| AuthError::new(
            "用户未授权",
            StatusCode::UNAUTHORIZED,
            JwtError::UserIsNotAuthorized,
        ))?;

    // 将用户信息添加到请求扩展中
    req.extensions_mut().insert(current_user);

    // 继续执行请求链
    Ok(next.run(req).await)
}
