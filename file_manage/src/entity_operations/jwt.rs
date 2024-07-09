use std::{fmt, sync::Arc};

use crate::routes::DBPool;
use axum::{
    body::Body,
    extract::{Json, Request, State},
    http::{self, Response, StatusCode},
    middleware::Next,
    response::{self, IntoResponse},
    Extension,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{MySql, Pool};

use super::user::{t_users::get_user_by_email, User};

// 定义一个用于在 JWT 令牌中保存声明数据的结构
#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize,    // 令牌的过期时间
    pub iat: usize,    // 令牌签发时间
    pub email: String, // 与令牌关联的电子邮件
}

// 登录结构体
#[derive(Deserialize, Debug)]
pub struct SignInData {
    pub email: String,    // Email entered during sign-in
    pub password: String, // Password entered during sign-in
}

// 登录用户返回结构体
#[derive(Serialize, Debug)]
pub struct UserSerialize {
    pub id: i64,
    pub name: String,
    pub is_superuser: bool,
    pub user_level: i32,
    pub email: String,
}
// 登录注册返回结构体
#[derive(Serialize, Debug)]
pub struct UserTokenData {
    pub token: String,           // Email entered during sign-in
    pub userData: UserSerialize, // Password entered during sign-in
}

impl UserTokenData {
    pub fn new(
        token: String,
        id: i64,
        name: String,
        is_superuser: bool,
        user_level: i32,
        email: String,
    ) -> Self {
        UserTokenData {
            token: token,
            userData: UserSerialize {
                id: id,
                name: name,
                is_superuser: is_superuser,
                user_level: user_level,
                email: email,
            },
        }
    }
}

pub async fn sign_in(
    State(db_pool): State<Arc<DBPool>>,
    Json(user_data): Json<SignInData>, // JSON payload containing sign-in data
) -> Result<Json<Value>, AuthError> {
    let user = match retrieve_user_by_email(&db_pool.pool, &user_data.email).await {
        Some(user) => user,
        None => {
            return Err(AuthError::new(
                "请检查登录邮箱",
                StatusCode::UNAUTHORIZED,
                JwtError::TheUserDoesNotExist,
            ))
        }
    };
    // 密码认证
    if !verify_password(&user_data.password, &user.password)
        .await
        .map_err(|_| {
            AuthError::new(
                "服务器错误",
                StatusCode::INTERNAL_SERVER_ERROR,
                JwtError::ServerError,
            )
        })?
    {
        return Err(AuthError::new(
            "请检查密码",
            StatusCode::UNAUTHORIZED,
            JwtError::WrongPassword,
        ));
    }

    let token = encode_jwt(user.email.clone()).map_err(|_| {
        AuthError::new(
            "服务器错误",
            StatusCode::INTERNAL_SERVER_ERROR,
            JwtError::ServerError,
        )
    })?; // Handle JWT encoding errors
         // Return the token as a JSON-wrapped string
    let user_token = UserTokenData::new(
        token,
        user.id,
        user.name,
        user.is_superuser,
        user.user_level,
        user.email,
    );
    Ok(Json(json!({"data":user_token})))
}

// 注册暂时不想写
async fn register() {}

#[derive(Debug)]
pub enum JwtError {
    RequestHeaderError,         // 请求头错误
    JwtTokenNotProvided,        // 未携带JwtToken
    JwtTokenSignatureIsInvalid, // JwtToken签名无效
    UserIsNotAuthorized,        // 用户未授权
    WrongPassword,              // 密码错误
    TheUserDoesNotExist,        // 用户不存在
    ServerError,                // 服务器错误
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            JwtError::RequestHeaderError => write!(f, "请求头错误"),
            JwtError::JwtTokenNotProvided => write!(f, "请求头中未携带JwtToken"),
            JwtError::JwtTokenSignatureIsInvalid => write!(f, "JwtToken签名无效"),
            JwtError::UserIsNotAuthorized => write!(f, "用户未授权"),
            JwtError::WrongPassword => write!(f, "密码错误"),
            JwtError::TheUserDoesNotExist => write!(f, "用户不存在"),
            JwtError::ServerError => write!(f, "服务器错误"),
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
            JwtError::WrongPassword => {
                state.serialize_field("error", &format!("{}", JwtError::WrongPassword))
            }
            JwtError::TheUserDoesNotExist => {
                state.serialize_field("error", &format!("{}", JwtError::TheUserDoesNotExist))
            }
            JwtError::ServerError => {
                state.serialize_field("error", &format!("{}", JwtError::ServerError))
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
async fn retrieve_user_by_email(pool: &Pool<MySql>, email: &str) -> Option<User> {
    match get_user_by_email(pool.clone(), email.to_string()).await {
        Ok(user) => Some(user),
        Err(_) => None,
    }
}
// 密码验证
async fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

// hash密码不可逆加密
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
    State(pool): State<Arc<DBPool>>,
    mut req: Request,
    next: Next,
) -> Result<Response<Body>, AuthError> {
    let auth_header = req.headers().get(http::header::AUTHORIZATION);

    // 检查是否存在 Authorization 头，以及它是否不为空
    let auth_header_str = auth_header
        .and_then(|h: &http::HeaderValue| h.to_str().ok())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            AuthError::new(
                "请求头中缺少 Authorization 或其内容为空",
                StatusCode::FORBIDDEN,
                JwtError::JwtTokenNotProvided,
            )
        })?;

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

    let token_data = decode_jwt(token.to_string()).map_err(|_| {
        AuthError::new(
            "Jwt Token 签名无效",
            StatusCode::UNAUTHORIZED,
            JwtError::JwtTokenSignatureIsInvalid,
        )
    })?;

    // 验证 JWT 令牌后，获取当前用户...
    let current_user = retrieve_user_by_email(&pool.pool, &token_data.claims.email)
        .await
        .ok_or_else(|| {
            AuthError::new(
                "用户未授权",
                StatusCode::UNAUTHORIZED,
                JwtError::UserIsNotAuthorized,
            )
        })?;

    // 将用户信息添加到请求扩展中
    let insert = req.extensions_mut().insert(current_user);

    // 继续执行请求链
    Ok(next.run(req).await)
}
