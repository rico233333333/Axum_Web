![Hello Files]([https://github.com/rico233333333/Axum_Web/src/images/svg/logo.svg](https://github.com/rico233333333/Axum_Web/blob/main/file_manage/src/images/svg/logo.svg))
# Axum_Web 练手文件公网映射项目
简体中文|[English](README_EN.md)

对于RustWeb开发的一个自学的小案例 具体想映射本地文件到公网 让用户可以快捷操作。

后端选择了RUST Axum框架。

前端Vue3 慢慢开发了 不着急了。

[前端 -》 file-manage-vue](https://github.com/rico233333333/file-manage-vue/)

看到这里**喜欢❤️❤️❤️**或者**clone🗑️🗑️🗑️**了本仓库就点个**star⭐️⭐️⭐️**支持一下吧 

本仓库作者在闲暇之余会持续更新

---

# 1. 模块说明

## 1.1 main.rs

程序主入口文件 调用db模块 创建数据库连接池 使用axum状态共享 共享数据库连接池等。

状态共享不懂不理解的话 可以去官网或者百度搜一搜Axum状态共享的三种方式。

```rust
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use file_manage::routes::app;
use file_manage::db::mysql::init_db_pool;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "example_jwt=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    let pool = init_db_pool().await;
    // 开启服务
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app(pool).await).await.unwrap();
}

```

## 1.2 lib.rs

方便create

```rust
pub mod db;
pub mod entity_operations;
pub mod routes;

```

## 1.3 routes.rs 路由模块

拆分路由把路由整合到函数中

这里有个数据库连接池 需要建立数据库 **file_manage**

```sql
CREATE DATABASE file_manage;
```

这里还需要建立数据表 这里建立**主键自增**的表就好啦这样咱也好打理不是
```sql
use file_manage;

CREATE TABLE 't_users' (
  'id' bigint NOT NULL AUTO_INCREMENT,
  'name' varchar(255) NOT NULL,
  'password' varchar(255) NOT NULL,
  'is_superuser' tinyint(1) NOT NULL,
  'user_level' int NOT NULL,
  'email' varchar(255) NOT NULL,
  PRIMARY KEY ('id')
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
```
建立数据表**t_users**是不是还得插入数据呀 
这里的密码是经过加密的**password1**
```sql
INSERT INTO 't_users' ('name', 'password', 'is_superuser', 'user_level', 'email') VALUES ('Alice','$2b$12$vPpLleEkSK1yX9.qUAri9uYkJxnmrQduUmYSJxH8VTAhBnqcSwxd.', 1, 1, '1@qq.com');
```
至于密码是怎么验证的 可以在下方的**entity_operations**中找到
好吧 **因为我"善"** 所以我把代码摘抄出来了
```rust
// 密码验证函数
async fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

// hash密码不可逆加密
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    let hash = hash(password, DEFAULT_COST)?;
    Ok(hash)
}
```
---
下面才是正儿八经的**routes.rs**
可以看到这里写的有路由中间件、还有数据共享 哈哈 我在上班的时候学习的 是不是**狠狠的进步**了呀

至于怎么登录 我会在后面放置**ApiFox**截图
```rust
use std::sync::Arc;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use sqlx::{MySql, Pool};

use crate::entity_operations::jwt::{authorization_middleware, sign_in};
use crate::entity_operations::user::user_request::{add_user, get_user_only};

#[derive(Clone, Debug)]
pub struct DBPool {
    pub pool: Pool<MySql>,
}

pub async fn app(db_pool: Pool<MySql>) -> Router {
    // 实例化数据库共享连接池
    let pool = Arc::new(DBPool { pool: db_pool });
    let app1 = Router::new()
        .route("/signin", post(sign_in))
        .with_state(pool.clone());

    let app2 = Router::new()
        .route("/:id", get(get_user_only))
        .layer(middleware::from_fn_with_state(
            pool.clone(),
            authorization_middleware,
        ))
        .with_state(pool.clone());

    let app = Router::new().nest("/", app1).nest("/user", app2);
    app
}

```

## 1.4 db 模块

### 1.4.1 mod.rs

```rust
pub mod mysql;
```

### 1.4.2 mysql.rs

读取配置文件 链接mysql。

可以按照不同的数据库 去调用sqlx不同的数据库连接池的。

```rust
use axum::Extension;
use dotenv::dotenv;
use lazy_static::lazy_static;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::pool::PoolOptions;
use sqlx::{MySql, MySqlPool, Pool};


pub async fn init_db_pool() -> Pool<MySql> {
    dotenv().ok().expect("环境加载失败！！！");
    let database_url = std::env::var("DATABASE_URL").expect("数据库连接失败！！！");
    let pool = MySqlPoolOptions::new()
        .max_connections(20)
        .connect(&database_url)
        .await
        .expect("池创建失败");
    pool
}
```

## 1.5 entity_operations 模块 实体的声明与请求

按照模块化开发 应该把一个系统按照不同的功能分成不同的模块等 这样方便了程序员对于每个模块的维护 很适合团队开发以及个人开发。

### 1.5.1 mod.rs

```rust
pub mod user; // user实体操作模块
pub mod jwt;
pub mod errors;  
```

### 1.5.2 user.rs 用户实体操作以及用户服务

user 里面包含了user服务需要的数据库操作模块和user服务

用户查询

```rust
use serde::{Deserialize, Serialize}; // 结构体的序列化与反序列化
use sqlx::FromRow;
use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(FromRow, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub password: String,
    pub is_superuser: bool,
    pub user_level: i32,
    pub email: String
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "id: {}\nname: {}\npassword: {}\nis_superuser: {}\nuser_level: {}\nemail: {}",
            self.id, self.name, self.password, self.is_superuser, self.user_level, self.email
        )
    }
}

impl User {
    pub fn new(name: String, password: String, is_superuser: bool, user_level: i32, email: String) -> Self {
        User {
            id: 111111i64,
            name: name,
            password: format!("加密后：{}", password),
            is_superuser: is_superuser,
            user_level: user_level,
            email: email,
        }
    }
}

pub mod user_request {
    use crate::{entity_operations::user::t_users::get_user_by_id, routes::DBPool};
    use axum::{extract::{Json, Path, Query, State}, http::StatusCode, Extension};
    use serde_json::{json, Value};
    use std::{collections::HashMap, sync::Arc};

    pub async fn get_user_only(
        // Extension(currentUser): Extension<CurrentUser>,
        Path(id): Path<i64>,
        State(pool): State<Arc<DBPool>>,
    ) -> (StatusCode, Json<Value>) {
        // println!("传递过来的用户{:?}", currentUser);
        let data = get_user_by_id(pool.pool.clone(), id).await;
        // println!("data:{:?}", data);
        match data {
            Ok(user) => {
                (StatusCode::OK, Json(json!({"data": user})))
            }
            Err(err) => {
                (StatusCode::NOT_FOUND, Json(json!({"data": format!("{}", err)})))
            }
        }
    }

    pub async fn add_user(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
        // let data = get_user_by_id(&mut MySqlConnection, 1u64).await.expect("数据查询失败！！！");

        println!("{:?}", params.get("name"));
        Json(json!({"id": 1212}))
    }
}

pub mod t_users {
    /// 针对t_user表的操作模块
    /// 具体封装sql还是啥的有点不清楚
    use crate::entity_operations::user::User;
    use sqlx::Error as SqlxError;
    use sqlx::{query, FromRow, MySql, Pool, Result}; // 引入sqlx的错误类型

    pub async fn get_user_by_id(pool: Pool<MySql>, id: i64) -> Result<User, SqlxError> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM t_users WHERE id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await;
        match user {
            Ok(user) => Ok(user),
            Err(err) => {
                Err(err)
            }
        }
    }

    pub async fn get_user_by_email(pool: Pool<MySql>, email: String) -> Result<User, SqlxError> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM t_users WHERE id = ?")
            .bind(email)
            .fetch_one(&pool)
            .await;
        match user {
            Ok(user) => Ok(user),
            Err(err) => {
                Err(err)
            }
        }
    }
}

```

### 1.5.3 jwt.rs 用户JWT登录、JWT验证中间件

在这里我集成了JWT登录、JWT验证中间件的部分功能 害不太完善后续还需升级改造 不过这个写成一个模块 你们想拿去直接CV就好了  这里还有错误处理的一个示例哦

```rust
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

```

# 2. URL请求
下面使用**ApiFox**进行请求的一些示例啦 具体放置在第几章我还在观望 存在**BUG**请告诉我哦
首先**cd**到**file_manage**中
然后启动**Axum** 开启3000的端口 可以在**main.rs**中设置
```shell
cd file_manage
cargo run
```
## 2.1 登录以及JWT中间件验证
下面就是登录以及怎么使用JWT中间件进行用户身份识别的
### 2.1.1 登录
因为 我的登录接口获取的是前端传递给后台的Json字符串 也就是使用了```Json(user_data): Json<SignInData>,``` 所以这里不能以表单的形式把数据发送到后端的 是直接发送json
请求url
```
http://127.0.0.1:3000/signin
```
注意：使用ApiFox与PostMan的时候把**form-data**修改成**row**
#### 200
成功
```json
{
    "email": "1@qq.com",
    "password": "password1"
}
```
```json
{
    "data": {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MjA5MTg1NjYsImlhdCI6MTcyMDgzMjE2NiwiZW1haWwiOiIxQHFxLmNvbSJ9.pz52KFvAS7yseNku_F3BguSzQqgWZDBEKjpevTLSu-g",
        "userData": {
            "email": "1@qq.com",
            "id": 1,
            "is_superuser": true,
            "name": "Alice",
            "user_level": 1
        }
    }
}
```
#### 401 
密码错误或不存在
```json
{
    "email": "1@qq.com",
    "password": ""
}
```
```json
{
    "error_message": "请检查密码",
    "error_type": "密码错误"
}
```
#### 401
邮箱错误或不存在
```json
{
    "email": "",
    "password": "password1"
}
```
```json
{
    "error_message": "请检查登录邮箱",
    "error_type": "用户不存在"
}
```
#### 500
这里的500并不是代码错了 而是我数据库对于**2@qq.com** 用户的**password**没有进行加密导致的
```json
{
    "email": "2@qq.com",
    "password": "password1"
}
```
```json
{
    "error_message": "服务器错误",
    "error_type": "服务器错误"
}
```
### 2.1.2 中间件认证
下面就是一个从数据读取一个用户的案例 主要是为了凸显中间件 这里需要传递一个用户id
```
http://127.0.0.1:3000/user/{id}
http://127.0.0.1:3000/user/1
```
注意：携带token需要在**Headers**中 携带 **Authorization** **Bearer token** 这里bearer与token中需要一个空格
#### 200
成功
```json
{
    "data": {
        "email": "1@qq.com",
        "id": 1,
        "is_superuser": true,
        "name": "Alice",
        "password": "$2b$12$vPpLleEkSK1yX9.qUAri9uYkJxnmrQduUmYSJxH8VTAhBnqcSwxd.",
        "user_level": 1
    }
}
```
#### 401
Jwt Token过期
```json
{
    "error_message": "Jwt Token 签名无效",
    "error_type": "JwtToken签名无效"
}
```
