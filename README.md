# Axum_Web

对于RustWeb开发的一个自学的小案例 具体想映射本地系统到公网 让用户可以快捷操作。

后端选择了RUST Axum框架。

前段Vue3 慢慢开发了 不着急了。

想着尽善尽美 对于后端把里面的东西都封装的差不多 然后搞一个文档 WEB开发的核心就那么多 不需要文件功能的直接删除文件部分的东西就可以了。至于前端我也想的是这样做 但是得等到后端的基本上都封装完了。

# 1. 模块说明

## 1.1 main.rs

程序主入口文件 调用db模块 创建数据库连接池 使用axum状态共享 共享数据库连接池等。

状态共享不懂不理解的话 可以去官网或者百度搜一搜Axum状态共享的三种方式。

```rust
use axum::{
    routing::{get, post},
    Router,
    http::{header::HeaderMap,request::Parts, StatusCode},
};
use axum::extract::{Path, Query, Json};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::time::Duration;
use std::collections::HashMap;

// 路由模块
use file_manage::routes::app;
// pub mod db;
use file_manage::db::mysql::{
    init_db_pool,
    // arc_pool,
};

#[tokio::main]
async fn main() {
    // 数据库服务
    let db_pool = init_db_pool().await;
  
    // 开启服务
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app(db_pool)).await.unwrap();
}
```

## 1.2 lib.rs

方便create

下面的models模块只是为了测试 可以删掉的

```rust
pub mod entity_operations;
pub mod db;
pub mod routes;

pub mod models {
    use crate::entity_operations::user;
    pub async fn add() {
        let user = user::User{
            id: 1i64,
            name: String::from("我叫我也不知道"),
            password: String::from("qw@13579"),
            is_superuser: true,
            user_level : 1i32,
        };
        println!("测试用户：\n{}", user);
    }
}
```

## 1.3 routes.rs 路由模块

拆分路由把路由整合到函数中

```rust
pub fn app(pool: Pool<MySql>) -> Router {
    let app = Router::new().route("/hello", get(|| async { "Hello, World!" }))
        .route("/", get(root))
        .route("/foo", get(get_foo).post(post_foo))
        .route("/foo/bar", get(foo_bar))
        // .route("/path/:user_id", get(path)) // Path提取器
        // .route("/query", post(query))
        // .route("/string", post(string))
        .route("/add", get(add))
        .route("/user", post(add_user))
        .route("/user/:id", get(get_user_by_id))
        .with_state(pool);
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
pub mod user;
```

### 1.5.2 user.rs

```rust
use sqlx::FromRow;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(FromRow)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub password: String,
    pub is_superuser: bool,
    pub user_level: i32,
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "id: {}\nname:{}\npassword: {}\nis_superuser: {}\nuser_level: {}",
            self.id, self.name, self.password, self.is_superuser, self.user_level
        )
    }
}

impl User {
    pub fn new(name: String, password: String, is_superuser: bool, user_level: i32) -> Self {
        User {
            id: 111111i64,
            name: name,
            password: format!("加密后：{}", password),
            is_superuser: is_superuser,
            user_level: user_level,
        }
    }
}

pub mod user_request {
    use axum::extract::{Json, Path, Query};
    use serde_json::{json, Value};
    use sqlx::{FromRow, MySqlConnection, Result};
    use std::collections::HashMap;
    // use crate::entity_operations::user::t_user::get_user_by_id;

    pub async fn add_user(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
        // let data = get_user_by_id(&mut MySqlConnection, 1u64).await.expect("数据查询失败！！！");

        println!("{:?}", params.get("name"));
        Json(json!({"id": 1212}))
    }
}

pub mod t_user {
    use crate::entity_operations::user::User;
    use axum::extract::{Json, Path, Query, State};
    use axum::http::{Error, StatusCode};
    use sqlx::{query, FromRow, MySql, MySqlConnection, Pool, Result};

    // pub struct Return_http {
    //     code : 
    // }

    pub async fn get_user_by_id(
        state: State<Pool<MySql>>,
        Path(id): Path<i64>,
    ) -> () {
        let user = sqlx::query_as::<_, User>("SELECT * FROM t_users WHERE id = ?")
            .bind(id)
            .fetch_one(&*state)
            .await;
        match user {
            Ok(user) => {
                println!("{}", user);
                // Ok(user);
                ()
        
            }
            Err(err) => {
                println!("{}", err);
                // Err(format!("数据库错误{}", err));
                ()
            }
        }
    }
}

```
