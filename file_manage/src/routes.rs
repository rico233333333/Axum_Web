use std::sync::Arc;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use sqlx::{MySql, Pool};

use crate::entity_operations::jwt::{authorization_middleware, sign_in};
use crate::entity_operations::user::user_request::{add_user, get_user_only};
use crate::models::add;

#[derive(Clone, Debug)]
pub struct DBPool {
    pub pool: Pool<MySql>,
}

pub async fn app(db_pool: Pool<MySql>) -> Router {
    // 实例化数据库共享连接池
    let pool = Arc::new(DBPool { pool: db_pool });
    let app1 = Router::new()
        // .route("/signin", post(sign_in))
        .route("/", get(root))
        .route("/foo", get(get_foo).post(post_foo))
        .route("/foo/bar", get(foo_bar))
        .route("/add", get(add))
        .route("/user", post(add_user))
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

async fn root() {}
async fn get_foo() {}
async fn post_foo() {}
async fn foo_bar() {}
