use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use sqlx::{MySql, Pool};

use crate::entity_operations::jwt;
use crate::entity_operations::user::user_request::{add_user, get_user_only};
use crate::models::add;

pub fn app(pool: Pool<MySql>) -> Router {
    let app = Router::new()
        .route("/signin", post(jwt::sign_in))
        // .route("/hello", get(jwt::hello))
        .route("/", get(root))
        .route("/foo", get(get_foo).post(post_foo))
        .route("/foo/bar", get(foo_bar))
        .route("/add", get(add))
        .route("/user", post(add_user))
        .route(
            "/user/:id",
            get(get_user_only).layer(middleware::from_fn(jwt::authorization_middleware))
        ).with_state(pool);
    app
}

async fn root() {}
async fn get_foo() {}
async fn post_foo() {}
async fn foo_bar() {}
