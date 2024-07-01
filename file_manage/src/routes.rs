use axum::{
    routing::{get, post},
    Router,
};
use sqlx::{MySql, Pool};
use tower_http::trace::TraceLayer;

use crate::entity_operations::user::{t_users::get_user_by_id, user_request::{add_user, get_user_only}};
use crate::models::add;

pub fn app(pool: Pool<MySql>) -> Router {
    let app = Router::new()
        .route("/hello", get(|| async { "Hello, World!" }))
        .route("/", get(root))
        .route("/foo", get(get_foo).post(post_foo))
        .route("/foo/bar", get(foo_bar))
        .route("/add", get(add))
        .route("/user", post(add_user))
        .route("/user/:id", get(get_user_only))
        // .layer(TraceLayer::new_for_http())
        .with_state(pool);
    app
}

async fn root() {}
async fn get_foo() {}
async fn post_foo() {}
async fn foo_bar() {}
