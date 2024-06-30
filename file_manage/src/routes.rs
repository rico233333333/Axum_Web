use axum::{
    routing::{get, post},
    Router,
    Json,
    http::{header::HeaderMap,request::Parts, StatusCode},
};
use sqlx::{MySql, Pool};

use crate::entity_operations::user::{t_user::get_user_by_id, user_request::add_user};
use crate::models::add;

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


async fn root() {}
async fn get_foo() {}
async fn post_foo() {}
async fn foo_bar() {}
// async fn path(Path(user_id): Path<u32>) -> Json<Value> {
//     println!("{:?}", user_id);
//     Json(json!({ "data": user_id }))
// }
// // 提取query
// async fn query(headers: HeaderMap, Query(params): Query<HashMap<String, String>>) -> Json<Value> {
//     println!("{:?}", params.get("id"));
//     println!("{:?}", headers);
//     Json(json!({"id": params.get("id")}))
// }
// // 提取body
// async fn string(body: String) -> Json<Value>{
//     println!("{}", body);
//     Json(json!({"id": 121212}))
// }

// async fn query(Query(params): Query<HashMap<String, String>>) {}
// async fn json(Json(payload): Json<serde_json::Value>) {}
