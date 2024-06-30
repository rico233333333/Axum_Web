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