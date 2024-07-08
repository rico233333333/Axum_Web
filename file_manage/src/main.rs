use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
// 路由模块
use file_manage::routes::app;
// pub mod db;
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
