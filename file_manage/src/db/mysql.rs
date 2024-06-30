use axum::Extension;
use dotenv::dotenv;
use lazy_static::lazy_static;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::pool::PoolOptions;
use sqlx::{MySql, MySqlPool, Pool};


// 应用状态结构体 这里我不太明白
// pub struct AppState {
//     db_pool: Arc<MySqlPoolOptions>,
// }

// impl AppState {
//     pub fn new(db_pool: Arc<MySqlPoolOptions>) -> Self {
//         AppState { db_pool }
//     }
// }

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

// pub async fn arc_pool(pool :MySqlPoolOptions) -> Arc<MySqlPoolOptions> {
//     Arc::new(pool)
// }
