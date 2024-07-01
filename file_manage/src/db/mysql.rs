use dotenv::dotenv;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{MySql, Pool};


pub async fn init_db_pool() -> Pool<MySql> {
    dotenv().ok().expect("环境加载失败！！！");
    let database_url = std::env::var("DATABASE_URL").expect("数据库连接失败！！！");
    let pool = MySqlPoolOptions::new()
        .max_connections(20)
        .connect(&database_url)
        .await
        .expect("池创建失败！！！");
    pool
}
