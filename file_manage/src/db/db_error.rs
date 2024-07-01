use axum::http::StatusCode;
use sqlx::Error;

pub struct DBError {
    pub status_code : StatusCode,
    pub err_mssage : Error,
}



pub async fn error() {
    
}