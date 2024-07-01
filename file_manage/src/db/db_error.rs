/// 对sqlx错误和axum状态码做了一个简单的封装
use axum::http::StatusCode;
use sqlx::Error;
use std::fmt;
use std::fmt::{Display, Formatter};

pub struct DBError {
    pub status_code: StatusCode,
    pub err_mssage: String,
}


impl Display for DBError {
    /// 实现了Display特征 方便打印查看
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "status_code: {}\nerr_mssage: {}",
            self.status_code, self.err_mssage
        )
    }
}

impl DBError {
    pub fn new(status_code: StatusCode, err_mssage: String) -> Self {
        DBError {
            status_code,
            err_mssage,
        }
    }
}

pub async fn error(err: Error) -> DBError {
    match err {
        Configuration => {
            DBError::new(
                StatusCode::INTERNAL_SERVER_ERROR, 
                String::from("解析连接字符串时发生错误。")
            )
        }
        Database => {
            DBError::new(
                StatusCode::INTERNAL_SERVER_ERROR, 
                String::from("解析连接字符串时发生错误。")
            )
        }
        Configuration => {
            DBError::new(
                StatusCode::INTERNAL_SERVER_ERROR, 
                String::from("解析连接字符串时发生错误。")
            )
        }
        Configuration => {
            DBError::new(
                StatusCode::INTERNAL_SERVER_ERROR, 
                String::from("解析连接字符串时发生错误。")
            )
        }
        Configuration => {
            DBError::new(
                StatusCode::INTERNAL_SERVER_ERROR, 
                String::from("解析连接字符串时发生错误。")
            )
        }
        Configuration => {
            DBError::new(
                StatusCode::INTERNAL_SERVER_ERROR, 
                String::from("解析连接字符串时发生错误。")
            )
        }
        Configuration => {
            DBError::new(
                StatusCode::INTERNAL_SERVER_ERROR, 
                String::from("解析连接字符串时发生错误。")
            )
        }
        Configuration => {
            DBError::new(
                StatusCode::INTERNAL_SERVER_ERROR, 
                String::from("解析连接字符串时发生错误。")
            )
        }
        Configuration => {
            DBError::new(
                StatusCode::INTERNAL_SERVER_ERROR, 
                String::from("解析连接字符串时发生错误。")
            )
        }
    }
}
