use serde::{Deserialize, Serialize}; // 结构体的序列化与反序列化
use sqlx::FromRow;
use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(FromRow, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub password: String,
    pub is_superuser: bool,
    pub user_level: i32,
    pub email: String
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "id: {}\nname: {}\npassword: {}\nis_superuser: {}\nuser_level: {}\nemail: {}",
            self.id, self.name, self.password, self.is_superuser, self.user_level, self.email
        )
    }
}

impl User {
    pub fn new(name: String, password: String, is_superuser: bool, user_level: i32, email: String) -> Self {
        User {
            id: 111111i64,
            name: name,
            password: format!("加密后：{}", password),
            is_superuser: is_superuser,
            user_level: user_level,
            email: email,
        }
    }
}

pub mod user_request {
    use crate::entity_operations::{jwt::CurrentUser, user::t_users::get_user_by_id};
    use axum::{extract::{Json, Path, Query, State}, http::StatusCode, Extension};
    use serde_json::{json, Value};
    use sqlx::{FromRow, MySql, MySqlConnection, Pool, Result};
    use std::collections::HashMap;

    pub async fn get_user_only(
        state: State<Pool<MySql>>,
        Extension(currentUser): Extension<CurrentUser>,
        Path(id): Path<i64>,
    ) -> (StatusCode, Json<Value>) {
        println!("传递过来的用户{:?}", currentUser);
        let data = get_user_by_id(state, id).await;
        // println!("data:{:?}", data);
        match data {
            Ok(user) => {
                (StatusCode::OK, Json(json!({"data": user})))
            }
            Err(err) => {
                (StatusCode::NOT_FOUND, Json(json!({"data": format!("{}", err)})))
            }
        }
    }

    pub async fn add_user(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
        // let data = get_user_by_id(&mut MySqlConnection, 1u64).await.expect("数据查询失败！！！");

        println!("{:?}", params.get("name"));
        Json(json!({"id": 1212}))
    }
}

pub mod t_users {
    /// 针对t_user表的操作模块
    /// 具体封装sql还是啥的有点不清楚
    use crate::entity_operations::user::User;
    use axum::extract::State;
    use sqlx::Error as SqlxError;
    use sqlx::{query, FromRow, MySql, Pool, Result}; // 引入sqlx的错误类型

    pub async fn get_user_by_id(state: State<Pool<MySql>>, id: i64) -> Result<User, SqlxError> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM t_users WHERE id = ?")
            .bind(id)
            .fetch_one(&*state)
            .await;
        match user {
            Ok(user) => Ok(user),
            Err(err) => {
                Err(err)
            }
        }
    }

    pub async fn get_user_by_email(state: State<Pool<MySql>>, email: String) -> Result<User, SqlxError> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM t_users WHERE id = ?")
            .bind(email)
            .fetch_one(&*state)
            .await;
        match user {
            Ok(user) => Ok(user),
            Err(err) => {
                Err(err)
            }
        }
    }
}
