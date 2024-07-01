use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter}; // 结构体的序列化与反序列化

#[derive(FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub password: String,
    pub is_superuser: bool,
    pub user_level: i32,
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "id: {}\nname:{}\npassword: {}\nis_superuser: {}\nuser_level: {}",
            self.id, self.name, self.password, self.is_superuser, self.user_level
        )
    }
}

impl User {
    pub fn new(name: String, password: String, is_superuser: bool, user_level: i32) -> Self {
        User {
            id: 111111i64,
            name: name,
            password: format!("加密后：{}", password),
            is_superuser: is_superuser,
            user_level: user_level,
        }
    }
}

pub mod user_request {
    use crate::entity_operations::user::t_users::get_user_by_id;
    use axum::extract::{Json, Path, Query, State};
    use serde_json::{json, Value};
    use sqlx::{FromRow, MySql, MySqlConnection, Pool, Result};
    use std::collections::HashMap;

    use super::User;

    pub async fn get_user_only(state: State<Pool<MySql>>, Path(id): Path<i64>) -> Json<Value> {
        let data = get_user_by_id(state, id).await;
        // println!("data:{:?}", data);
        match data {
            Ok(user) => {
                println!("{}", user);
            }
            Err(err) => {
                println!("{}", err);
            }
        }
        
        Json(json!({"data": 1212}))
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
    use sqlx::{query, FromRow, MySql, Pool, Result};
    use sqlx::Error as SqlxError; // 引入sqlx的错误类型

    pub async fn get_user_by_id(state: State<Pool<MySql>>, id:i64) -> Result<User, SqlxError> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM t_users WHERE id = ?")
            .bind(id)
            .fetch_one(&*state)
            .await;
        match user {
            Ok(user) => {
                Ok(user)
            }
            Err(err) => {
                println!("{:?}", err.as_database_error());
                // println!("{:?}", err.into_database_error());
                Err(err)
            }
        }
    }
}
