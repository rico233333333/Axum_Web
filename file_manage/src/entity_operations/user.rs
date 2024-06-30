use sqlx::FromRow;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(FromRow)]
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
    use axum::extract::{Json, Path, Query};
    use serde_json::{json, Value};
    use sqlx::{FromRow, MySqlConnection, Result};
    use std::collections::HashMap;
    // use crate::entity_operations::user::t_user::get_user_by_id;

    pub async fn add_user(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
        // let data = get_user_by_id(&mut MySqlConnection, 1u64).await.expect("数据查询失败！！！");

        println!("{:?}", params.get("name"));
        Json(json!({"id": 1212}))
    }
}

pub mod t_user {
    use crate::entity_operations::user::User;
    use axum::extract::{Json, Path, Query, State};
    use axum::http::{Error, StatusCode};
    use sqlx::{query, FromRow, MySql, MySqlConnection, Pool, Result};

    // pub struct Return_http {
    //     code : 
    // }

    pub async fn get_user_by_id(
        state: State<Pool<MySql>>,
        Path(id): Path<i64>,
    ) -> () {
        let user = sqlx::query_as::<_, User>("SELECT * FROM t_users WHERE id = ?")
            .bind(id)
            .fetch_one(&*state)
            .await;
        match user {
            Ok(user) => {
                println!("{}", user);
                // Ok(user);
                ()
                
            }
            Err(err) => {
                println!("{}", err);
                // Err(format!("数据库错误{}", err));
                ()
            }
        }
    }
}
