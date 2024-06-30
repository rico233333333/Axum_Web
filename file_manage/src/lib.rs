pub mod entity_operations;
pub mod db;
pub mod routes;

pub mod models {
    use crate::entity_operations::user;
    pub async fn add() {
        let user = user::User{
            id: 1i64,
            name: String::from("我叫我也不知道"),
            password: String::from("qw@13579"),
            is_superuser: true,
            user_level : 1i32,
        };
        println!("测试用户：\n{}", user);
    }
}