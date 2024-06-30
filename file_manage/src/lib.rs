pub mod entity_operations;
pub mod db;
pub mod routes;

pub mod models {
    use crate::entity_operations::user;
    pub async fn add() {
        // let user_1 = user::User::new(
        //     String::from("你叫什么"),
        //     String::from("qw@13579"),
        //     true,
        //     1u32,
        // );
        // println!("测试用户1：\n{}", user_1);

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