use cot::auth::canonical::CanonicalUser;
use cot::auth::user_pass::PasswordUser;
use cot::auth::{Auth, AuthError, Authenticated, UserId};
use cot::common_types::Password;
use cot::db::Model;
use cot::request::RequestExt;
use cot::test::{TestDatabase, TestRequestBuilder, TestUser};

async fn create_user(test_db: &TestDatabase, username: &str, password: &str) -> TestUser {
    let mut user = TestUser::new();
    user.insert(&**test_db).await.unwrap();
    PasswordUser::create(&**test_db, &user, username, &Password::new(password))
        .await
        .unwrap();
    user
}

#[cot_macros::dbtest]
async fn password_user(test_db: &mut TestDatabase) {
    test_db
        .with_test_user()
        .with_auth::<TestUser>()
        .run_migrations()
        .await;
    let mut request_builder = TestRequestBuilder::get("/");
    request_builder
        .with_db_auth::<TestUser>(test_db.database())
        .await;

    let mut request = request_builder.clone().with_session().build();
    let auth: Auth<TestUser> = request.extract_from_head().await.unwrap();

    // Anonymous user
    assert!(!auth.is_authenticated());
    assert!(auth.user().is_none());

    // Authenticated user
    let created_user = create_user(test_db, "testuser", "password123").await;

    let authenticated = auth
        .authenticate_username_password("testuser", &Password::new("password123"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(Some(authenticated.user_id().clone()), created_user.id());
    assert_eq!(authenticated.backend_name(), "cot_password_user");

    // Log in
    auth.login_authenticated(authenticated).await.unwrap();
    assert!(auth.is_authenticated());
    assert_eq!(auth.user().unwrap().id(), created_user.id());
    assert_eq!(auth.backend().unwrap().name(), "cot_password_user");

    // Invalid credentials
    let user_id = auth
        .authenticate_username_password("testuser", &Password::new("wrongpassword"))
        .await
        .unwrap();
    assert!(user_id.is_none());
    let user_id = auth
        .authenticate_username_password("nonexistent", &Password::new("password123"))
        .await
        .unwrap();
    assert!(user_id.is_none());

    // User persists between requests
    let mut request = request_builder.clone().with_session_from(&request).build();
    let auth: Auth<TestUser> = request.extract_from_head().await.unwrap();
    assert_eq!(auth.user().unwrap().id(), created_user.id());
    assert_eq!(auth.backend().unwrap().name(), "cot_password_user");

    // Log out
    auth.logout().await.unwrap();
    assert!(!auth.is_authenticated());
    assert!(auth.user().is_none());

    // Log in without credentials
    let backend = auth.backends()[0].common();
    auth.login_authenticated(Authenticated::new(created_user.id().unwrap(), backend))
        .await
        .unwrap();
    assert_eq!(auth.user().unwrap().id(), created_user.id());
    assert_eq!(auth.backend().unwrap().name(), "cot_password_user");

    // Logging in a non-existing user fails
    let error = auth
        .login_authenticated(Authenticated::new(UserId::Int(1000), backend))
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::UserNotFound));
}
