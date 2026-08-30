use std::error::Error;

use async_trait::async_trait;
use cot::admin::AdminApp;
use std::sync::Arc;

use cot::auth::backend::AuthBackend;
use cot::auth::user_pass::{PasswordUser, PasswordUserApp, PasswordUserBackend};
use cot::cli::CliMetadata;
use cot::common_types::Password;
use cot::config::{DatabaseConfig, MiddlewareConfig, ProjectConfig, SessionMiddlewareConfig};
use cot::db::Model;
use cot::db::migrations::SyncDynMigration;
use cot::middleware::{AuthMiddleware, SessionMiddleware};
use cot::project::{AuthBackendContext, MiddlewareContext, RegisterAppsContext, RootHandler};
use cot::static_files::StaticFilesMiddleware;
use cot::test::{TestServer, TestServerBuilder, TestUser};
use cot::{App, AppBuilder, Project, ProjectContext};
use fantoccini::{Client, ClientBuilder, Locator};

const DEFAULT_USERNAME: &str = "admin";
const DEFAULT_PASSWORD: &str = "admin";

struct HelloApp;

#[async_trait]
impl App for HelloApp {
    fn name(&self) -> &'static str {
        env!("CARGO_PKG_NAME")
    }

    fn migrations(&self) -> Vec<Box<SyncDynMigration>> {
        TestUser::migrations()
    }

    async fn init(&self, context: &mut ProjectContext) -> cot::Result<()> {
        let mut user = TestUser::new();
        user.insert(context.database()).await?;
        PasswordUser::create(
            context.database(),
            &user,
            DEFAULT_USERNAME,
            &Password::new(DEFAULT_PASSWORD),
        )
        .await?;
        Ok(())
    }
}

struct AdminProject;

impl Project for AdminProject {
    type User = TestUser;

    fn cli_metadata(&self) -> CliMetadata {
        cot::cli::metadata!()
    }

    fn config(&self, _config_name: &str) -> cot::Result<ProjectConfig> {
        Ok(ProjectConfig::builder()
            .debug(true)
            .database(DatabaseConfig::builder().url("sqlite::memory:").build())
            .middlewares(
                MiddlewareConfig::builder()
                    .session(SessionMiddlewareConfig::builder().secure(false).build())
                    .build(),
            )
            .build())
    }

    fn register_apps(&self, apps: &mut AppBuilder, _context: &RegisterAppsContext) {
        apps.register(PasswordUserApp::<Self::User>::new());
        apps.register_with_views(AdminApp::<Self::User>::new(), "/admin");
        apps.register(HelloApp);
    }

    fn auth_backends(&self, context: &AuthBackendContext) -> Vec<AuthBackend<TestUser>> {
        vec![AuthBackend::UsernamePassword(Arc::new(
            PasswordUserBackend::new(context.database().clone()),
        ))]
    }

    fn middlewares(
        &self,
        handler: cot::project::RootHandlerBuilder,
        context: &MiddlewareContext,
    ) -> RootHandler {
        handler
            .middleware(StaticFilesMiddleware::from_context(context))
            .middleware(AuthMiddleware::<Self::User>::new())
            .middleware(SessionMiddleware::from_context(context))
            .build()
    }
}

#[ignore = "This test requires a Webdriver to be running"]
#[cot::e2e_test]
async fn admin_e2e_login() -> Result<(), Box<dyn Error>> {
    let server = TestServerBuilder::new(AdminProject).start().await;
    let driver = create_webdriver().await?;

    login(&server, &driver).await?;

    let welcome_message = driver
        .find(Locator::XPath(
            "//h2[contains(text(), 'Choose a model to manage')]",
        ))
        .await?;
    assert!(welcome_message.is_displayed().await?);

    driver.close().await?;
    server.close().await;
    Ok(())
}

async fn login(server: &TestServer<AdminProject>, driver: &Client) -> Result<(), Box<dyn Error>> {
    login_with(server, driver, DEFAULT_USERNAME, DEFAULT_PASSWORD).await
}

async fn login_with(
    server: &TestServer<AdminProject>,
    driver: &Client,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    driver.goto(&format!("{}/admin/", server.url())).await?;

    let username_form = driver.find(Locator::Id("username")).await?;
    username_form.send_keys(username).await?;
    let password_form = driver.find(Locator::Id("password")).await?;
    password_form.send_keys(password).await?;
    let submit_button = driver.find(Locator::Css("button[type=submit]")).await?;
    submit_button.click().await?;

    Ok(())
}

async fn create_webdriver() -> Result<Client, Box<dyn Error>> {
    Ok(ClientBuilder::native()
        .connect("http://localhost:4444")
        .await?)
}
