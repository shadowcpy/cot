mod migrations;

use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::time::Duration;

use async_trait::async_trait;
use cot::admin::{AdminApp, AdminModel, AdminModelManager, DefaultAdminModelManager};
use std::sync::Arc;

use cot::auth::backend::AuthBackend;
use cot::auth::canonical::CanonicalUser;
use cot::auth::user_pass::{PasswordUser, PasswordUserApp, PasswordUserBackend};
use cot::cli::CliMetadata;
use cot::common_types::Password;
use cot::config::{
    DatabaseConfig, MiddlewareConfig, ProjectConfig, SessionMiddlewareConfig, StaticFilesConfig,
    StaticFilesPathRewriteMode,
};
use cot::db::migrations::SyncDynMigration;
use cot::db::{Auto, Database, Model, model};
use cot::form::Form;
use cot::html::Html;
use cot::middleware::{AuthMiddleware, LiveReloadMiddleware, SessionMiddleware};
use cot::project::{AuthBackendContext, MiddlewareContext, RegisterAppsContext, RootHandler};
use cot::router::{Route, Router, Urls};
use cot::static_files::StaticFilesMiddleware;
use cot::{App, AppBuilder, Project, ProjectContext, Template};

/// The user of the project.
///
/// The usernames and passwords are stored by [`PasswordUserApp`], so the user
/// model itself only needs a primary key. Add any other data you need about
/// your users here.
#[derive(Debug, Clone)]
#[model]
struct DefaultCanonicalUser {
    #[model(primary_key)]
    id: Auto<i64>,
}

impl CanonicalUser for DefaultCanonicalUser {
    fn display_name(&self) -> Option<Cow<'_, str>> {
        None
    }

    fn is_admin(&self) -> bool {
        // every user can access the admin panel
        true
    }
}

#[derive(Debug, Clone, Form, AdminModel)]
#[model]
struct TodoItem {
    #[model(primary_key)]
    id: Auto<i32>,
    title: String,
}

impl Display for TodoItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.title)
    }
}

#[derive(Debug, Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    urls: &'a Urls,
    todo_items: Vec<TodoItem>,
}

async fn index(urls: Urls, db: Database) -> cot::Result<Html> {
    let todo_items = TodoItem::objects().all(&db).await?;
    let index_template = IndexTemplate {
        urls: &urls,
        todo_items,
    };
    let rendered = index_template.render()?;

    Ok(Html::new(rendered))
}

struct HelloApp;

#[async_trait]
impl App for HelloApp {
    fn name(&self) -> &'static str {
        env!("CARGO_PKG_NAME")
    }

    async fn init(&self, context: &mut ProjectContext) -> cot::Result<()> {
        let mut transaction = context.database().begin().await?;

        let credentials = PasswordUser::get_by_username(&mut transaction, "admin").await?;
        if credentials.is_none() {
            let mut user = DefaultCanonicalUser { id: Auto::auto() };
            user.insert(&mut transaction).await?;
            PasswordUser::create(&mut transaction, &user, "admin", &Password::new("admin")).await?;
        }

        transaction.commit().await?;
        Ok(())
    }

    fn migrations(&self) -> Vec<Box<SyncDynMigration>> {
        cot::db::migrations::wrap_migrations(migrations::MIGRATIONS)
    }

    fn admin_model_managers(&self) -> Vec<Box<dyn AdminModelManager>> {
        vec![Box::new(DefaultAdminModelManager::<TodoItem>::new())]
    }

    fn router(&self) -> Router {
        Router::with_urls([Route::with_handler("/", index)])
    }
}

struct AdminProject;

impl Project for AdminProject {
    type User = DefaultCanonicalUser;

    fn cli_metadata(&self) -> CliMetadata {
        cot::cli::metadata!()
    }

    fn config(&self, _config_name: &str) -> cot::Result<ProjectConfig> {
        Ok(ProjectConfig::builder()
            .debug(true)
            .database(
                DatabaseConfig::builder()
                    .url("sqlite://db.sqlite3?mode=rwc")
                    .build(),
            )
            .middlewares(
                MiddlewareConfig::builder()
                    .session(SessionMiddlewareConfig::builder().secure(false).build())
                    .build(),
            )
            .static_files(
                StaticFilesConfig::builder()
                    .rewrite(StaticFilesPathRewriteMode::QueryParam)
                    .cache_timeout(Duration::from_secs(300))
                    .build(),
            )
            .build())
    }

    fn register_apps(&self, apps: &mut AppBuilder, _context: &RegisterAppsContext) {
        apps.register(PasswordUserApp::<Self::User>::new());
        apps.register_with_views(AdminApp::<Self::User>::new(), "/admin");
        apps.register_with_views(HelloApp, "");
    }

    fn auth_backends(
        &self,
        context: &AuthBackendContext,
    ) -> Vec<AuthBackend<DefaultCanonicalUser>> {
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
            .middleware(LiveReloadMiddleware::new())
            .build()
    }
}

#[cot::main]
fn main() -> impl Project {
    AdminProject
}
