mod migrations;

use std::borrow::Cow;
use std::sync::Arc;

use cot::auth::backend::AuthBackend;
use cot::auth::canonical::CanonicalUser;
use cot::auth::user_pass::{PasswordUserApp, PasswordUserBackend};
use cot::cli::CliMetadata;
use cot::db::migrations::SyncDynMigration;
use cot::db::{Auto, model};
use cot::html::Html;
use cot::middleware::{
    AuthMiddleware, LiveReloadMiddleware, SessionMiddleware, TrailingSlashMiddleware,
};
use cot::project::{
    AuthBackendContext, MiddlewareContext, RegisterAppsContext, RootHandler, RootHandlerBuilder,
};
use cot::request::extractors::StaticFiles;
use cot::router::{Route, Router};
use cot::static_files::{StaticFile, StaticFilesMiddleware};
use cot::session::db::SessionApp;
use cot::{App, AppBuilder, Project, static_files, Template};

/// The user of the project.
///
/// Usernames and passwords are stored by [`PasswordUserApp`], so the user model
/// itself only needs a primary key. Add any other data you need about your
/// users here (and run `cot migration make` afterwards).
///
/// The table name is set explicitly, so that the struct can be renamed without
/// changing the table.
#[derive(Debug, Clone)]
#[model(table_name = "user")]
struct {{ project_struct_name }}User {
    #[model(primary_key)]
    id: Auto<i64>,
}

impl CanonicalUser for {{ project_struct_name }}User {
    fn display_name(&self) -> Option<Cow<'_, str>> {
        None
    }
}

#[derive(Debug, Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    static_files: StaticFiles,
}

async fn index(static_files: StaticFiles) -> cot::Result<Html> {
    let index_template = IndexTemplate { static_files };
    let rendered = index_template.render()?;

    Ok(Html::new(rendered))
}

struct {{ app_name }};

impl App for {{ app_name }} {
    fn name(&self) -> &'static str {
        env!("CARGO_CRATE_NAME")
    }

    fn migrations(&self) -> Vec<Box<SyncDynMigration>> {
        cot::db::migrations::wrap_migrations(migrations::MIGRATIONS)
    }

    fn router(&self) -> Router {
        Router::with_urls([Route::with_handler_and_name("/", index, "index")])
    }

    fn static_files(&self) -> Vec<StaticFile> {
        static_files!("css/main.css")
    }
}

struct {{ project_struct_name }};

impl Project for {{ project_struct_name }} {
    type User = {{ project_struct_name }}User;

    fn cli_metadata(&self) -> CliMetadata {
        cot::cli::metadata!()
    }

    fn register_apps(&self, apps: &mut AppBuilder, _context: &RegisterAppsContext) {
        apps.register_with_views({{ app_name }}, "");
        apps.register(PasswordUserApp::<Self::User>::new());
        apps.register(SessionApp::new());
    }

    fn auth_backends(&self, context: &AuthBackendContext) -> Vec<AuthBackend<Self::User>> {
        vec![AuthBackend::UsernamePassword(Arc::new(
            PasswordUserBackend::new(context.database().clone()),
        ))]
    }

    fn middlewares(
        &self,
        handler: RootHandlerBuilder,
        context: &MiddlewareContext,
    ) -> RootHandler {
        handler
            .middleware(StaticFilesMiddleware::from_context(context))
            .middleware(AuthMiddleware::<Self::User>::new())
            .middleware(SessionMiddleware::from_context(context))
            .middleware(LiveReloadMiddleware::from_context(context))
            .middleware(TrailingSlashMiddleware::from_context(context))
            .build()
    }
}

#[cot::main]
fn main() -> impl Project {
    {{ project_struct_name }}
}
