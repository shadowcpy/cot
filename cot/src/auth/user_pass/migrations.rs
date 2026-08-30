//! List of migrations for the current app.
//!
//! The migrations are generic over the canonical user of the project, as the
//! credentials reference the table of the user.

pub mod m_0001_initial;
pub mod m_0002_password_user;

use crate::auth::canonical::CanonicalUser;
use crate::db::migrations::SyncDynMigration;

/// Returns the migrations of [`PasswordUserApp<U>`](super::PasswordUserApp).
#[must_use]
pub fn migrations<U: CanonicalUser>() -> Vec<Box<SyncDynMigration>> {
    vec![
        Box::new(m_0001_initial::Migration),
        Box::new(m_0002_password_user::Migration::<U>::new()),
    ]
}
