//! The canonical user type of a Cot project.
//!
//! Every project has exactly one canonical user type, defined by
//! [`Project::User`](crate::Project::User). This is the type every
//! authentication backend resolves users to, and the type that is returned by
//! [`Auth::user`](crate::auth::Auth::user).
//!
//! The canonical user is a regular Cot ORM [`Model`] defined by the project,
//! so it can store any data the project needs. Credentials are not stored in
//! the canonical user, but by the authentication backends (for instance, the
//! passwords of [`PasswordUserBackend`](crate::auth::user_pass::PasswordUserBackend)
//! are stored in [`PasswordUser`](crate::auth::user_pass::PasswordUser)).
//!
//! If the project doesn't have users at all, use [`NoUser`].

use std::borrow::Cow;

use crate::auth::UserId;
use crate::db::{Auto, Model, model};

/// The main user object of the Cot authentication system.
///
/// Each project has exactly one canonical user type, set via
/// [`Project::User`](crate::Project::User). Authentication backends (see
/// [`AuthBackend`](crate::auth::backend::AuthBackend)) authenticate the
/// credentials they are given and return the [`UserId`] of the canonical user
/// they belong to; the user is then loaded from the database by its primary
/// key.
///
/// # Examples
///
/// ```
/// use std::borrow::Cow;
///
/// use cot::auth::canonical::CanonicalUser;
/// use cot::db::{Auto, LimitedString, model};
///
/// #[model]
/// struct MyUser {
///     #[model(primary_key)]
///     id: Auto<i64>,
///     display_name: LimitedString<255>,
///     is_staff: bool,
/// }
///
/// impl CanonicalUser for MyUser {
///     fn display_name(&self) -> Option<Cow<'_, str>> {
///         Some(Cow::Borrowed(&self.display_name))
///     }
///
///     fn is_admin(&self) -> bool {
///         self.is_staff
///     }
/// }
/// ```
pub trait CanonicalUser: Model<PrimaryKey = Auto<i64>> + Send + Sync + 'static {
    /// Returns the ID of the user.
    ///
    /// This returns [`None`] if the user hasn't been saved to the database
    /// yet.
    fn id(&self) -> Option<UserId> {
        match self.primary_key() {
            Auto::Fixed(id) => Some(UserId::Int(*id)),
            Auto::Auto => None,
        }
    }

    /// Returns the name of the user that can be displayed to humans, if there
    /// is one.
    fn display_name(&self) -> Option<Cow<'_, str>>;

    /// Returns whether the user is active.
    ///
    /// Inactive users can't be logged in. If an already logged-in user
    /// becomes inactive, they are logged out on their next request.
    ///
    /// The default implementation returns `true`.
    fn is_active(&self) -> bool {
        true
    }

    /// Returns whether the user has access to the admin panel.
    ///
    /// The default implementation returns `false`.
    fn is_admin(&self) -> bool {
        false
    }
}

/// The canonical user type for projects that don't have users.
///
/// Nobody can be logged in as this user: it can't be constructed, its table
/// doesn't exist, and it is never [active](CanonicalUser::is_active).
///
/// # Examples
///
/// ```
/// use cot::Project;
/// use cot::auth::NoUser;
///
/// struct MyProject;
/// impl Project for MyProject {
///     type User = NoUser;
/// }
/// ```
#[derive(Debug, Clone)]
#[model(table_name = "cot__no_user", model_type = "internal")]
pub struct NoUser {
    #[model(primary_key)]
    id: Auto<i64>,
}

impl CanonicalUser for NoUser {
    fn display_name(&self) -> Option<Cow<'_, str>> {
        None
    }

    fn is_active(&self) -> bool {
        false
    }
}
