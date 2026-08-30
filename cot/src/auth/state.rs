//! The authentication state of a request.
//!
//! Everything here needs the canonical user to be loaded from the database, so
//! this module is only available with the `db` feature.

use std::sync::{Arc, Mutex, MutexGuard};

use cot_core::error::impl_into_cot_error;
use derive_more::with_trait::Debug;
use thiserror::Error;

use crate::auth::backend::{self, AuthBackend};
use crate::auth::canonical::CanonicalUser;
use crate::auth::{AuthError, Result, SessionAuthHash, UserId};
use crate::common_types::Password;
use crate::config::SecretKey;
use crate::db::{Auto, Database};
use crate::request::extractors::FromRequestHead;
use crate::request::{Request, RequestExt, RequestHead};
use crate::session::{ScopedSession, Session};

/// The authentication setup of a project: the database the canonical users
/// are loaded from and the authentication backends.
///
/// It is created by the [`Bootstrapper`](crate::Bootstrapper) from
/// [`Project::User`](crate::Project::User) and
/// [`Project::auth_backends`](crate::Project::auth_backends), and stored in
/// the [`ProjectContext`](crate::ProjectContext) with its user type erased.
/// [`AuthMiddleware`](crate::middleware::AuthMiddleware) retrieves it by the
/// user type it has been created with.
#[derive(Debug)]
pub(crate) struct AuthState<U: CanonicalUser> {
    database: Database,
    backends: Vec<AuthBackend<U>>,
}

impl<U: CanonicalUser> AuthState<U> {
    pub(crate) fn new(
        database: Database,
        backends: Vec<AuthBackend<U>>,
    ) -> std::result::Result<Self, InvalidAuthBackendName> {
        for (index, backend) in backends.iter().enumerate() {
            let name = backend.name();
            // the name is used as the scope of the backend session, which uses `.` as
            // the separator
            if name.contains('.') {
                return Err(InvalidAuthBackendName::ContainsDot { name });
            }
            if backends[..index].iter().any(|other| other.name() == name) {
                return Err(InvalidAuthBackendName::Duplicate { name });
            }
        }

        Ok(Self { database, backends })
    }

    pub(crate) fn backends(&self) -> &[AuthBackend<U>] {
        &self.backends
    }

    fn backend_index(&self, name: &str) -> Option<usize> {
        self.backends
            .iter()
            .position(|backend| backend.name() == name)
    }

    async fn load_user(&self, id: &UserId) -> Result<Option<U>> {
        let UserId::Int(id) = id else {
            return Err(AuthError::UserIdTypeNotSupported);
        };

        U::get_by_primary_key(&self.database, Auto::fixed(*id))
            .await
            .map_err(AuthError::backend_error)
    }

    async fn session_auth_hash(
        &self,
        user: &U,
        secret_key: &SecretKey,
    ) -> Result<Option<SessionAuthHash>> {
        const SESSION_AUTH_HASH_CONTEXT: &str = "cot.rs combined session auth hash v1";

        let Some(user_id) = user.id() else {
            return Ok(None);
        };

        let mut backend_hashes = Vec::new();
        for backend in &self.backends {
            let common = backend.common();
            if let Some(hash) = common.session_auth_hash(&user_id, secret_key).await? {
                backend_hashes.push((common.name(), hash));
            }
        }
        if backend_hashes.is_empty() {
            return Ok(None);
        }

        // Combine the hashes of all backends, so that a change of the credentials in
        // any of them invalidates all sessions of the user, no matter which backend
        // they have logged in with. Sorting by name makes the result independent of
        // the order of the backends; the lengths keep the encoding unambiguous.
        backend_hashes.sort_unstable_by_key(|(name, _)| *name);
        let mut hasher = blake3::Hasher::new_derive_key(SESSION_AUTH_HASH_CONTEXT);
        for (name, hash) in &backend_hashes {
            for part in [name.as_bytes(), hash.as_bytes()] {
                hasher.update(&(part.len() as u64).to_le_bytes());
                hasher.update(part);
            }
        }

        Ok(Some(SessionAuthHash::new(hasher.finalize().as_bytes())))
    }

    async fn authenticate_username_password(
        &self,
        username: &str,
        password: &Password,
    ) -> Result<Option<Authenticated>> {
        for backend in &self.backends {
            if let AuthBackend::UsernamePassword(backend) = backend
                && let Some(user_id) = backend.authenticate(username, password).await?
            {
                return Ok(Some(Authenticated::new(user_id, &**backend)));
            }
        }

        Ok(None)
    }
}

/// The name of an authentication backend of the project is invalid.
#[derive(Debug, Error)]
pub(crate) enum InvalidAuthBackendName {
    /// Two authentication backends of the project have the same name.
    #[error(
        "there are multiple authentication backends named `{name}`; the names of the backends \
        must be unique"
    )]
    Duplicate { name: &'static str },
    /// The name of an authentication backend contains a `.`.
    #[error("the name of the authentication backend `{name}` must not contain `.`")]
    ContainsDot { name: &'static str },
}
impl_into_cot_error!(InvalidAuthBackendName);

/// A user that has been successfully authenticated by an authentication
/// backend, but not logged in yet.
///
/// This is returned by methods such as
/// [`Auth::authenticate_username_password`] and can be passed to
/// [`Auth::login_authenticated`] to log the user in, which also remembers the
/// backend that was used.
///
/// # Examples
///
/// ```
/// use cot::auth::{Auth, AuthError};
/// # use cot::test::TestUser as MyUser;
/// use cot::common_types::Password;
///
/// async fn login(auth: Auth<MyUser>) -> cot::Result<()> {
///     let authenticated = auth
///         .authenticate_username_password("admin", &Password::new("password"))
///         .await?;
///     if let Some(authenticated) = authenticated {
///         auth.login_authenticated(authenticated).await?;
///     }
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    user_id: UserId,
    backend_name: &'static str,
}

impl Authenticated {
    /// Creates a new object for a user that has been authenticated by
    /// `backend`.
    ///
    /// Use this if you call the authentication methods of the backends
    /// directly (for instance,
    /// [`KeyBackend::authenticate`](backend::KeyBackend::authenticate)).
    #[must_use]
    pub fn new<U: CanonicalUser>(
        user_id: UserId,
        backend: &dyn backend::AuthenticationBackendCommon<U>,
    ) -> Self {
        Self {
            user_id,
            backend_name: backend.name(),
        }
    }

    /// Returns the ID of the authenticated user.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the [name](backend::AuthenticationBackendCommon::name) of the
    /// backend that has authenticated the user.
    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        self.backend_name
    }
}

/// Authentication helper structure.
///
/// This is an object that provides access to the currently logged-in user and
/// methods to sign users in and out. `U` is the canonical user type of the
/// project ([`Project::User`](crate::Project::User)). It is constructed by
/// [`AuthMiddleware<U>`](crate::middleware::AuthMiddleware) and can be
/// extracted in any request handler as long as the middleware is active.
///
/// # Errors
///
/// Extracting `Auth<U>` fails if there is no
/// [`AuthMiddleware<U>`](crate::middleware::AuthMiddleware) with the same
/// user type enabled for the route.
///
/// # Security
///
/// This is a wrapper around a reference-counted inner object, which contains
/// the actual user data. It's safe and cheap to clone it and authenticate the
/// user, as the change will be reflected in all clones.
///
/// # Examples
///
/// ```
/// use cot::auth::Auth;
/// use cot::auth::canonical::CanonicalUser;
/// use cot::html::Html;
/// # use cot::test::TestUser as MyUser;
///
/// async fn index(auth: Auth<MyUser>) -> Html {
///     match auth.user() {
///         Some(user) => Html::new(format!("Hello, {:?}!", user.id())),
///         None => Html::new("Hello, stranger!"),
///     }
/// }
/// ```
#[derive(Debug)]
pub struct Auth<U: CanonicalUser> {
    inner: Arc<AuthInner<U>>,
}

impl<U: CanonicalUser> Clone for Auth<U> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[derive(Debug)]
struct AuthInner<U: CanonicalUser> {
    session: Session,
    state: Arc<AuthState<U>>,
    secret_key: SecretKey,
    // Using a standard Mutex object instead of an async version - it's unlikely this will ever be
    // accessed from multiple threads, since it's tied to a single request. The mutex is used
    // mostly to allow the `Auth` object to be cloned and passed around while maintaining the
    // reference to the same `AuthInner` object with a mutable `user`.
    #[debug("..")]
    user: Mutex<Option<LoggedIn<U>>>,
}

/// The currently logged-in user.
struct LoggedIn<U> {
    user: Arc<U>,
    /// The index of the backend the user has logged in with.
    backend: usize,
}

impl<U: CanonicalUser> Auth<U> {
    pub(crate) async fn new(
        session: Session,
        state: Arc<AuthState<U>>,
        secret_key: SecretKey,
        fallback_secret_keys: &[SecretKey],
    ) -> Result<Self> {
        let user =
            get_user_with_saved_id(&session, &state, &secret_key, fallback_secret_keys).await?;

        Ok(Self {
            inner: Arc::new(AuthInner {
                session,
                state,
                secret_key,
                user: Mutex::new(user),
            }),
        })
    }

    pub(crate) async fn from_request(request: &mut Request) -> crate::Result<Self> {
        let context = request.context();
        let state = context
            .auth_state::<U>()
            .ok_or(AuthNotConfigured::new::<U>())?;
        let config = context.config();
        let secret_key = config.secret_key.clone();
        let session = Session::from_request(request).clone();

        Ok(Self::new(session, state, secret_key, &config.fallback_secret_keys).await?)
    }

    /// Returns the currently logged-in user, or [`None`] if the user is not
    /// logged in.
    #[must_use]
    pub fn user(&self) -> Option<Arc<U>> {
        self.user_lock()
            .as_ref()
            .map(|logged_in| Arc::clone(&logged_in.user))
    }

    /// Returns the authentication backend the current user has logged in
    /// with.
    ///
    /// Returns [`None`] if no user is logged in.
    #[must_use]
    pub fn backend(&self) -> Option<&AuthBackend<U>> {
        let index = self.user_lock().as_ref()?.backend;
        Some(&self.inner.state.backends()[index])
    }

    /// Returns the private part of the session of the given backend.
    ///
    /// Backends can use it to store any data they need between requests,
    /// without having to worry about colliding with the data of other
    /// backends or the application. The scope is derived from the
    /// [name](backend::AuthenticationBackendCommon::name) of the backend.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::backend::AuthBackend;
    /// use cot::auth::Auth;
    /// # use cot::test::TestUser as MyUser;
    ///
    /// async fn start_login(auth: Auth<MyUser>) -> cot::Result<()> {
    ///     for backend in auth.backends() {
    ///         if let AuthBackend::RedirectAuthenticate(backend) = backend {
    ///             let url = backend.redirect(&auth.backend_session(&**backend)).await?;
    ///             // redirect the user to `url`...
    ///         }
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[must_use]
    pub fn backend_session(
        &self,
        backend: &dyn backend::AuthenticationBackendCommon<U>,
    ) -> ScopedSession {
        ScopedSession::new(
            self.inner.session.clone(),
            &format!("{BACKEND_SESSION_SCOPE_PREFIX}{}", backend.name()),
        )
    }

    /// Returns whether a user is logged in.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.user_lock().is_some()
    }

    /// Returns the authentication backends of the project.
    #[must_use]
    pub fn backends(&self) -> &[AuthBackend<U>] {
        self.inner.state.backends()
    }

    /// Checks the given username and password against all the
    /// [`UsernamePassword`](AuthBackend::UsernamePassword) backends
    /// of the project, in order.
    ///
    /// Returns the authenticated user (together with the backend that accepted
    /// the credentials), or [`None`] if no backend accepted the credentials.
    ///
    /// Note that this doesn't log the user in, it only checks if the
    /// credentials are valid. To log the user in, use
    /// [`login_authenticated`](Self::login_authenticated).
    ///
    /// # Errors
    ///
    /// Returns an error if any of the backends fails.
    pub async fn authenticate_username_password(
        &self,
        username: &str,
        password: &Password,
    ) -> Result<Option<Authenticated>> {
        self.inner
            .state
            .authenticate_username_password(username, password)
            .await
    }

    /// Logs in a user that has been authenticated by one of the
    /// authentication backends of the project.
    ///
    /// The backend is remembered in the session and can be retrieved with
    /// [`backend`](Self::backend). To log in a user without them presenting
    /// any credentials (for instance, right after they signed up), create the
    /// [`Authenticated`] object yourself with [`Authenticated::new`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::UnknownBackend`] if the backend is not one of the
    /// backends of the project.
    ///
    /// Returns [`AuthError::UserNotFound`] if the user doesn't exist.
    ///
    /// Returns [`AuthError::UserInactive`] if the user is not active.
    ///
    /// Returns an error if the user cannot be loaded or stored in the session.
    pub async fn login_authenticated(&self, authenticated: Authenticated) -> Result<()> {
        self.backend_index(authenticated.backend_name())?;
        let user = self
            .load_user(authenticated.user_id())
            .await?
            .ok_or(AuthError::UserNotFound)?;

        self.login_user(Arc::new(user), authenticated.backend_name())
            .await
    }

    pub(crate) async fn load_user(&self, id: &UserId) -> Result<Option<U>> {
        self.inner.state.load_user(id).await
    }

    pub(crate) async fn login_user(&self, user: Arc<U>, backend_name: &str) -> Result<()> {
        let user_id = user.id().ok_or(AuthError::UserNotFound)?;
        if !user.is_active() {
            return Err(AuthError::UserInactive);
        }
        let backend = self.backend_index(backend_name)?;

        // Mitigate the session fixation attack by changing the session ID:
        // https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renew-the-session-id-after-any-privilege-level-change
        let session = &self.inner.session;
        session.cycle_id().await?;

        session.insert(USER_ID_SESSION_KEY, user_id).await?;
        session.insert(BACKEND_SESSION_KEY, backend_name).await?;
        let session_auth_hash = self
            .inner
            .state
            .session_auth_hash(&user, &self.inner.secret_key)
            .await?;
        if let Some(session_auth_hash) = session_auth_hash {
            session
                .insert(SESSION_HASH_SESSION_KEY, session_auth_hash.as_bytes())
                .await?;
        }
        *self.user_lock() = Some(LoggedIn { user, backend });

        Ok(())
    }

    /// Logs out the current user.
    ///
    /// This flushes the session. Subsequent calls to [`user`](Self::user)
    /// return [`None`], unless a user is logged in again.
    ///
    /// # Errors
    ///
    /// Returns an error if the session cannot be flushed.
    pub async fn logout(&self) -> Result<()> {
        self.inner.session.flush().await?;
        *self.user_lock() = None;

        Ok(())
    }

    fn backend_index(&self, name: &str) -> Result<usize> {
        self.inner
            .state
            .backend_index(name)
            .ok_or_else(|| AuthError::UnknownBackend(name.to_owned()))
    }

    fn user_lock(&self) -> MutexGuard<'_, Option<LoggedIn<U>>> {
        self.inner.user.lock().unwrap_or_else(|poison_error| {
            // We don't have any invariants about the structure of the
            // user object, so we can safely clear the poison.
            self.inner.user.clear_poison();
            poison_error.into_inner()
        })
    }
}

/// # Errors
///
/// Returns an error if
/// [`AuthMiddleware<U>`](crate::middleware::AuthMiddleware) is not enabled for
/// the route/project.
impl<U: CanonicalUser> FromRequestHead for Auth<U> {
    #[expect(clippy::unused_async_trait_impl)]
    async fn from_request_head(head: &RequestHead) -> cot::Result<Self> {
        let auth = head
            .extensions
            .get::<Auth<U>>()
            .ok_or_else(AuthMiddlewareMissing::new::<U>)?
            .clone();

        Ok(auth)
    }
}

/// The authentication state for the requested user type is not available.
#[derive(Debug, Error)]
#[error(
    "`Auth<{user_type}>` requested, but the project doesn't have authentication set up for \
    `{user_type}`; make sure it is the `Project::User` type and the database is configured"
)]
struct AuthNotConfigured {
    user_type: &'static str,
}

impl AuthNotConfigured {
    fn new<U>() -> Self {
        Self {
            user_type: std::any::type_name::<U>(),
        }
    }
}
impl_into_cot_error!(AuthNotConfigured);

/// [`Auth`] was extracted, but there is no matching
/// [`AuthMiddleware`](crate::middleware::AuthMiddleware) enabled.
#[derive(Debug, Error)]
#[error(
    "`Auth<{user_type}>` requested, but `AuthMiddleware<{user_type}>` is not enabled for the \
    route/project"
)]
pub(crate) struct AuthMiddlewareMissing {
    user_type: &'static str,
}

impl AuthMiddlewareMissing {
    pub(crate) fn new<U>() -> Self {
        Self {
            user_type: std::any::type_name::<U>(),
        }
    }
}
impl_into_cot_error!(AuthMiddlewareMissing);

const USER_ID_SESSION_KEY: &str = "__cot_auth_user_id";
const SESSION_HASH_SESSION_KEY: &str = "__cot_auth_session_hash";
const BACKEND_SESSION_KEY: &str = "__cot_auth_backend";
const BACKEND_SESSION_SCOPE_PREFIX: &str = "__cot_auth_backend_data.";

async fn get_user_with_saved_id<U: CanonicalUser>(
    session: &Session,
    state: &AuthState<U>,
    secret_key: &SecretKey,
    fallback_secret_keys: &[SecretKey],
) -> Result<Option<LoggedIn<U>>> {
    let Some(user_id) = session.get::<UserId>(USER_ID_SESSION_KEY).await? else {
        return Ok(None);
    };

    let Some(backend_name) = session.get::<String>(BACKEND_SESSION_KEY).await? else {
        return Ok(None);
    };
    // the backend the user has logged in with may have been removed from the project
    let Some(backend) = state.backend_index(&backend_name) else {
        return Ok(None);
    };

    let Some(user) = state.load_user(&user_id).await? else {
        return Ok(None);
    };

    if !user.is_active() {
        return Ok(None);
    }

    if session_auth_hash_valid(&user, session, state, secret_key, fallback_secret_keys).await? {
        Ok(Some(LoggedIn {
            user: Arc::new(user),
            backend,
        }))
    } else {
        Ok(None)
    }
}

async fn session_auth_hash_valid<U: CanonicalUser>(
    user: &U,
    session: &Session,
    state: &AuthState<U>,
    secret_key: &SecretKey,
    fallback_secret_keys: &[SecretKey],
) -> Result<bool> {
    let Some(user_hash) = state.session_auth_hash(user, secret_key).await? else {
        return Ok(true);
    };

    let Some(stored_hash) = session.get::<Vec<u8>>(SESSION_HASH_SESSION_KEY).await? else {
        // The user has a session hash now, but didn't have one when they logged in
        return Ok(false);
    };
    let stored_hash = SessionAuthHash::new(&stored_hash);

    if user_hash == stored_hash {
        return Ok(true);
    }

    // If the primary secret key doesn't match, try the fallback keys (in other
    // words, check if the session hash was generated with an old secret key)
    // and update the session hash with the new key if a match is found.
    for fallback_key in fallback_secret_keys {
        let user_hash_fallback = state.session_auth_hash(user, fallback_key).await?;
        if user_hash_fallback.as_ref() == Some(&stored_hash) {
            session
                .insert(SESSION_HASH_SESSION_KEY, user_hash.as_bytes())
                .await?;

            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::{Auth, AuthState, Authenticated, BACKEND_SESSION_KEY, USER_ID_SESSION_KEY};
    use crate::auth::backend::{AuthBackend, AuthenticationBackendCommon, UsernamePasswordBackend};
    use crate::auth::canonical::CanonicalUser;
    use crate::auth::user_pass::{PasswordUser, PasswordUserBackend};
    use crate::auth::{SessionAuthHash, UserId};
    use crate::common_types::Password;
    use crate::config::SecretKey;
    use crate::db::{Database, Model};
    use crate::session::Session;
    use crate::test::{TestDatabase, TestRequestBuilder, TestUser as TestDbUser};

    const TEST_KEY_1: &[u8] = b"key1";
    const TEST_KEY_2: &[u8] = b"key2";
    const TEST_KEY_3: &[u8] = b"key3";

    async fn test_database() -> TestDatabase {
        let mut test_db = TestDatabase::new_sqlite().await.unwrap();
        test_db
            .with_test_user()
            .with_auth::<TestDbUser>()
            .run_migrations()
            .await;
        test_db
    }

    fn state(database: &Database) -> Arc<AuthState<TestDbUser>> {
        Arc::new(
            AuthState::new(
                database.clone(),
                vec![AuthBackend::UsernamePassword(Arc::new(
                    PasswordUserBackend::new(database.clone()),
                ))],
            )
            .unwrap(),
        )
    }

    async fn create_user(test_db: &TestDatabase, username: &str, password: &str) -> TestDbUser {
        let database = test_db.database();
        let mut user = TestDbUser::new();
        user.insert(&database).await.unwrap();
        PasswordUser::create(&database, &user, username, &Password::new(password))
            .await
            .unwrap();
        user
    }

    fn new_session() -> Session {
        let request = TestRequestBuilder::get("/").with_session().build();
        Session::from_request(&request).clone()
    }

    async fn login(auth: &Auth<TestDbUser>, user: &TestDbUser) {
        let authenticated = Authenticated::new(user.id().unwrap(), auth.backends()[0].common());
        auth.login_authenticated(authenticated).await.unwrap();
    }

    async fn new_auth<U: CanonicalUser>(
        session: &Session,
        state: &Arc<AuthState<U>>,
        secret_key: &[u8],
        fallback_keys: &[&[u8]],
    ) -> Auth<U> {
        let fallback_keys: Vec<_> = fallback_keys
            .iter()
            .map(|key| SecretKey::new(key))
            .collect();
        Auth::new(
            session.clone(),
            Arc::clone(state),
            SecretKey::new(secret_key),
            &fallback_keys,
        )
        .await
        .unwrap()
    }

    #[cot::test]
    #[cfg_attr(miri, ignore)]
    async fn user_anonymous() {
        let test_db = test_database().await;
        let state = state(&test_db.database());

        let auth = new_auth(&new_session(), &state, TEST_KEY_1, &[]).await;
        assert!(!auth.is_authenticated());
        assert!(auth.user().is_none());
        assert_eq!(auth.backends().len(), 1);

        test_db.cleanup().await.unwrap();
    }

    #[cot::test]
    #[cfg_attr(miri, ignore)]
    async fn login_logout() {
        let test_db = test_database().await;
        let state = state(&test_db.database());
        let user = create_user(&test_db, "testuser", "password").await;
        let session = new_session();
        let auth = new_auth(&session, &state, TEST_KEY_1, &[]).await;

        login(&auth, &user).await;
        assert_eq!(auth.user().unwrap().id(), user.id());
        assert!(!session.is_empty().await);

        // the user is restored from the session
        let auth_2 = new_auth(&session, &state, TEST_KEY_1, &[]).await;
        assert!(auth_2.is_authenticated());

        auth.logout().await.unwrap();
        assert!(auth.user().is_none());
        assert!(session.is_empty().await);

        test_db.cleanup().await.unwrap();
    }

    /// Test the session fixation attack mitigation
    #[cot::test]
    #[cfg_attr(miri, ignore)]
    async fn login_cycle_id() {
        let test_db = test_database().await;
        let state = state(&test_db.database());
        let user_1 = create_user(&test_db, "user1", "password").await;
        let user_2 = create_user(&test_db, "user2", "password").await;
        let session = new_session();
        let auth = new_auth(&session, &state, TEST_KEY_1, &[]).await;

        login(&auth, &user_1).await;
        session.save().await.unwrap();
        let id_1 = session.id();
        assert!(id_1.is_some());

        login(&auth, &user_2).await;
        session.save().await.unwrap();
        let id_2 = session.id();
        assert!(id_2.is_some());

        assert_ne!(id_1, id_2);

        test_db.cleanup().await.unwrap();
    }

    /// Test that the user is logged out when there is an invalid user ID in
    /// the session (can happen if the user is deleted from the database)
    #[cot::test]
    #[cfg_attr(miri, ignore)]
    async fn logout_on_invalid_user_id_in_session() {
        let test_db = test_database().await;
        let state = state(&test_db.database());
        let session = new_session();
        session
            .insert(USER_ID_SESSION_KEY, UserId::Int(42))
            .await
            .unwrap();

        let auth = new_auth(&session, &state, TEST_KEY_1, &[]).await;
        assert!(!auth.is_authenticated());

        test_db.cleanup().await.unwrap();
    }

    /// Test that the user is logged out when the session doesn't contain the
    /// backend the user has logged in with
    #[cot::test]
    #[cfg_attr(miri, ignore)]
    async fn logout_on_missing_backend_in_session() {
        let test_db = test_database().await;
        let state = state(&test_db.database());
        let user = create_user(&test_db, "testuser", "password").await;
        let session = new_session();

        let auth = new_auth(&session, &state, TEST_KEY_1, &[]).await;
        login(&auth, &user).await;
        session.remove_value(BACKEND_SESSION_KEY).await.unwrap();

        let auth = new_auth(&session, &state, TEST_KEY_1, &[]).await;
        assert!(!auth.is_authenticated());

        test_db.cleanup().await.unwrap();
    }

    /// Test that the user is logged out when the backend the user has logged
    /// in with is not one of the backends of the project anymore
    #[cot::test]
    #[cfg_attr(miri, ignore)]
    async fn logout_on_unknown_backend_in_session() {
        let test_db = test_database().await;
        let state = state(&test_db.database());
        let user = create_user(&test_db, "testuser", "password").await;
        let session = new_session();

        let auth = new_auth(&session, &state, TEST_KEY_1, &[]).await;
        login(&auth, &user).await;
        session
            .insert(BACKEND_SESSION_KEY, "removed_backend")
            .await
            .unwrap();

        let auth = new_auth(&session, &state, TEST_KEY_1, &[]).await;
        assert!(!auth.is_authenticated());

        test_db.cleanup().await.unwrap();
    }

    /// A backend whose session auth hash can be changed by the test.
    struct HashBackend(Arc<Mutex<Vec<u8>>>);

    #[async_trait]
    impl AuthenticationBackendCommon<TestDbUser> for HashBackend {
        fn name(&self) -> &'static str {
            "test_hash"
        }

        async fn session_auth_hash(
            &self,
            _user_id: &UserId,
            _secret_key: &SecretKey,
        ) -> crate::auth::Result<Option<SessionAuthHash>> {
            Ok(Some(SessionAuthHash::new(&self.0.lock().unwrap())))
        }
    }

    #[async_trait]
    impl UsernamePasswordBackend<TestDbUser> for HashBackend {
        async fn authenticate(
            &self,
            _username: &str,
            _password: &Password,
        ) -> crate::auth::Result<Option<UserId>> {
            Ok(None)
        }
    }

    /// Test that the session auth hash is combined from all backends,
    /// independent of their order
    #[cot::test]
    #[cfg_attr(miri, ignore)]
    async fn session_auth_hash_combines_all_backends() {
        let test_db = test_database().await;
        let database = test_db.database();
        let user = create_user(&test_db, "testuser", "password").await;
        let hash = Arc::new(Mutex::new(b"hash1".to_vec()));
        let password_backend =
            AuthBackend::UsernamePassword(Arc::new(PasswordUserBackend::new(database.clone())));
        let hash_backend = AuthBackend::UsernamePassword(Arc::new(HashBackend(Arc::clone(&hash))));
        let state_1 = Arc::new(
            AuthState::new(
                database.clone(),
                vec![password_backend.clone(), hash_backend.clone()],
            )
            .unwrap(),
        );
        let state_2 =
            Arc::new(AuthState::new(database, vec![hash_backend, password_backend]).unwrap());
        let session = new_session();

        // logs in with the password backend
        let auth = new_auth(&session, &state_1, TEST_KEY_1, &[]).await;
        login(&auth, &user).await;

        // the order of the backends doesn't matter
        let auth = new_auth(&session, &state_2, TEST_KEY_1, &[]).await;
        assert!(auth.is_authenticated());

        // a change in a backend the user hasn't logged in with logs them out
        *hash.lock().unwrap() = b"hash2".to_vec();
        let auth = new_auth(&session, &state_1, TEST_KEY_1, &[]).await;
        assert!(!auth.is_authenticated());

        test_db.cleanup().await.unwrap();
    }

    #[cot::test]
    #[cfg_attr(miri, ignore)]
    async fn logout_on_password_change() {
        let test_db = test_database().await;
        let state = state(&test_db.database());
        let user = create_user(&test_db, "testuser", "password").await;
        let session = new_session();

        let auth = new_auth(&session, &state, TEST_KEY_1, &[]).await;
        login(&auth, &user).await;

        let auth = new_auth(&session, &state, TEST_KEY_1, &[]).await;
        assert!(auth.is_authenticated());

        let mut credentials = PasswordUser::get_by_user(&*test_db, &user)
            .await
            .unwrap()
            .unwrap();
        credentials.set_password(&Password::new("new_password"));
        credentials.save(&*test_db).await.unwrap();
        let auth = new_auth(&session, &state, TEST_KEY_1, &[]).await;
        assert!(!auth.is_authenticated());

        test_db.cleanup().await.unwrap();
    }

    #[cot::test]
    #[cfg_attr(miri, ignore)]
    async fn user_secret_key_change() {
        let test_db = test_database().await;
        let state = state(&test_db.database());
        let user = create_user(&test_db, "testuser", "password").await;
        let session = new_session();

        let auth = new_auth(&session, &state, TEST_KEY_1, &[]).await;
        login(&auth, &user).await;

        // Change the secret key and verify the user is still logged in with the
        // fallback key
        let auth = new_auth(&session, &state, TEST_KEY_2, &[TEST_KEY_1]).await;
        assert!(auth.is_authenticated());

        // Remove fallback key and verify the user is still logged in (the session
        // hash has been updated to the new key)
        let auth = new_auth(&session, &state, TEST_KEY_2, &[]).await;
        assert!(auth.is_authenticated());

        // Remove both keys and verify the user is logged out
        let auth = new_auth(&session, &state, TEST_KEY_3, &[]).await;
        assert!(!auth.is_authenticated());

        test_db.cleanup().await.unwrap();
    }
}
