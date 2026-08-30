//! Authentication system for Cot.
//!
//! This module provides the authentication system for Cot. Each project has a
//! single [canonical user type](canonical::CanonicalUser) (set with
//! [`Project::User`](crate::Project::User)) and any number of
//! [authentication backends](backend::AuthBackend) (set with
//! [`Project::auth_backends`](crate::Project::auth_backends)) that check
//! credentials and resolve them to a canonical user. The currently logged-in
//! user can be accessed with the [`Auth`] extractor.
//!
//! For the default user type and the default username/password backend, see
//! the [`db`] module.

#[cfg(feature = "db")]
pub mod backend;
#[cfg(feature = "db")]
pub mod canonical;
#[cfg(feature = "db")]
mod state;
#[cfg(feature = "db")]
pub mod user_pass;

use cot_core::error::impl_into_cot_error;
use derive_more::with_trait::Debug;
use password_auth::VerifyError;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::common_types::Password;

#[cfg(feature = "db")]
pub use canonical::NoUser;
#[cfg(feature = "db")]
pub(crate) use state::AuthState;
#[cfg(feature = "db")]
pub use state::{Auth, Authenticated};

const ERROR_PREFIX: &str = "failed to authenticate user:";

/// An error that occurs during authentication.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The password hash that was provided to [`PasswordHash::new`] is invalid.
    #[error("{ERROR_PREFIX} password hash is invalid")]
    PasswordHashInvalid,
    /// An error occurred while accessing the session object.
    #[error("{ERROR_PREFIX} error while accessing the session object")]
    SessionAccess(#[from] tower_sessions::session::Error),
    /// An error occurred while accessing the user object.
    #[error("{ERROR_PREFIX} error while accessing the user object")]
    UserBackend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The credentials type provided to
    /// [`GenericAuthBackend::authenticate`](backend::GenericAuthBackend::authenticate)
    /// is not supported.
    #[error("{ERROR_PREFIX} tried to authenticate with an unsupported credentials type")]
    CredentialsTypeNotSupported,
    /// The [`UserId`] type is not supported by the canonical user type.
    #[error("{ERROR_PREFIX} tried to get a user by an unsupported user ID type")]
    UserIdTypeNotSupported,
    /// The user to log in doesn't exist in the database.
    #[error("{ERROR_PREFIX} the user does not exist")]
    UserNotFound,
    /// The user to log in is not [active](canonical::CanonicalUser::is_active).
    #[error("{ERROR_PREFIX} the user is inactive")]
    UserInactive,
    /// The authentication backend the user has been authenticated with is
    /// not one of the backends of the project.
    #[error("{ERROR_PREFIX} unknown authentication backend `{0}`")]
    UnknownBackend(String),
}
impl_into_cot_error!(AuthError, UNAUTHORIZED);

impl AuthError {
    /// Creates a new [`AuthError::UserBackend`] error from a backend error.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::AuthError;
    ///
    /// let error = AuthError::backend_error(std::io::Error::new(std::io::ErrorKind::Other, "test"));
    /// ```
    pub fn backend_error(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::UserBackend(Box::new(error))
    }
}

/// The result type for authentication operations.
pub type Result<T> = std::result::Result<T, AuthError>;

/// A user ID that uniquely identifies a user in a backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UserId {
    /// A user ID that is an integer.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::UserId;
    ///
    /// let user_id = UserId::Int(42);
    /// ```
    Int(i64),
    /// A user ID that is a string.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::UserId;
    ///
    /// let user_id = UserId::String("forty_two@example.com".to_string());
    /// ```
    String(String),
}

impl UserId {
    /// Returns the user ID as an integer.
    ///
    /// Returns [`None`] if the user ID is not an integer.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::UserId;
    ///
    /// let user_id = UserId::Int(42);
    /// assert_eq!(user_id.as_int(), Some(42));
    /// ```
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(id) => Some(*id),
            Self::String(_) => None,
        }
    }

    /// Returns the user ID as a string.
    ///
    /// Returns [`None`] if the user ID is not a string.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::UserId;
    ///
    /// let user_id = UserId::String("42".to_string());
    /// assert_eq!(user_id.as_string(), Some("42"));
    /// ```
    #[must_use]
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::Int(_) => None,
            Self::String(id) => Some(id),
        }
    }
}

/// A session authentication hash.
///
/// This is used to verify that the session hash stored in the session object is
/// valid. If the session hash is not valid, the user is logged out. More
/// details can be found in the
/// [`AuthenticationBackendCommon::session_auth_hash`](backend::AuthenticationBackendCommon::session_auth_hash)
/// method.
///
/// # Security
///
/// The implementation of the [`PartialEq`] trait for this type is constant-time
/// to prevent timing attacks.
///
/// The implementation of the [`Debug`] trait for this type hides the session
/// auth hash value to prevent it from being leaked in logs or other debug
/// output.
///
/// # Examples
///
/// ```
/// use cot::auth::SessionAuthHash;
///
/// let hash = SessionAuthHash::new(&[1, 2, 3]);
/// assert_eq!(hash.as_bytes(), &[1, 2, 3]);
/// ```
#[repr(transparent)]
#[derive(Clone)]
pub struct SessionAuthHash(Box<[u8]>);

impl SessionAuthHash {
    /// Creates a new session authentication hash object from a byte slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::SessionAuthHash;
    ///
    /// let hash = SessionAuthHash::new(&[1, 2, 3, 4]);
    /// ```
    #[must_use]
    pub fn new(hash: &[u8]) -> Self {
        Self(Box::from(hash))
    }

    /// Returns the session authentication hash as a byte slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::SessionAuthHash;
    ///
    /// let hash = SessionAuthHash::new(&[1, 2, 3, 4]);
    /// assert_eq!(hash.as_bytes(), &[1, 2, 3, 4]);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the session authentication hash as a byte slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::SessionAuthHash;
    ///
    /// let hash = SessionAuthHash::new(&[1, 2, 3, 4]);
    /// assert_eq!(hash.into_bytes(), Box::from([1, 2, 3, 4]));
    /// ```
    #[must_use]
    pub fn into_bytes(self) -> Box<[u8]> {
        self.0
    }
}

impl From<&[u8]> for SessionAuthHash {
    fn from(hash: &[u8]) -> Self {
        Self::new(hash)
    }
}

impl PartialEq for SessionAuthHash {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SessionAuthHash {}

impl Debug for SessionAuthHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SessionAuthHash")
            .field(&"**********")
            .finish()
    }
}

/// A hashed password.
///
/// This is used to store a hashed user password in the database. The password
/// hash is created using the `password_auth` crate internally, so by default,
/// it generates the hash using the latest recommended algorithm.
///
/// # Security
///
/// The implementation of the [`Debug`] trait for this type hides the password
/// hash value to prevent it from being leaked in logs or other debug output.
///
/// There is no [`PartialEq`] implementation for this type, as it should never
/// be needed to compare password hashes directly. Instead, use the
/// [`verify`](Self::verify) method to verify a password against the hash.
#[repr(transparent)]
#[derive(Clone)]
pub struct PasswordHash(String);

impl PasswordHash {
    /// Creates a new password hash object from a string.
    ///
    /// Note that this method takes the hash directly and does not perform any
    /// hashing. If you need to hash a password, use the
    /// [`from_password`](Self::from_password) method instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::PasswordHash;
    /// use cot::common_types::Password;
    ///
    /// let hash = PasswordHash::from_password(&Password::new("password"));
    /// let stored_hash = hash.into_string();
    /// let hash = PasswordHash::new(stored_hash).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the password hash is invalid.
    pub fn new<T: Into<String>>(hash: T) -> Result<Self> {
        let hash = hash.into();

        if hash.len() > MAX_PASSWORD_HASH_LENGTH as usize {
            return Err(AuthError::PasswordHashInvalid);
        }
        password_auth::is_hash_obsolete(&hash).map_err(|_| AuthError::PasswordHashInvalid)?;

        Ok(Self(hash))
    }

    /// Creates a new password hash from a password.
    ///
    /// The password is hashed using the latest recommended algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::PasswordHash;
    /// use cot::common_types::Password;
    ///
    /// let hash = PasswordHash::from_password(&Password::new("password"));
    /// ```
    #[must_use]
    pub fn from_password(password: &Password) -> Self {
        let hash = password_auth::generate_hash(password.as_str());

        if hash.len() > MAX_PASSWORD_HASH_LENGTH as usize {
            unreachable!("password hash should never exceed {MAX_PASSWORD_HASH_LENGTH} bytes");
        }
        Self(hash)
    }

    /// Verifies a password against the hash.
    ///
    /// This method returns one of the following values:
    ///
    /// * [`PasswordVerificationResult::Ok`]: The password is valid.
    /// * [`PasswordVerificationResult::OkObsolete`]: The password is valid, but
    ///   the hash is obsolete. The new hash, calculated with the currently
    ///   preferred algorithm, is provided and should be saved to the database.
    /// * [`PasswordVerificationResult::Invalid`]: The password is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::{PasswordHash, PasswordVerificationResult};
    /// use cot::common_types::Password;
    ///
    /// let password = Password::new("password");
    /// let hash = PasswordHash::from_password(&password);
    ///
    /// match hash.verify(&password) {
    ///     PasswordVerificationResult::Ok => println!("Password is valid"),
    ///     PasswordVerificationResult::OkObsolete(new_hash) => println!(
    ///         "Password is valid, but the hash is obsolete. Save the new hash: {}",
    ///         new_hash.as_str()
    ///     ),
    ///     PasswordVerificationResult::Invalid => println!("Password is invalid"),
    /// }
    /// ```
    pub fn verify(&self, password: &Password) -> PasswordVerificationResult {
        const VALID_ERROR_STR: &str = "password hash should always be valid if created with `PasswordHash::new` or `PasswordHash::from_password`";

        match password_auth::verify_password(password.as_str(), &self.0) {
            Ok(()) => {
                let Ok(is_obsolete) = password_auth::is_hash_obsolete(&self.0) else {
                    unreachable!("{VALID_ERROR_STR}");
                };
                if is_obsolete {
                    PasswordVerificationResult::OkObsolete(PasswordHash::from_password(password))
                } else {
                    PasswordVerificationResult::Ok
                }
            }
            Err(error) => match error {
                VerifyError::PasswordInvalid => PasswordVerificationResult::Invalid,
                VerifyError::Parse(_) => unreachable!("{VALID_ERROR_STR}"),
            },
        }
    }

    /// Returns the password hash as a string.
    ///
    /// For security reasons, you should avoid using this method as much as
    /// possible. Typically, you should use the [`PasswordHash::verify()`]
    /// method to verify a password against the hash. This method is mostly
    /// useful for persisting the password hash externally.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::PasswordHash;
    /// use cot::common_types::Password;
    ///
    /// let hash = PasswordHash::from_password(&Password::new("password"));
    /// assert!(!hash.as_str().is_empty());
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the object and returns the password hash as a string.
    ///
    /// For security reasons, you should avoid using this method as much as
    /// possible. Typically, you should use the [`PasswordHash::verify()`]
    /// method to verify a password against the hash. This method is mostly
    /// useful for persisting the password hash externally.
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::auth::PasswordHash;
    /// use cot::common_types::Password;
    ///
    /// let hash = PasswordHash::from_password(&Password::new("password"));
    /// assert!(!hash.into_string().is_empty());
    /// ```
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl TryFrom<String> for PasswordHash {
    type Error = AuthError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// The result returned by [`PasswordHash::verify()`].
#[derive(Debug, Clone)]
#[must_use]
pub enum PasswordVerificationResult {
    /// The password is valid.
    Ok,
    /// The password is valid, but the hash is obsolete. The new hash, which was
    /// calculated with the currently preferred algorithm, is provided and
    /// should be saved to the database.
    OkObsolete(PasswordHash),
    /// The password is invalid.
    Invalid,
}

impl Debug for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PasswordHash")
            .field(&format!("{}**********", &self.0[..10]))
            .finish()
    }
}

const MAX_PASSWORD_HASH_LENGTH: u32 = 128;

#[cfg(feature = "db")]
mod db_impls {
    use super::{MAX_PASSWORD_HASH_LENGTH, PasswordHash};
    use crate::db::{
        ColumnType, DatabaseField, DbValue, FromDbValue, SqlxValueRef, TextField, ToDbValue,
    };

    impl DatabaseField for PasswordHash {
        const TYPE: ColumnType = ColumnType::String(MAX_PASSWORD_HASH_LENGTH);
    }

    impl FromDbValue for PasswordHash {
        #[cfg(feature = "sqlite")]
        fn from_sqlite(value: crate::db::impl_sqlite::SqliteValueRef<'_>) -> cot::db::Result<Self> {
            PasswordHash::new(value.get::<String>()?).map_err(cot::db::DatabaseError::value_decode)
        }

        #[cfg(feature = "postgres")]
        fn from_postgres(
            value: crate::db::impl_postgres::PostgresValueRef<'_>,
        ) -> cot::db::Result<Self> {
            PasswordHash::new(value.get::<String>()?).map_err(cot::db::DatabaseError::value_decode)
        }

        #[cfg(feature = "mysql")]
        fn from_mysql(value: crate::db::impl_mysql::MySqlValueRef<'_>) -> crate::db::Result<Self>
        where
            Self: Sized,
        {
            PasswordHash::new(value.get::<String>()?).map_err(cot::db::DatabaseError::value_decode)
        }
    }

    impl ToDbValue for PasswordHash {
        fn to_db_value(&self) -> DbValue {
            self.0.clone().into()
        }
    }

    impl FromDbValue for Option<PasswordHash> {
        #[cfg(feature = "sqlite")]
        fn from_sqlite(value: crate::db::impl_sqlite::SqliteValueRef<'_>) -> cot::db::Result<Self> {
            value
                .get::<Option<String>>()
                .map(|op_str| op_str.map(PasswordHash::new))?
                .transpose()
                .map_err(cot::db::DatabaseError::value_decode)
        }

        #[cfg(feature = "postgres")]
        fn from_postgres(
            value: crate::db::impl_postgres::PostgresValueRef<'_>,
        ) -> cot::db::Result<Self> {
            value
                .get::<Option<String>>()
                .map(|op_str| op_str.map(PasswordHash::new))?
                .transpose()
                .map_err(cot::db::DatabaseError::value_decode)
        }

        #[cfg(feature = "mysql")]
        fn from_mysql(value: crate::db::impl_mysql::MySqlValueRef<'_>) -> crate::db::Result<Self>
        where
            Self: Sized,
        {
            value
                .get::<Option<String>>()
                .map(|op_str| op_str.map(PasswordHash::new))?
                .transpose()
                .map_err(cot::db::DatabaseError::value_decode)
        }
    }

    impl ToDbValue for Option<PasswordHash> {
        fn to_db_value(&self) -> DbValue {
            match self {
                Some(hash) => hash.to_db_value(),
                None => <Option<String>>::None.to_db_value(),
            }
        }
    }

    impl TextField for PasswordHash {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn password_hash() {
        let password = Password::new("password".to_string());
        let hash = PasswordHash::from_password(&password);
        match hash.verify(&password) {
            PasswordVerificationResult::Ok => {}
            _ => panic!("Password hash verification failed"),
        }
    }

    #[test]
    fn session_auth_hash_debug() {
        let hash = SessionAuthHash::from([1, 2, 3].as_ref());
        assert_eq!(format!("{hash:?}"), "SessionAuthHash(\"**********\")");
    }

    const TEST_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$QAAI3EMU1eTLT9NzzBhQjg$khq4zuHsEyk9trGjuqMBFYnTbpqkmn0wXGxFn1nkPBc";

    #[test]
    #[cfg_attr(miri, ignore)]
    fn password_hash_debug() {
        let hash = PasswordHash::new(TEST_PASSWORD_HASH).unwrap();
        assert_eq!(
            format!("{hash:?}"),
            "PasswordHash(\"$argon2id$**********\")"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn password_hash_verify() {
        let password = Password::new("password");
        let hash = PasswordHash::from_password(&password);
        match hash.verify(&password) {
            PasswordVerificationResult::Ok => {}
            _ => panic!("Password hash verification failed"),
        }

        let wrong_password = Password::new("wrongpassword");
        match hash.verify(&wrong_password) {
            PasswordVerificationResult::Invalid => {}
            _ => panic!("Password hash verification failed"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn password_hash_str() {
        let hash = PasswordHash::new(TEST_PASSWORD_HASH).unwrap();
        assert_eq!(hash.as_str(), TEST_PASSWORD_HASH);
        assert_eq!(hash.into_string(), TEST_PASSWORD_HASH);

        let hash = PasswordHash::try_from(TEST_PASSWORD_HASH.to_string()).unwrap();
        assert_eq!(hash.as_str(), TEST_PASSWORD_HASH);
        assert_eq!(hash.into_string(), TEST_PASSWORD_HASH);
    }
}
