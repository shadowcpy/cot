//! The authentication middleware.

use std::fmt::Debug;
use std::marker::PhantomData;
use std::task::{Context, Poll};

use futures_core::future::BoxFuture;
use tower::Service;

use crate::Error;
use crate::auth::Auth;
use crate::auth::canonical::CanonicalUser;
use crate::request::Request;
use crate::response::Response;

/// A middleware that provides authentication functionality.
///
/// This middleware is used to authenticate requests and add the authenticated
/// user to the request extensions. This adds the [`Auth<U>`](crate::auth::Auth)
/// object to the request which can be accessed by the request handlers.
///
/// `U` must be the canonical user type of the project
/// ([`Project::User`](crate::Project::User)); otherwise, every request fails
/// with an error.
///
/// This middleware requires [`SessionMiddleware`](super::SessionMiddleware). Since each
/// [`RootHandlerBuilder::middleware`](crate::project::RootHandlerBuilder::middleware) call wraps the existing handler, register
/// `SessionMiddleware` after `AuthMiddleware` so session handling runs first.
///
/// # Examples
///
/// ```
/// use cot::middleware::{AuthMiddleware, SessionMiddleware};
/// use cot::project::{MiddlewareContext, RootHandler, RootHandlerBuilder};
/// use cot::{Project, ProjectContext};
/// # use cot::test::TestUser as MyUser;
///
/// struct MyProject;
/// impl Project for MyProject {
///     type User = MyUser;
///
///     fn middlewares(
///         &self,
///         handler: RootHandlerBuilder,
///         context: &MiddlewareContext,
///     ) -> RootHandler {
///         handler
///             .middleware(AuthMiddleware::<Self::User>::new())
///             .build()
///     }
/// }
/// ```
pub struct AuthMiddleware<U> {
    _user: PhantomData<fn() -> U>,
}

impl<U> Debug for AuthMiddleware<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthMiddleware")
            .field("user", &std::any::type_name::<U>())
            .finish()
    }
}

impl<U> AuthMiddleware<U> {
    /// Create a new [`AuthMiddleware`].
    ///
    /// # Examples
    ///
    /// ```
    /// use cot::middleware::AuthMiddleware;
    /// # use cot::test::TestUser as MyUser;
    ///
    /// let middleware = AuthMiddleware::<MyUser>::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { _user: PhantomData }
    }
}

impl<U> Clone for AuthMiddleware<U> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<U> Copy for AuthMiddleware<U> {}

impl<U> Default for AuthMiddleware<U> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, U> tower::Layer<S> for AuthMiddleware<U> {
    type Service = AuthService<S, U>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService::new(inner)
    }
}

/// Service that adds [`Auth<U>`](crate::auth::Auth) to the request.
///
/// Used by [`AuthMiddleware`].
pub struct AuthService<S, U> {
    inner: S,
    _user: PhantomData<fn() -> U>,
}

impl<S: Debug, U> Debug for AuthService<S, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService")
            .field("inner", &self.inner)
            .field("user", &std::any::type_name::<U>())
            .finish()
    }
}

impl<S, U> AuthService<S, U> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            _user: PhantomData,
        }
    }
}

impl<S: Clone, U> Clone for AuthService<S, U> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

impl<S, U> Service<Request> for AuthService<S, U>
where
    S: Service<Request, Response = Response, Error = Error> + Clone + Send + 'static,
    S::Future: Send,
    U: CanonicalUser,
{
    type Response = S::Response;
    type Error = Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        // The inner service may panic until ready, so it's important to clone
        // it here and used the version that is ready. This is a common pattern
        // when using `tower::Service`.
        //
        // https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let auth = Auth::<U>::from_request(&mut req).await?;
            req.extensions_mut().insert(auth);

            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http::Request;
    use tower::{Layer, Service, ServiceExt};

    use super::*;
    use crate::Body;
    use crate::test::{TestRequestBuilder, TestUser};

    async fn auth_database() -> crate::db::Database {
        crate::db::Database::new("sqlite::memory:").await.unwrap()
    }

    #[cot::test]
    #[cfg_attr(miri, ignore)]
    async fn auth_middleware_adds_auth() {
        let svc = tower::service_fn(|req: Request<Body>| async move {
            let auth = req
                .extensions()
                .get::<Auth<TestUser>>()
                .expect("Auth should be present");

            assert!(!auth.is_authenticated());

            Ok::<_, Error>(Response::new(Body::empty()))
        });

        let mut svc = AuthMiddleware::<TestUser>::new().layer(svc);

        let request = TestRequestBuilder::get("/")
            .with_session()
            .auth_backends::<TestUser>(auth_database().await, Vec::new())
            .build();

        svc.ready().await.unwrap().call(request).await.unwrap();
    }

    #[cot::test]
    #[cfg_attr(miri, ignore)]
    #[should_panic(
        expected = "Session extension missing. Add SessionMiddleware, and if using AuthMiddleware, register SessionMiddleware after AuthMiddleware."
    )]
    async fn auth_middleware_requires_session() {
        let svc = tower::service_fn(|_req: Request<Body>| async move {
            Ok::<_, Error>(Response::new(Body::empty()))
        });

        let mut svc = AuthMiddleware::<TestUser>::new().layer(svc);

        let request = TestRequestBuilder::get("/")
            .auth_backends::<TestUser>(auth_database().await, Vec::new())
            .build();

        // Should fail because Auth middleware requires session
        let _result = svc.ready().await.unwrap().call(request).await;
    }

    #[cot::test]
    #[cfg_attr(miri, ignore)]
    async fn auth_service_cloning() {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let svc = tower::service_fn(move |req: Request<Body>| {
            let counter = counter_clone.clone();
            async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                assert!(req.extensions().get::<Auth<TestUser>>().is_some());

                Ok::<_, Error>(Response::new(Body::empty()))
            }
        });

        let mut svc = AuthMiddleware::<TestUser>::new().layer(svc);
        let svc = svc.ready().await.unwrap();

        // Send multiple requests to test service cloning
        let database = auth_database().await;
        let request1 = TestRequestBuilder::get("/")
            .with_session()
            .auth_backends::<TestUser>(database.clone(), Vec::new())
            .build();
        let request2 = TestRequestBuilder::get("/")
            .with_session()
            .auth_backends::<TestUser>(database, Vec::new())
            .build();

        // Process requests concurrently
        let (res1, res2) = tokio::join!(svc.clone().call(request1), svc.call(request2));

        assert!(res1.is_ok());
        assert!(res2.is_ok());

        // Counter should have been incremented twice
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
