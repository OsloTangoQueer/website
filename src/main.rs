use axum::{
    async_trait,
    extract::{Extension, Form, FromRequest, RequestParts},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get_service, post},
    Router,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use sailfish::TemplateOnce;
use serde::Deserialize;
use std::{io, net::SocketAddr};
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::debug;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use validator::Validate;

#[derive(TemplateOnce)]
#[template(path = "500.stpl")]
struct Error500Template {
    message: String,
}

async fn handle_error(_err: io::Error) -> impl IntoResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(
            Error500Template {
                message: "Something went wrong...".to_string(),
            }
            .render_once()
            .unwrap_or("Uh oh... Something went really wrong".to_string()),
        ),
    )
}

fn internal_error<E>(err: E) -> (StatusCode, Html<String>)
where
    E: std::error::Error,
{
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(
            Error500Template {
                message: err.to_string(),
            }
            .render_once()
            .unwrap_or("Uh oh... Something went really wrong".to_string()),
        ),
    )
}

struct DbConn(r2d2::PooledConnection<SqliteConnectionManager>);

#[async_trait]
impl<B> FromRequest<B> for DbConn
where
    B: Send,
{
    type Rejection = (StatusCode, Html<String>);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(pool) = Extension::<Pool<SqliteConnectionManager>>::from_request(req)
            .await
            .map_err(internal_error)?;

        let conn = pool.get().map_err(internal_error)?;

        Ok(Self(conn))
    }
}

#[derive(Validate, Deserialize)]
struct Subscriber {
    #[validate(email)]
    email: String,
}

async fn subscribe(
    Form(subscriber): Form<Subscriber>,
    DbConn(conn): DbConn,
) -> Result<String, (StatusCode, Html<String>)> {
    subscriber.validate().map_err(internal_error)?;

    conn.execute(
        "INSERT INTO newsletter (email) VALUES (?1)",
        params![subscriber.email],
    )
    .map_err(internal_error)?;

    Ok("ok".to_string())
}

async fn unsubscribe(
    Form(subscriber): Form<Subscriber>,
    DbConn(conn): DbConn,
) -> Result<String, (StatusCode, Html<String>)> {
    conn.execute(
        "DELETE FROM newsletter WHERE email=?1",
        params![subscriber.email],
    )
    .map_err(internal_error)?;

    Ok("ok".to_string())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "otq_no=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_journald::layer().unwrap())
        .init();

    let db_pool = Pool::new(SqliteConnectionManager::file("otq.db"))
        .expect("failed to create DB connection pool");
    db_pool
        .get()
        .expect("failed to get DB connection")
        .execute(
            "CREATE TABLE IF NOT EXISTS newsletter (email text UNIQUE)",
            params![],
        )
        .expect("failed to create newsletter table");

    let app = Router::new()
        .route("/subscribe", post(subscribe))
        .route("/unsubscribe", post(unsubscribe))
        .fallback(get_service(ServeDir::new("./frontend")).handle_error(handle_error))
        .layer(TraceLayer::new_for_http())
        .layer(Extension(db_pool));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
