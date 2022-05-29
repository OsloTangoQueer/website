use axum::{
    extract::Extension,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, get_service},
    Router,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use std::{io, net::SocketAddr};
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::debug;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

async fn handle_error(_err: io::Error) -> impl IntoResponse {
    (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong...")
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "otq_no=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_pool = Pool::new(SqliteConnectionManager::file("otq.db"))
        .expect("failed to create DB connection pool");
    db_pool
        .get()
        .expect("failed to get DB connection")
        .execute(
            "CREATE TABLE IF NOT EXISTS newsletter (email text)",
            params![],
        )
        .expect("failed to create newsletter table");

    let app = Router::new()
        .route("/foo", get(|| async { "Hi from /foo" }))
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
