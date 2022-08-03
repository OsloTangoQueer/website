use axum::{
    async_trait,
    extract::{Extension, Form, FromRequest, RequestParts},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get_service, post},
    Router,
};
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, Message, SmtpTransport,
    Transport,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use sailfish::TemplateOnce;
use serde::Deserialize;
use std::{io, net::SocketAddr};
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use validator::Validate;

#[derive(Deserialize)]
struct Config {
    email_username: String,
    email_password: String,
    smtp_server: String,
    smtp_port: i64,

    db_path: String,

    frontend_path: String,
}

fn read_config() -> std::io::Result<Config> {
    let content = std::fs::read_to_string("/home/intarga/otq-no/Config.toml")?;
    Ok(toml::from_str(&content)?)
}

#[derive(TemplateOnce)]
#[template(path = "response.stpl")]
struct ResponseTemplate {
    code: String,
    title: String,
    message: String,
    image_link: String,
}

async fn handle_error(err: io::Error) -> impl IntoResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(
            ResponseTemplate {
                code: "Error 500".to_string(),
                title: "Internal Server Error".to_string(),
                message: err.to_string(),
                image_link: "resources/rustacean-flat-noshadow.svg".to_string(),
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
            ResponseTemplate {
                code: "Error 500".to_string(),
                title: "Internal Server Error".to_string(),
                message: err.to_string(),
                image_link: "resources/rustacean-flat-noshadow.svg".to_string(),
            }
            .render_once()
            .unwrap_or("Uh oh... Something went really wrong".to_string()),
        ),
    )
}

fn success_response(message: &str) -> (StatusCode, Html<String>) {
    (
        StatusCode::OK,
        Html(
            ResponseTemplate {
                code: "Ok 200".to_string(),
                title: "Success!".to_string(),
                message: message.to_string(),
                image_link: "resources/rustacean-flat-happy.svg".to_string(),
            }
            .render_once()
            .unwrap_or("Uh oh... Something went really wrong".to_string()),
        ),
    )
}

fn send_subscribe_email(addr: Mailbox) -> Result<(), (StatusCode, Html<String>)> {
    let config: Config = read_config().map_err(internal_error)?;

    let email = Message::builder()
        .from(
            "Oslo Tango Queer <styret@oslotangoqueer.no>"
                .parse()
                .unwrap(),
        )
        .to(addr)
        .bcc("styret@oslotangoqueer.no".parse().map_err(internal_error)?)
        .subject("Velkommen til e-postlisten!")
        .body(String::from(""))
        .map_err(internal_error)?;

    let creds = Credentials::new(config.email_username, config.email_password);

    let mailer = SmtpTransport::relay(&config.smtp_server)
        .map_err(internal_error)?
        .port(config.smtp_port.try_into().unwrap())
        .credentials(creds)
        .build();

    mailer.send(&email).map_err(internal_error)?;

    Ok(())
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
) -> Result<(StatusCode, Html<String>), (StatusCode, Html<String>)> {
    info!("Subscribe request from {}", subscriber.email);
    subscriber.validate().map_err(internal_error)?;

    conn.execute(
        "INSERT INTO newsletter (email) VALUES (?1)",
        params![subscriber.email],
    )
    .map_err(internal_error)?;

    match subscriber.email.parse::<Mailbox>() {
        Ok(addr) => send_subscribe_email(addr)?,
        Err(err) => error!("Failed to send subscribe confirmation: {}", err),
    }

    Ok(success_response("Velkommen til e-postlisten! :)"))
}

async fn unsubscribe(
    Form(subscriber): Form<Subscriber>,
    DbConn(conn): DbConn,
) -> Result<(StatusCode, Html<String>), (StatusCode, Html<String>)> {
    conn.execute(
        "DELETE FROM newsletter WHERE email=?1",
        params![subscriber.email],
    )
    .map_err(internal_error)?;

    Ok(success_response(
        "epostadressen din er fjernet fra listen! :)",
    ))
}

#[tokio::main]
async fn main() {
    let config: Config = read_config().expect("Failed to read config file");

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "otq_no=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_journald::layer().unwrap())
        .init();

    let db_pool = Pool::new(SqliteConnectionManager::file(config.db_path))
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
        .fallback(get_service(ServeDir::new(config.frontend_path)).handle_error(handle_error))
        .layer(TraceLayer::new_for_http())
        .layer(Extension(db_pool));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
