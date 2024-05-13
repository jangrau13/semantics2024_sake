//! Run with
//!
//! ```not_rust
//! cargo run -p example-static-file-server
//! ```

use axum::{routing::get, Router, Extension};
use std::net::SocketAddr;
use std::sync::Arc;
use axum::response::Html;
use tower_http::{
    services::{ServeDir},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tera::
{
    Tera, Context,
};


#[tokio::main]
async fn main() {
    let tera = match Tera::new("templates/**/*.html") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            ::std::process::exit(1);
        }
    };
    let shared_tera = Arc::new(tera);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "example_static_file_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tokio::join!(
        serve(using_serve_dir(shared_tera.clone()), 3001)
    );
}

async fn handle_request(Extension(tera): Extension<Arc<Tera>>,
                        axum::extract::Path(my_url_id): axum::extract::Path<String>,
) -> Html<String> {
    let mut context = Context::new();
    context.insert("myID", &my_url_id);
    Html(tera.render("index.html", &context).expect("Failed to render template"))
}

async fn handle_htmx(Extension(tera): Extension<Arc<Tera>>,
) -> Html<String> {
    let context = Context::new();
    Html(tera.render("viewer_fragment.html", &context).expect("Failed to render template"))
}

fn using_serve_dir(tera: Arc<Tera>) -> Router {
    // serve the file in the "public" directory under `/public`
    Router::new()
        .nest_service("/pdf_api", ServeDir::new("pdf_api"))
        .nest_service("/pdf_files", ServeDir::new("public") )
        .route("/pdf/:my_url_id", get(handle_request))
        .route("/pdf_viewer", get(handle_htmx))
        .layer(Extension(tera))
}

async fn serve(app: Router, port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app.layer(TraceLayer::new_for_http()))
        .await
        .unwrap();
}