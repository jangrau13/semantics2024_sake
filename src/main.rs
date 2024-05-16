//! Run with
//!
//! ```not_rust
//! cargo run -p example-static-file-server
//! ```

use std::fs;
use std::fs::{File, read_dir};
use std::io::Write;
use axum::{routing::get, Router, Extension};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use axum::response::{Html, IntoResponse};
use axum::routing::post;
use tower_http::{
    services::{ServeDir},
    trace::TraceLayer,
};
use axum::{
    extract::Multipart,
    http::StatusCode,
};
use axum::extract::DefaultBodyLimit;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tera::
{
    Tera, Context,
};
use tower::ServiceBuilder;


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
        serve(using_serve_dir(shared_tera.clone()), 8000)
    );
}

async fn save_pdf(mut multipart: Multipart) -> impl IntoResponse {
    // Initialize the filename and pdf_data
    let mut filename = String::new();
    let mut pdf_data = Vec::new();

    // Process each field in the multipart form data
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        if name == "file" {
            filename = field.file_name().unwrap().to_string();
            pdf_data = field.bytes().await.unwrap().to_vec();
        }
    }

    // Ensure the filename and pdf_data are not empty
    if filename.is_empty() || pdf_data.is_empty() {
        return (StatusCode::BAD_REQUEST, "Invalid file data").into_response();
    }

    let file_path = PathBuf::from("public/pdf").join(&filename);

    if file_path.exists() {
        // Create backup directory if it doesn't exist
        let backup_dir = Path::new("backup");
        if !backup_dir.exists() {
            if let Err(e) = fs::create_dir(backup_dir) {
                eprintln!("Failed to create backup directory: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create backup directory").into_response();
            }
        }

        // Determine the new version number
        let base_name = filename.trim_end_matches(".pdf");
        let mut max_version = 0;
        if let Ok(entries) = read_dir(backup_dir) {
            for entry in entries.flatten() {
                if let Some(file_name) = entry.file_name().to_str() {
                    if file_name.starts_with(base_name) && file_name.ends_with(".pdf") {
                        if let Some(version_str) = file_name.trim_start_matches(base_name).trim_start_matches('_').trim_end_matches(".pdf").parse::<u32>().ok() {
                            if version_str > max_version {
                                max_version = version_str;
                            }
                        }
                    }
                }
            }
        }
        let new_version = max_version + 1;
        let backup_file_name = format!("{}_{}.pdf", base_name, new_version);
        let backup_path = backup_dir.join(&backup_file_name);

        // Move existing file to backup
        if let Err(e) = fs::rename(&file_path, &backup_path) {
            eprintln!("Failed to move existing file to backup: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to move existing file to backup").into_response();
        }
    }

    // Save the new file
    match File::create(&file_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&pdf_data) {
                eprintln!("Failed to write file: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to write file").into_response();
            }
        }
        Err(e) => {
            eprintln!("Failed to create file: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create file").into_response();
        }
    }

    (StatusCode::OK, "File saved successfully").into_response()
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
    // Set the maximum body size to 20MB (20 * 1024 * 1024 bytes)
    let max_body_size = 20 * 1024 * 1024;
    // serve the file in the "public" directory under `/public`
    Router::new()
        .nest_service("/pdf_api", ServeDir::new("pdf_api"))
        .nest_service("/pdf_files", ServeDir::new("public") )
        .route("/pdf/:my_url_id", get(handle_request))
        .route("/pdf_viewer", get(handle_htmx))
        .route("/api/savepdf", post(save_pdf))
        .layer(
            ServiceBuilder::new()
                .layer(DefaultBodyLimit::max(max_body_size))
                .into_inner(),
        )
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