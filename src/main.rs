//! Run with
//!
//! ```not_rust
//! cargo run -p example-static-file-server
//! ```

use std::collections::HashMap;
use std::string::String;
use std::fs;
use std::fs::{File};
use std::io::Write;
use axum::{routing::{post, put, get}, Router, Extension, Json};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use axum::response::{Html, IntoResponse};
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
use pdf::file::{FileOptions};
use pdf::primitive::Primitive;
use serde_json::json;


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

async fn process_multipart(mut multipart: Multipart) -> Result<(String, Vec<u8>), (StatusCode, &'static str)> {
    let mut filename = String::new();
    let mut pdf_data = Vec::new();

    while let Some(field) = multipart.next_field().await.unwrap() {
        if let Some(name) = field.name() {
            if name == "file" {
                if let Some(file_name) = field.file_name() {
                    filename = file_name.to_string();
                    pdf_data = field.bytes().await.unwrap().to_vec();
                }
            }
        }
    }

    if filename.is_empty() || pdf_data.is_empty() {
        Err((StatusCode::BAD_REQUEST, "Invalid file data"))
    } else {
        Ok((filename, pdf_data))
    }
}

fn save_file(file_path: &Path, data: &[u8]) -> Result<(), (StatusCode, &'static str)> {
    match File::create(file_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(data) {
                eprintln!("Failed to write file: {}", e);
                Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to write file"))
            } else {
                Ok(())
            }
        }
        Err(e) => {
            eprintln!("Failed to create file: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to create file"))
        }
    }
}

async fn save_pdf(multipart: Multipart) -> impl IntoResponse {
    match process_multipart(multipart).await {
        Ok((filename, pdf_data)) => {
            let file_path = PathBuf::from("public/pdf").join(&filename);
            match save_file(&file_path, &pdf_data) {
                Ok(_) => (StatusCode::OK, "File saved successfully").into_response(),
                Err(e) => e.into_response(),
            }
        }
        Err(e) => e.into_response(),
    }
}

async fn save_and_update_pdf(multipart: Multipart) -> impl IntoResponse {
    match process_multipart(multipart).await {
        Ok((filename, pdf_data)) => {
            let file_path = PathBuf::from("public/pdf").join(&filename);

            if file_path.exists() {
                let backup_dir = Path::new("backup");
                if !backup_dir.exists() {
                    if let Err(e) = fs::create_dir(backup_dir) {
                        eprintln!("Failed to create backup directory: {}", e);
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create backup directory").into_response();
                    }
                }

                let base_name = filename.trim_end_matches(".pdf");
                let mut max_version = 0;
                if let Ok(entries) = fs::read_dir(backup_dir) {
                    for entry in entries.flatten() {
                        if let Some(file_name) = entry.file_name().to_str() {
                            if file_name.starts_with(base_name) && file_name.ends_with(".pdf") {
                                if let Ok(version) = file_name.trim_start_matches(base_name).trim_start_matches('_').trim_end_matches(".pdf").parse::<u32>() {
                                    if version > max_version {
                                        max_version = version;
                                    }
                                }
                            }
                        }
                    }
                }

                let new_version = max_version + 1;
                let backup_file_name = format!("{}_{}.pdf", base_name, new_version);
                let backup_path = backup_dir.join(&backup_file_name);

                if let Err(e) = fs::rename(&file_path, &backup_path) {
                    eprintln!("Failed to move existing file to backup: {}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to move existing file to backup").into_response();
                }
            }

            match save_file(&file_path, &pdf_data) {
                Ok(_) => (StatusCode::OK, "File saved successfully").into_response(),
                Err(e) => e.into_response(),
            }
        }
        Err(e) => e.into_response(),
    }
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

async fn get_annotations(axum::extract::Path(pdf_name): axum::extract::Path<String>) -> impl IntoResponse {
    let full_pdf_name = pdf_name + ".pdf";
    let file_path = PathBuf::from("public/pdf").join(&full_pdf_name);

    if !file_path.exists() {
        return (StatusCode::NOT_FOUND, "PDF file not found").into_response();
    }
    let mut annotations = HashMap::new();
    let my_pdf_file = FileOptions::uncached().open(file_path).unwrap();
    for scani in my_pdf_file.scan() {
        if let Ok(scan_item) = scani {
            if let pdf::file::ScanItem::Object(my_object, my_primitive) = scan_item
            {
                let is_annot = check_if_annot(&my_primitive);
                if is_annot {
                    let my_ultimate_dict = my_primitive.clone().into_dictionary().unwrap();
                    for (key, val) in my_ultimate_dict {
                        if key.as_str() == "Contents" {
                            if let pdf::primitive::Primitive::String(content) = val {
                                let rdfa_key = my_object.id;
                                let rdfa_string =  content.to_string().unwrap();
                                annotations.insert(rdfa_key, rdfa_string);
                            }
                        }
                    }
                }
            }
        }
    }
    Json(json!(annotations)).into_response()
}

fn check_if_annot(my_primitive: &Primitive) -> bool {
    let mut result = false;
    if let pdf::primitive::Primitive::Dictionary(dict) = my_primitive {
        for (key, val) in dict {
            if key.as_str() == "Type" {
                if let pdf::primitive::Primitive::Name(type_name) = val {
                    result = type_name == "Annot"
                }
            }
        }
    }
    return result;
}

fn using_serve_dir(tera: Arc<Tera>) -> Router {
    // Set the maximum body size to 20MB (20 * 1024 * 1024 bytes)
    let max_body_size = 20 * 1024 * 1024;
    // serve the file in the "public" directory under `/public`
    Router::new()
        .nest_service("/pdf_api", ServeDir::new("pdf_api"))
        .nest_service("/pdf_files", ServeDir::new("public"))
        .route("/pdf/:my_url_id", get(handle_request))
        .route("/pdf_viewer", get(handle_htmx))
        .route("/api/pdf", put(save_pdf))
        .route("/api/pdf", post(save_and_update_pdf))
        .route("/api/annotation/:pdf_name", get(get_annotations))
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