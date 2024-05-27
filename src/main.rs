//! Run with
//!
//! ```not_rust
//! cargo run -p example-static-file-server
//! ```

use std::error::Error;
use std::string::String;
use std::fs;
use std::fs::{File};
use std::io::{Read, Write};
use axum::{routing::{post, put, get}, Router, Extension};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use axum::response::{Html, IntoResponse, Response};
use tower_http::{
    services::{ServeDir},
    trace::TraceLayer,
};
use axum::{
    extract::Multipart,
    http::StatusCode,
};
use axum::extract::{DefaultBodyLimit};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tera::
{
    Tera, Context,
};
use tower::ServiceBuilder;
use pdf::file::{FileOptions};
use pdf::primitive::{Primitive};
use graph_rdfa_processor::RdfaGraph;
use sophia::api::prelude::*;
use sophia::inmem::graph::{FastGraph, LightGraph};
use sophia::turtle::parser::{turtle};
use axum::http::{HeaderMap, HeaderValue};
use scraper::Selector;
use sophia::jsonld::{serializer::JsonLdSerializer};
use sophia::turtle::serializer::{
    nq::NqSerializer,
    trig::{TrigSerializer},
    turtle::{TurtleSerializer},
};
use sophia::xml::serializer::RdfXmlSerializer;
use atomic_lib::{Resource, Store, Storelike, Value};
use atomic_lib::errors::AtomicResult;
use atomic_lib::values::SubResource;
use reqwest::{Client, multipart};


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

async fn handle_request(
    Extension(tera): Extension<Arc<Tera>>,
    axum::extract::Path(my_url_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut response_headers = HeaderMap::new();
    response_headers.insert("Cache-Control", HeaderValue::from_static("no-store, no-cache, must-revalidate, proxy-revalidate"));
    response_headers.insert("Pragma", HeaderValue::from_static("no-cache"));
    response_headers.insert("Expires", HeaderValue::from_static("0"));

    match headers.get(axum::http::header::CONTENT_TYPE).and_then(|ct| ct.to_str().ok()) {
        Some(content_type) if matches!(
            content_type,
            "text/turtle"
                | "application/trig"
                | "application/n-quads"
                | "application/rdf+xml"
                | "application/ld+json"
        ) => {
            // we need to update the PDF according to the Atomic SST first
            match update_pdf(&my_url_id).await {
                Ok(_) => {
                    if let Some(output) = get_annotations(&my_url_id, content_type).await {
                        (response_headers, output.into_response())
                    } else {
                        let mut context = Context::new();
                        context.insert("myID", &my_url_id);
                        let html_response = Html(tera.render("index.html", &context).expect("Failed to render template")).into_response();
                        (response_headers, html_response)
                    }
                }
                Err(err) => {
                    eprintln!("Error updating PDF: {}", err); // Log the error
                    (HeaderMap::new(), Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(err.into()).unwrap())
                }
            }
        }
        _ => {
            let mut context = Context::new();
            context.insert("myID", &my_url_id);
            let html_response = Html(tera.render("index.html", &context).expect("Failed to render template")).into_response();
            (response_headers, html_response)
        }
    }
}

async fn handle_htmx(Extension(tera): Extension<Arc<Tera>>,
) -> Html<String> {
    let context = Context::new();
    Html(tera.render("viewer_fragment.html", &context).expect("Failed to render template"))
}

async fn handle_update(axum::extract::Path(my_pdf_name): axum::extract::Path<String>) -> impl IntoResponse {
    match update_pdf(&my_pdf_name).await {
        Ok(_) => StatusCode::OK,
        Err(err) => {
            eprintln!("Error updating PDF: {}", err); // Log the error
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn get_latest_file_handle(axum::extract::Path(my_pdf_name): axum::extract::Path<String>) -> Result<File, Box<dyn std::error::Error>> {
    let pdf_name = my_pdf_name;
    get_latest_file(&pdf_name).await
}

async fn get_latest_file(pdf_name: &str) -> Result<File, Box<dyn Error>> {

    let my_atomic_store = get_local_atomic_store()?;

    // Get the file name and path
    let full_pdf_name = pdf_name.to_owned() + ".pdf";
    let file_path = PathBuf::from("public/pdf").join(&full_pdf_name);

    // Get the download URL from the atomic store
    let file_names = get_latest_version(my_atomic_store, &pdf_name);
    if let Some(file) = file_names {
        if let Ok(download_url) = file.get("https://atomicdata.dev/properties/downloadURL") {
            let url = download_url.to_string();

            // Download the PDF
            let client = Client::new();
            let response = client.get(url).send().await.unwrap();
            let bytes = response.bytes().await.unwrap();

            // Save the PDF to the buffer
            let mut file = File::create(&file_path).unwrap();
            file.write_all(&bytes).unwrap();

            return Ok(file)
        } else {
            Err("Download URL not found".into())
        }
    } else {
        Err("File not found in atomic store".into())
    }
}

fn get_local_atomic_store() -> Result<Store, Box<dyn Error>> {
    let my_atomic_agent = atomic_lib::agents::Agent::from_private_key_and_subject(
        "rEdi8xEOMiTQPsNKa9cHr5GoNDMJ5hcUlm9WHKDaKUc=",
        "https://wiser-sp4.interactions.ics.unisg.ch/agents/KA+r8Uki9vD3dE/KNxR7exHG9ZEloH9nXP4vNjO3RMo=",
    ).map_err(|e| format!("Failed to create agent: {:?}", e))?;

    // Initialize and populate the store
    let my_atomic_store = Store::init().map_err(|e| format!("Failed to initialize store: {:?}", e))?;
    my_atomic_store.populate().map_err(|e| format!("Failed to populate store: {:?}", e))?;
    my_atomic_store.set_default_agent(my_atomic_agent.clone());
    Ok(my_atomic_store)
}

fn get_latest_version(my_atomic_store: Store, my_pdf_name: &str) -> Option<Resource> {
    let mut filenames = Vec::new();
    let files = my_atomic_store.get_resource(&*("https://wiser-sp4.interactions.ics.unisg.ch/collections/collection/".to_string()
        + my_pdf_name.to_string().as_str())).unwrap();
    let attachments = files.get("https://atomicdata.dev/properties/attachments").unwrap();

    let mut newest_version: Option<(String, String)> = None; // (timestamp, resource)

    if let Value::ResourceArray(vec_subresources) = attachments {
        for sub_res in vec_subresources {
            if let SubResource::Subject(sub) = sub_res {
                let final_resource = my_atomic_store.get_resource(sub).unwrap();
                let file_name = final_resource.get("https://atomicdata.dev/properties/internalId").unwrap();
                let file_name_str = file_name.to_string();
                filenames.push(file_name_str.clone());

                // Extract timestamp from the internal ID
                if let Some((timestamp_str, _)) = file_name_str.split_once('-') {
                    if let Ok(timestamp) = timestamp_str.parse::<u64>() {
                        if newest_version.is_none() || timestamp > newest_version.as_ref().unwrap().0.parse::<u64>().unwrap() {
                            newest_version = Some((timestamp_str.to_string(), sub.to_string()));
                        }
                    }
                }
            }
        }
    }

    if let Some((_, latest_resource)) = &newest_version {
        let latest_final_resource = my_atomic_store.get_resource(latest_resource).unwrap();
        Some(latest_final_resource)
    } else {
        None
    }
}


async fn upload_pdf_to_atomic(axum::extract::Path(my_pdf_name): axum::extract::Path<String>) -> () {
    //TODO: make this work with Atomic, so that everything runs with Atomic then.
    let my_atomic_store = get_local_atomic_store();
    let full_pdf_name = my_pdf_name.to_owned() + ".pdf";
    let file_path = PathBuf::from("public/pdf").join(&full_pdf_name);

    if !file_path.exists() {
        return;
    }
    let mut file = File::open(&file_path).unwrap();
    let mut file_content = Vec::new();
    file.read_to_end(&mut file_content).unwrap();

    // Create a multipart form
    let form = multipart::Form::new()
        .part("file", multipart::Part::bytes(file_content).file_name(full_pdf_name));

    // Make the POST request to upload the file
    let client = reqwest::Client::new();

    match format_and_create_if_not_exists(my_pdf_name, &my_atomic_store) {
        None => {
            println!("formatting did not work")
        }
        Some(parent) => {
            let auth_header = "eyJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9hZ2VudCI6Imh0dHBzOi8vd2lzZXItc3A0LmludGVyYWN0aW9ucy5pY3MudW5pc2cuY2gvYWdlbnRzL0tBK3I4VWtpOXZEM2RFL0tOeFI3ZXhIRzlaRWxvSDluWFA0dk5qTzNSTW89IiwiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvcmVxdWVzdGVkU3ViamVjdCI6Imh0dHBzOi8vd2lzZXItc3A0LmludGVyYWN0aW9ucy5pY3MudW5pc2cuY2giLCJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9wdWJsaWNLZXkiOiJLQStyOFVraTl2RDNkRS9LTnhSN2V4SEc5WkVsb0g5blhQNHZOak8zUk1vPSIsImh0dHBzOi8vYXRvbWljZGF0YS5kZXYvcHJvcGVydGllcy9hdXRoL3RpbWVzdGFtcCI6MTcxNjgwNzc5NzQxOCwiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvc2lnbmF0dXJlIjoiZzJFdXNWU2U4T0FpQ2tQOEQ5TENGOVU0L2d1dnFOajB3SXRzdW1MVm04Rm5LN0s2dXRZU1pFc3Z0clo4Z2YzM3BnMitzSDBENkthcis4cXZWVkptQ1E9PSJ9";
            let response = client.post("https://wiser-sp4.interactions.ics.unisg.ch/upload?parent=".to_owned() + parent.as_str())
                .multipart(form)
                .header("Authorization", format!("Bearer {}", auth_header)) // replace with actual token
                .send()
                .await.unwrap();

            // Check the response
            if response.status().is_success() {
                println!("File uploaded successfully");
                return;
            } else {
                let error_text = response.text().await.unwrap();
                println!("Failed to upload file: {}", error_text);
            }
        }
    }
}

fn format_and_create_if_not_exists(my_pdf_name: String, my_atomic_store: &Store) -> Option<String> {
    let parent = "https://wiser-sp4.interactions.ics.unisg.ch/collections/collection/".to_string() + my_pdf_name.as_str();
    match my_atomic_store.get_resource(&parent) {
        Ok(_) => {
            Some(parent)
        }
        Err(_) => {
            let mut new_resource = Resource::new(parent.clone());
            new_resource.set_string("https://atomicdata.dev/properties/name".to_string(), &my_pdf_name, my_atomic_store).unwrap();
            new_resource.set_string("https://atomicdata.dev/properties/parent".to_string(),
                                    "https://wiser-sp4.interactions.ics.unisg.ch/collections/collection/wiser-collection",
                                    my_atomic_store).unwrap();
            match new_resource.check_required_props(my_atomic_store) {
                Ok(_) => {
                    match new_resource.save(my_atomic_store) {
                        Ok(_) => {
                            Some(parent)
                        }
                        Err(err) => {
                            eprintln!("creating parent did not work {:?}", err);
                            None
                        }
                    }
                }
                Err(err) => {
                    eprintln!("requried check: {}", err);
                    None
                }
            }
        }
    }
}

async fn update_pdf(pdf_name: &str) -> Result<bool, String> {

    if let Ok(file) = get_latest_file(pdf_name.clone()){
        // only go for it if
        let my_atomic_store = get_local_atomic_store()?;
        match my_atomic_store.get_resource("https://wiser-sp4.interactions.ics.unisg.ch/property/wiser-id") {
            Ok(_res) => {
                let mut doc = lopdf::Document::load_from(file).map_err(|e| format!("Failed to load PDF: {:?}", e))?;
                let mut delete_me = Vec::new();
                for (id, object) in &doc.objects {
                    if let lopdf::Object::Dictionary(ref obj_dict) = object {
                        for (_key, value) in obj_dict.as_hashmap() {
                            if let lopdf::Object::String(content, _format) = value {
                                let my_content = String::from_utf8_lossy(content).to_string();
                                let html_content = scraper::Html::parse_fragment(&my_content);
                                let selector = Selector::parse("[data-wiser-subject]").map_err(|e| format!("Failed to parse selector: {:?}", e))?;
                                for element in html_content.select(&selector) {
                                    // Extract the value of the `data-wiser-subject` attribute
                                    if let Some(subject) = element.value().attr("data-wiser-subject") {
                                        match my_atomic_store.get_resource(subject) {
                                            Ok(_res) => (),
                                            Err(_err) => {
                                                // TODO: check if the error really should delete the stuff
                                                //println!("atomic error: {:?}", _err);
                                                delete_me.push(id.clone())
                                            }
                                        }
                                    }
                                }
                                let selector = Selector::parse("[data-wiser-potential-subject]").map_err(|e| format!("Failed to parse selector: {:?}", e))?;
                                for element in html_content.select(&selector) {
                                    // Extract the value of the `data-wiser-subject` attribute
                                    if let Some(_subject) = element.value().attr("data-wiser-potential-subject") {
                                        //println!("deleting {}",_subject);
                                        delete_me.push(id.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                for delete_id in delete_me {
                    //println!("deleting {}", delete_id.0);
                    doc.delete_object(delete_id);
                }
                //doc.save(&file_path).map_err(|e| format!("Failed to save PDF: {:?}", e))?;

                Ok(true)
            }
            Err(err) => {
                // TODO: check if the error really should delete the stuff
                //println!("atomic error: {:?}", err);
                Err(format!("KG is not available: {:?}", err))
            }
        }
    }
    // Only update if you can fetch wiser-id
}


async fn get_annotations(pdf_name: &str, serializer_name: &str) -> Option<String> {
    let full_pdf_name = pdf_name.to_owned() + ".pdf";
    let file_path = PathBuf::from("public/pdf").join(&full_pdf_name);

    if !file_path.exists() {
        return None;
    }
    let my_pdf_file = FileOptions::uncached().open(file_path).unwrap();
    let mut main_graph_from_pdf = FastGraph::new();
    for pdf_scan_result in my_pdf_file.scan() {
        if let Ok(scan_item) = pdf_scan_result {
            if let pdf::file::ScanItem::Object(my_object, my_primitive) = scan_item {
                let is_annot = check_if_annot(&my_primitive);
                if is_annot {
                    let my_ultimate_dict = my_primitive.clone().into_dictionary().unwrap();
                    for (key, val) in my_ultimate_dict {
                        if key.as_str() == "Contents" {
                            if let pdf::primitive::Primitive::String(content) = val {
                                let _rdfa_key = my_object.id;
                                let rdfa_string = content.to_string().unwrap();
                                let base = "http://localhost:8000";
                                let rdfa_content = RdfaGraph::parse_str(&rdfa_string, base, None).unwrap();
                                let inner_graph: LightGraph = turtle::parse_str(&rdfa_content).collect_triples().unwrap();
                                main_graph_from_pdf.insert_all(inner_graph.triples()).expect("Insertion of Graph did not work");
                            }
                        }
                    }
                }
            }
        }
    }

    // Determine the serializer based on the provided parameter
    let serialized_output = match serializer_name {
        "text/turtle" => {
            let mut serializer = TurtleSerializer::new_stringifier();
            serializer.serialize_graph(&main_graph_from_pdf).unwrap().to_string()
        }
        "application/trig" => {
            let mut serializer = TrigSerializer::new_stringifier();
            serializer.serialize_dataset(&main_graph_from_pdf.as_dataset()).unwrap().to_string()
        }
        "application/n-quads" => {
            let mut serializer = NqSerializer::new_stringifier();
            serializer.serialize_dataset(&main_graph_from_pdf.as_dataset()).unwrap().to_string()
        }
        "application/rdf+xml" => {
            {
                let mut serializer = RdfXmlSerializer::new_stringifier();
                serializer.serialize_graph(&main_graph_from_pdf).unwrap().to_string()
            }
        }
        "application/ld+json" => {
            let mut serializer = JsonLdSerializer::new_stringifier();
            serializer.serialize_dataset(&main_graph_from_pdf.as_dataset()).unwrap().to_string()
        }
        _ => return None,
    };

    Some(serialized_output)
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
        .route("/api/update/:my_pdf_name", get(handle_update))
        .route("/api/upload/:my_pdf_name", get(upload_pdf_to_atomic))
        .route("/api/download/:my_pdf_name", get(get_latest_file_handle))
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