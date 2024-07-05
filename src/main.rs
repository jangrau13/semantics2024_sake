use lopdf::{dictionary, Dictionary, ObjectId};
use std::collections::HashMap;
use std::error::Error;
use std::string::String;
use std::fs::{File};
use std::io::{Cursor, Read, Write};
use axum::{routing::{get}, Router, Extension, middleware, Json};
use std::ops::Deref;
use std::path::{PathBuf};
use std::sync::Arc;
use axum::response::{Html, IntoResponse, Response};
use tower_http::{
    services::{ServeDir},
};
use axum::{
    extract::Multipart,
    http::StatusCode,
};
use axum::extract::{DefaultBodyLimit, FromRef, Host, State};
use tera::
{
    Tera, Context,
};
use tower::ServiceBuilder;
use pdf::file::{FileOptions, NoCache, NoLog};
use pdf::primitive::{Primitive};
use graph_rdfa_processor::RdfaGraph;
use sophia::api::prelude::*;
use sophia::inmem::graph::{FastGraph, LightGraph};
use sophia::turtle::parser::{turtle};
use axum::http::{HeaderMap};
use scraper::Selector;
use sophia::jsonld::{serializer::JsonLdSerializer};
use sophia::turtle::serializer::{
    nq::NqSerializer,
    trig::{TrigSerializer},
    turtle::{TurtleSerializer},
};
use sophia::xml::serializer::RdfXmlSerializer;
use atomic_lib::{Resource, Store, Storelike, Value};
use atomic_lib::agents::Agent;
use atomic_lib::values::SubResource;
use axum::body::Body;
use axum::routing::{post, put};
use lopdf::content::{Operation};
use lopdf::{Document, Object};
use reqwest::{Client, multipart};
use tokio::sync::RwLock;
use tempfile::{NamedTempFile};
use shuttle_runtime::SecretStore;
use sqlx::PgPool;
use axum_extra::extract::cookie::Key;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use serde::Serialize;

pub mod errors;
pub mod oauth;
mod decrypter;

#[derive(Clone)]
struct AtomicStruct {
    auth_header: String,
    atomic_secret_key: String,
    local_auth_header: String,
    local_atomic_secret_key: String,
}

#[derive(Clone)]
pub struct AppState {
    db: PgPool,
    ctx: Client,
    key: Key,
    wiser_key: String,
    atomic_private_key: String,
    atomic_subject: String,
    local_atomic_private_key: String,
    local_atomic_subject: String,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

#[shuttle_runtime::main]
async fn axum(
    #[shuttle_shared_db::Postgres] pool: PgPool,
    #[shuttle_runtime::Secrets] secrets: SecretStore,
) -> shuttle_axum::ShuttleAxum {
    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("Migrations failed :(");

    let manager = Arc::new(SingletonManager::new());

    let tera = match Tera::new("templates/**/*.html") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            ::std::process::exit(1);
        }
    };
    let shared_tera = Arc::new(tera);
    let auth_header_string = secrets.get("ATOMIC_AUTH_HEADER").unwrap().clone();
    let secret_key_string = secrets.get("ATOMIC_AGENT_SECRET_KEY").unwrap().clone();
    let atomic_private_key = secrets.get("ATOMIC_AGENT_PRIVATE_KEY").unwrap().clone();
    let atomic_subject = secrets.get("ATOMIC_AGENT_SUBJECT").unwrap().clone();
    let local_auth_header_string = secrets.get("LOCAL_ATOMIC_AUTH_HEADER").unwrap().clone();
    let local_secret_key_string = secrets.get("LOCAL_ATOMIC_AGENT_SECRET_KEY").unwrap().clone();
    let local_atomic_private_key = secrets.get("LOCAL_ATOMIC_AGENT_PRIVATE_KEY").unwrap().clone();
    let local_atomic_subject = secrets.get("LOCAL_ATOMIC_AGENT_SUBJECT").unwrap().clone();
    let oauth_id = secrets.get("KEYCLOAK_OAUTH_CLIENT_ID").unwrap();
    let oauth_secret = secrets.get("KEYCLOAK_OAUTH_CLIENT_SECRET").unwrap();
    let wiser_key = secrets.get("WISER_SECRET_KEY").unwrap();

    let ctx = Client::new();

    let state = AppState {
        db: pool,
        ctx,
        key: Key::generate(),
        wiser_key,
        atomic_private_key,
        atomic_subject,
        local_atomic_private_key,
        local_atomic_subject,
    };

    let oauth_client = build_oauth_client(oauth_id.clone(), oauth_secret.clone());


    // Create the AtomicStruct
    let atomic_struct = AtomicStruct {
        auth_header: auth_header_string,
        atomic_secret_key: secret_key_string,
        local_auth_header: local_auth_header_string,
        local_atomic_secret_key: local_secret_key_string,
    };

    // Wrap the AtomicStruct in an Arc
    let atomic_struct = Arc::new(atomic_struct);

    Ok(shuttle_axum::AxumService(setting_up_router(
        shared_tera.clone(),
        manager,
        atomic_struct,
        oauth_client,
        state,
        oauth_id.clone(),
    )))
}

fn build_oauth_client(client_id: String, client_secret: String) -> BasicClient {
    let redirect_url = "https://wiser-pdf-annotator.shuttleapp.rs/api/auth/wiser_callback".to_string();

    let auth_url = AuthUrl::new("https://auth.wiser.ehealth.hevs.ch/realms/wiser/protocol/openid-connect/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://auth.wiser.ehealth.hevs.ch/realms/wiser/protocol/openid-connect/token".to_string())
        .expect("Invalid token endpoint URL");

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        auth_url,
        Some(token_url),
    )
        .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
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

async fn save_pdf(
    Extension(manager): Extension<Arc<SingletonManager>>,
    Extension(atomic_struct): Extension<Arc<AtomicStruct>>,
    Host(host): Host,
    multipart: Multipart,
) -> impl IntoResponse {
    let is_localhost = host.starts_with("localhost") || host.starts_with("127.0.0.1");

    let mut atomic_secret_key = atomic_struct.atomic_secret_key.as_str();
    let mut atomic_auth_hedaer = atomic_struct.auth_header.as_str();
    if is_localhost {
        atomic_secret_key = atomic_struct.local_atomic_secret_key.as_str();
        atomic_auth_hedaer = atomic_struct.local_auth_header.as_str();
    }
    let my_atomic_store = get_local_atomic_store(manager, atomic_secret_key).await.unwrap();
    match process_multipart(multipart).await {
        Ok((filename, pdf_data)) => {
            match upload_file_to_atomic(filename, &my_atomic_store, &pdf_data, atomic_auth_hedaer, atomic_secret_key).await {
                Ok(_) => (StatusCode::OK, "File uploaded successfully").into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file").into_response(),
            }
        }
        Err(_) => (StatusCode::BAD_REQUEST, "Failed to process multipart data").into_response(),
    }
}

async fn handle_pdf_request(
    axum::extract::Path(my_pdf_file): axum::extract::Path<String>,
    Extension(manager): Extension<Arc<SingletonManager>>,
    Extension(atomic_struct): Extension<Arc<AtomicStruct>>,
    Host(host): Host
) -> impl IntoResponse {
    // Remove the .pdf suffix
    let removed_file_ending = my_pdf_file.strip_suffix(".pdf").unwrap().to_string();
    let is_localhost = host.starts_with("localhost") || host.starts_with("127.0.0.1");

    let mut atomic_secret_key = atomic_struct.atomic_secret_key.as_str();
    let mut atomic_auth_hedaer = atomic_struct.auth_header.as_str();
    if is_localhost {
        atomic_secret_key = atomic_struct.local_atomic_secret_key.as_str();
        atomic_auth_hedaer = atomic_struct.local_auth_header.as_str();
    }
    // Retrieve the atomic server
    let my_atomic_server = get_local_atomic_store(manager, atomic_secret_key).await.unwrap();

    // Get the latest file
    match get_latest_file(&removed_file_ending, &my_atomic_server, atomic_auth_hedaer, atomic_secret_key).await {
        Ok(mut file) => {
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();
            // Return the file as a response
            Response::builder()
                .header("Content-Type", "application/pdf")
                .body(Body::from(buffer))
                .unwrap()
        }
        Err(_) => {
            let buffer = create_404_pdf_content();
            // Return the generated PDF as a response
            Response::builder()
                .header("Content-Type", "application/pdf")
                .body(Body::from(buffer))
                .unwrap()
        }
    }
}

fn create_404_pdf_content() -> Vec<u8> {
    let mut doc = Document::with_version("1.5");

    let mut content = lopdf::content::Content {
        operations: vec![]
    };
    content.operations.push(Operation::new("BT", vec![]));
    content.operations.push(Operation::new("Tf", vec![Object::Name("F1".as_bytes().to_vec()), Object::Integer(32)])); // Smaller font size
    content.operations.push(Operation::new("Td", vec![Object::Integer(150), Object::Integer(750)])); // Centered text
    content.operations.push(Operation::new("Tj", vec![Object::string_literal("404 - Document Not Found")]));
    content.operations.push(Operation::new("ET", vec![]));

    content.operations.push(Operation::new("BT", vec![]));
    content.operations.push(Operation::new("Tf", vec![Object::Name("F1".as_bytes().to_vec()), Object::Integer(16)])); // Smaller font size for description
    content.operations.push(Operation::new("Td", vec![Object::Integer(100), Object::Integer(700)]));
    content.operations.push(Operation::new("Tj", vec![Object::string_literal("No PDF with this name found in the knowledge graph.")]));
    content.operations.push(Operation::new("ET", vec![]));

    let content_stream = lopdf::Stream::new(Dictionary::new(), content.encode().unwrap());
    let content_stream_id = doc.add_object(content_stream);

    let font_id = doc.add_object(
        lopdf::dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        }
    );

    let resources_id = doc.add_object(
        lopdf::dictionary! {
            "Font" => lopdf::dictionary! {
                "F1" => font_id,
            }
        }
    );

    let page_id = doc.add_object(
        lopdf::dictionary! {
            "Type" => "Page",
            "Parent" => (ObjectId::from((2,0))), // Set temporary parent, to be updated
            "Contents" => content_stream_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        }
    );

    let pages_id = doc.add_object(
        lopdf::dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        }
    );

    // Update the parent reference in the page dictionary
    if let Some(page_dict) = doc.objects.get_mut(&page_id) {
        if let lopdf::Object::Dictionary(ref mut dict) = *page_dict {
            dict.set("Parent", pages_id);
        }
    }

    let catalog_id = doc.add_object(
        lopdf::dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        }
    );

    doc.trailer.set("Root", catalog_id);

    let mut buffer = Vec::new();
    doc.save_to(&mut buffer).unwrap();
    buffer
}

async fn handle_request(
    Extension(tera): Extension<Arc<Tera>>,
    Extension(manager): Extension<Arc<SingletonManager>>,
    Extension(atomic_struct): Extension<Arc<AtomicStruct>>,
    Host(host): Host,
    axum::extract::Path(my_url_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    //hack the browser to
    let response_headers = HeaderMap::new();
    //response_headers.insert("Cache-Control", HeaderValue::from_static("no-store, no-cache, must-revalidate, proxy-revalidate"));
    //response_headers.insert("Pragma", HeaderValue::from_static("no-cache"));
    //response_headers.insert("Expires", HeaderValue::from_static("0"));
    let is_localhost = host.starts_with("localhost") || host.starts_with("127.0.0.1");

    let mut atomic_secret_key = atomic_struct.atomic_secret_key.as_str();
    let mut atomic_auth_hedaer = atomic_struct.auth_header.as_str();
    if is_localhost {
        atomic_secret_key = atomic_struct.local_atomic_secret_key.as_str();
        atomic_auth_hedaer = atomic_struct.local_auth_header.as_str();
    }
    let my_atomic_store = get_local_atomic_store(manager.clone(), atomic_secret_key).await.unwrap();
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
            let file_name = my_url_id.clone() + ".pdf";
            let file = get_latest_file(&*my_url_id, &my_atomic_store, atomic_auth_hedaer, atomic_secret_key).await.unwrap();
            match update_pdf(file, &file_name, &my_atomic_store, atomic_auth_hedaer, atomic_secret_key).await {
                Ok(updated_string) => {

                    if let Some(output) = get_annotations(&updated_string, content_type).await {
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

#[derive(Serialize)]
struct AtomicAgent {
    key: String,
    url: String,
}

async fn handle_get_my_agent(
    State(state): State<AppState>,
    Host(host): Host
) -> Json<AtomicAgent> {
    let mut key = state.atomic_private_key;
    let mut url = state.atomic_subject;
    let is_localhost = host.starts_with("localhost") || host.starts_with("127.0.0.1");

    if is_localhost {
        key = state.local_atomic_private_key;
        url = state.local_atomic_subject;
    }
    let agent = AtomicAgent {
        key,
        url,
    };
    Json(agent)
}

async fn handle_update(
    Extension(manager): Extension<Arc<SingletonManager>>,
    Extension(atomic_struct): Extension<Arc<AtomicStruct>>,
    Host(host): Host,
    axum::extract::Path(my_pdf_name): axum::extract::Path<String>,
) -> impl IntoResponse {
    let is_localhost = host.starts_with("localhost") || host.starts_with("127.0.0.1");

    let mut atomic_secret_key = atomic_struct.atomic_secret_key.as_str();
    let mut atomic_auth_hedaer = atomic_struct.auth_header.as_str();
    if is_localhost {
        atomic_secret_key = atomic_struct.local_atomic_secret_key.as_str();
        atomic_auth_hedaer = atomic_struct.local_auth_header.as_str();
    }
    let my_atomic_store = get_local_atomic_store(manager, atomic_secret_key).await.unwrap();
    let my_file = get_latest_file(&my_pdf_name, &my_atomic_store, atomic_auth_hedaer, atomic_secret_key).await.unwrap();
    match update_pdf(my_file, &my_pdf_name, &my_atomic_store, atomic_auth_hedaer, atomic_secret_key).await {
        Ok(_) => StatusCode::OK,
        Err(err) => {
            eprintln!("Error updating PDF: {}", err); // Log the error
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn get_latest_file(
    pdf_name: &str,
    my_atomic_store: &Store,
    auth_header: &str,
    atomic_secret_key: &str,
) -> Result<File, Box<dyn Error>> {
    // Get the download URL from the atomic store
    let file_names = get_latest_version(my_atomic_store, &pdf_name, atomic_secret_key);
    if let Some(file) = file_names {
        if let Ok(download_url) = file.get("https://atomicdata.dev/properties/downloadURL") {
            let url = download_url.to_string();
            // Download the PDF
            let client = Client::new();
            let response = client
                .get(url)
                .header("Authorization", format!("Bearer {}", auth_header))
                .send()
                .await
                .unwrap();
            let bytes = response.bytes().await.unwrap();

            // Create a temporary file and write the PDF bytes into it
            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(&bytes).unwrap();
            temp_file.flush().unwrap(); // Ensure all data is written

            // Reopen the file as a Tokio File
            let temp_path = temp_file.into_temp_path();
            let file = File::open(temp_path).unwrap();
            Ok(file)
        } else {
            Err("Download URL not found".into())
        }
    } else {
        Err("File not found in atomic store".into())
    }
}

struct SingletonManager {
    stores: RwLock<HashMap<String, Arc<Store>>>,
}

impl SingletonManager {
    fn new() -> Self {
        SingletonManager {
            stores: RwLock::new(HashMap::new()),
        }
    }

    async fn get_or_create_store(&self, agent: &Agent) -> Option<Arc<Store>> {
        let mut stores = self.stores.write().await;

        let subject_str = agent.subject.to_string();

        if let Some(store) = stores.get(&subject_str) {
            Some(store.clone())
        } else {
            match Store::init() {
                Ok(new_store) => {
                    let new_store = Arc::new(new_store);
                    new_store.set_default_agent(agent.clone());
                    let _test_res = new_store.fetch_resource("https://wiser-sp4.interactions.ics.unisg.ch/classes", Some(agent)).unwrap();
                    stores.insert(subject_str, new_store.clone());
                    Some(new_store)
                }
                Err(_) => None,
            }
        }
    }
}

async fn get_local_atomic_store(
    manager: Arc<SingletonManager>,
    atomic_secret_key: &str,
) -> Result<Store, String> {
    let my_atomic_agent = get_local_atomic_agent(atomic_secret_key).unwrap();

    if let Some(store) = manager.get_or_create_store(&my_atomic_agent).await {
        // Use the store
        Ok(store.deref().clone())
    } else {
        Err("Could not find the store".to_string())
    }
}

fn get_local_atomic_agent(
    atomic_secret: &str
) -> Result<Agent, String> {
    let my_atomic_agent = Agent::from_secret(
        atomic_secret
    ).map_err(|e| format!("Failed to create agent: {:?}", e)).unwrap();
    Ok(my_atomic_agent)
}


fn get_latest_version(
    my_atomic_store: &Store,
    my_pdf_name: &str,
    atomic_secret_key: &str,
) -> Option<Resource> {
    let mut filenames = Vec::new();
    let my_atomic_agent = get_local_atomic_agent(atomic_secret_key).unwrap();
    match my_atomic_store.fetch_resource(&*("https://wiser-sp4.interactions.ics.unisg.ch/collections/collection/".to_string()
        + my_pdf_name.to_string().as_str()), Some(&my_atomic_agent)) {
        Ok(files) => {
            let attachments = match files.get("https://atomicdata.dev/properties/attachments") {
                Ok(att) => att.clone(),
                Err(_) => {
                    my_atomic_store.build_index(true).unwrap();
                    my_atomic_store.populate().unwrap();
                    // It seems to be a caching problem here, so I need to fetch
                    let potential_resource_url = format!("https://wiser-sp4.interactions.ics.unisg.ch/collections/collection/{}", my_pdf_name);
                    let my_atomic_agent = get_local_atomic_agent(atomic_secret_key).unwrap();
                    let potential_resource = my_atomic_store.fetch_resource(&potential_resource_url, Some(&my_atomic_agent));
                    match potential_resource {
                        Ok(pot_resource) => {
                            pot_resource.get("https://atomicdata.dev/properties/attachments").unwrap().clone()
                        }
                        Err(_) => {
                            return None;
                        }
                    }
                }
            };
            let mut newest_version: Option<(String, String)> = None; // (timestamp, resource)

            if let Value::ResourceArray(vec_subresources) = attachments {
                for sub_res in vec_subresources {
                    if let SubResource::Subject(sub) = sub_res {
                        let final_resource = my_atomic_store.fetch_resource(&sub, Some(&my_atomic_agent)).unwrap();
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
                let latest_final_resource = my_atomic_store.fetch_resource(latest_resource, Some(&my_atomic_agent)).unwrap();
                Some(latest_final_resource)
            } else {
                None
            }
        }
        _ => None
    }
}

async fn upload_file_to_atomic(
    my_pdf_name: String,
    my_atomic_store: &Store,
    file_content: &Vec<u8>,
    auth_header: &str,
    atomic_secret_key: &str,
) -> Result<bool, String> {
    let form = multipart::Form::new()
        .part("file", multipart::Part::bytes(file_content.clone()).file_name(my_pdf_name.clone()));

    // Make the POST request to upload the file
    let client = Client::new();

    match format_and_create_if_not_exists(&my_pdf_name, my_atomic_store, atomic_secret_key) {
        None => {
            Err("formatting did not work".to_string())
        }
        Some(parent) => {
            let response = client.post("https://wiser-sp4.interactions.ics.unisg.ch/upload?parent=".to_owned() + parent.as_str())
                .multipart(form)
                .header("Authorization", format!("Bearer {}", auth_header)) // replace with actual token
                .send()
                .await.unwrap();

            // Check the response
            if response.status().is_success() {
                //println!("File uploaded successfully");
                return Ok(true);
            } else {
                let error_text = response.text().await.unwrap();
                println!("Failed to upload file: {}", error_text);
                return Err(error_text);
            }
        }
    }
}

fn format_and_create_if_not_exists(
    my_pdf_name: &str,
    my_atomic_store: &Store,
    atomic_secret_key: &str,
) -> Option<String> {
    let my_atomic_agent = get_local_atomic_agent(atomic_secret_key).unwrap();
    let formatted_name = if my_pdf_name.ends_with(".pdf") {
        &my_pdf_name[..my_pdf_name.len() - 4] // Remove the ".pdf" extension
    } else {
        my_pdf_name
    };
    let parent = "https://wiser-sp4.interactions.ics.unisg.ch/collections/collection/".to_string() + formatted_name;
    match my_atomic_store.fetch_resource(&parent, Some(&my_atomic_agent)) {
        Ok(_) => {
            Some(parent)
        }
        Err(_) => {
            let mut new_resource = Resource::new(parent.clone());
            new_resource.set_string("https://atomicdata.dev/properties/name".to_string(), &formatted_name, my_atomic_store).unwrap();
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

async fn update_pdf(
    pdf: File,
    pdf_name: &str,
    my_atomic_store: &Store,
    auth_header: &str,
    atomic_secret_key: &str,
) -> Result<Vec<u8>, String> {
    let my_atomic_agent = get_local_atomic_agent(atomic_secret_key).unwrap();
    let mut doc = lopdf::Document::load_from(pdf).map_err(|e| format!("Failed to load PDF: {:?}", e))?;
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
                            match my_atomic_store.fetch_resource(subject, Some(&my_atomic_agent)) {
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
    let mut file_contents = Vec::new();
    doc.save_to(&mut file_contents).unwrap();
    upload_file_to_atomic(pdf_name.to_string(), my_atomic_store, &file_contents, auth_header, atomic_secret_key).await.expect("TODO: panic message");
    Ok(file_contents)
}

async fn get_annotations(file_contents: &Vec<u8>, serializer_name: &str) -> Option<String> {
    let file_option = FileOptions::uncached();
    let my_pdf_file = file_option.load(file_contents.as_slice()).unwrap();
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
                                let base = "https://wiser-pdf-annotator.shuttleapp.rs";
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

fn setting_up_router(
    tera: Arc<Tera>,
    store_manager: Arc<SingletonManager>,
    atomic_struct: Arc<AtomicStruct>,
    oauth_client: BasicClient,
    state: AppState,
    oauth_id: String,
) -> Router {
    let auth_router = Router::new().route("/auth/wiser_callback", get(oauth::wiser_callback));

    let max_body_size = 20 * 1024 * 1024;

    let unprotected_router = Router::new()
        .route("/", get(homepage_handler))
        .layer(Extension(tera.clone()))
        .layer(Extension(oauth_id));

    let protected_router = Router::new()
        .nest_service("/pdf_api", ServeDir::new("pdf_api"))
        .nest_service("/pdf_files/pdf/:my_pdf_file", get(handle_pdf_request))
        .route("/pdf/:my_url_id", get(handle_request))
        .route("/pdf_viewer", get(handle_htmx))
        .route("/pdf", put(save_pdf))
        .route("/pdf", post(save_pdf))
        .route("/upload", post(save_pdf))
        .route("/get_my_agent", get(handle_get_my_agent))
        .route("/update/:my_pdf_name", get(handle_update))
        .layer(
            ServiceBuilder::new()
                .layer(DefaultBodyLimit::max(max_body_size))
                .into_inner(),
        )
        .layer(Extension(tera))
        .layer(Extension(store_manager))
        .layer(Extension(atomic_struct))
        .route_layer(middleware::from_fn_with_state(state.clone(), oauth::check_authenticated));

    Router::new()
        .nest("/api", auth_router)
        .nest("/", unprotected_router)
        .nest("/v1/api", protected_router)
        .layer(Extension(oauth_client))
        .with_state(state)
}

async fn homepage_handler(
    Extension(oauth_id): Extension<String>,
    Host(host): Host,
) -> Html<String> {
    let is_localhost = host.starts_with("localhost") || host.starts_with("127.0.0.1");

    if is_localhost {
        Html(format!(
            r#"
            <p>Welcome, localhost user!</p>
            <a href="http://localhost:8080/login">
                Login (Local)
            </a>
        "#
        ))
    } else {
        Html(format!(
            r#"
        <p>Welcome!</p>
        <a href="https://auth.wiser.ehealth.hevs.ch/realms/wiser/protocol/openid-connect/auth?scope=openid%20profile%20email&client_id={oauth_id}&response_type=code&redirect_uri=https://wiser-pdf-annotator.shuttleapp.rs/api/auth/wiser_callback">
            Login with Keycloak
        </a>

    "#
        ))
    }
}
