use axum::{
    response::Json,
    routing::get,
    Router,
};
use serde::Serialize;
use std::fs;

#[derive(Serialize)]
struct DirectoryList {
    directories: Vec<String>,
}

async fn list_directories() -> Json<DirectoryList> {
    let path = "/srv/fleabox";
    let mut directories = Vec::new();

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        directories.push(name.to_string());
                    }
                }
            }
        }
    }

    directories.sort();
    Json(DirectoryList { directories })
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(list_directories));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
