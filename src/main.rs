use axum::{
    extract::Path,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use std::fs;

async fn list_directories() -> Html<String> {
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

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fleabox</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 40px;
            max-width: 600px;
            width: 100%;
        }}
        h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            color: #333;
            margin-bottom: 10px;
            text-align: center;
        }}
        .subtitle {{
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 0.95rem;
        }}
        .apps-list {{
            list-style: none;
        }}
        .app-item {{
            margin-bottom: 12px;
        }}
        .app-link {{
            display: block;
            padding: 16px 20px;
            background: #f8f9fa;
            border-radius: 8px;
            text-decoration: none;
            color: #333;
            font-weight: 500;
            transition: all 0.2s ease;
            border: 2px solid transparent;
        }}
        .app-link:hover {{
            background: #667eea;
            color: white;
            transform: translateX(5px);
            border-color: #667eea;
        }}
        .empty-state {{
            text-align: center;
            padding: 40px 20px;
            color: #999;
        }}
        .empty-state svg {{
            width: 64px;
            height: 64px;
            margin-bottom: 16px;
            opacity: 0.5;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🦎 Fleabox</h1>
        <p class="subtitle">Your self-hosted apps</p>
        {}
    </div>
</body>
</html>"#,
        if directories.is_empty() {
            r#"<div class="empty-state">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
            </svg>
            <p>No apps found</p>
        </div>"#.to_string()
        } else {
            format!(
                r#"<ul class="apps-list">
            {}
        </ul>"#,
                directories
                    .iter()
                    .map(|dir| format!(r#"<li class="app-item"><a href="/{}" class="app-link">{}</a></li>"#, dir, dir))
                    .collect::<Vec<_>>()
                    .join("\n            ")
            )
        }
    );

    Html(html)
}

async fn serve_app_file(Path((app, file)): Path<(String, String)>) -> Response {
    let file_path = format!("/srv/fleabox/{}/{}", app, file);
    
    match fs::read_to_string(&file_path) {
        Ok(content) => {
            let content_type = if file_path.ends_with(".html") {
                "text/html"
            } else if file_path.ends_with(".css") {
                "text/css"
            } else if file_path.ends_with(".js") {
                "application/javascript"
            } else if file_path.ends_with(".json") {
                "application/json"
            } else {
                "text/plain"
            };
            
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, content_type)],
                content,
            )
                .into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "File not found").into_response(),
    }
}

async fn serve_app_index(Path(app): Path<String>) -> Response {
    let index_path = format!("/srv/fleabox/{}/index.html", app);
    
    match fs::read_to_string(&index_path) {
        Ok(content) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/html")],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "App not found").into_response(),
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(list_directories))
        .route("/:app", get(serve_app_index))
        .route("/:app/*file", get(serve_app_file));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
