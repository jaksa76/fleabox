use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use std::{fs, path::Path as StdPath};

pub(crate) async fn homepage(State(state): State<AppState>) -> Html<String> {
    let path = &state.apps_dir;
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
        * {{box-sizing: border-box; margin: 0; padding: 0;}}
        html,body {{height: 100%;}}
        body {{
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
            background: radial-gradient(1200px 600px at 10% 10%, rgba(156,163,175,0.04), transparent),
                        linear-gradient(180deg, #090912 0%, #0f1724 100%);
            color: #e6eef8c4;
            -webkit-font-smoothing:antialiased;
            -moz-osx-font-smoothing:grayscale;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 48px 24px 88px;
        }}
        .apps {{
            display: flex;
            flex-direction: column;
            gap: 18px;
            align-items: center;
            text-align: center;
        }}
        .apps a {{
            color: inherit;
            text-decoration: none;
            font-size: 3.2rem;
            font-weight: 100;
            letter-spacing: -0.02em;
            padding: 8px 16px;
            transition: transform 220ms cubic-bezier(.2,.9,.2,1), color 180ms ease, text-shadow 220ms ease;
            will-change: transform;
        }}
        .apps a:hover {{
            transform: scale(1.08);
            color: #ffffff;
            text-shadow: 0 6px 24px rgba(125,211,252,0.06);
        }}
        .empty {{
            color: #9aa4b2;
            font-size: 1rem;
            letter-spacing: 0.02em;
        }}
        .footer {{
            position: fixed;
            left: 0; right: 0;
            bottom: 12px;
            display: flex;
            justify-content: center;
            pointer-events: none;
        }}
        .footer .meta {{
            color: #728096;
            font-size: 0.82rem;
            background: rgba(255,255,255,0.02);
            padding: 6px 10px;
            border-radius: 999px;
            pointer-events: auto;
            backdrop-filter: blur(4px);
        }}
    </style>
</head>
<body>
    <main class="apps">
        {}
    </main>
    <div class="footer"><div class="meta">fleabox {}</div></div>
</body>
</html>"#,
        if directories.is_empty() {
            r#"<div class="empty">No apps found</div>"#.to_string()
        } else {
            directories
                .iter()
                .map(|dir| format!(r#"<a href="/{}/">{}</a>"#, dir, dir))
                .collect::<Vec<_>>()
                .join("\n        ")
        },
        env!("CARGO_PKG_VERSION")
    );

    Html(html)
}

pub(crate) async fn serve_app_file(
    State(state): State<AppState>,
    Path((app, file)): Path<(String, String)>,
    _jar: CookieJar,
) -> Response {
    // For now, allow access to static files without token validation
    // since they're just HTML/CSS/JS that gets loaded initially
    let file_path = format!("{}/{}/{}", state.apps_dir, app, file);

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

pub(crate) async fn serve_app_index(
    State(state): State<AppState>,
    Path(app): Path<String>,
) -> Response {
    // Handle requests ending with '/' by trying index.html or index.htm
    let index_path = if app.ends_with('/') {
        let app_name = app.trim_end_matches('/');
        let html_path = format!("{}/{}/index.html", state.apps_dir, app_name);
        let htm_path = format!("{}/{}/index.htm", state.apps_dir, app_name);

        if StdPath::new(&html_path).exists() {
            html_path
        } else if StdPath::new(&htm_path).exists() {
            htm_path
        } else {
            html_path // Try html by default for error message
        }
    } else {
        format!("{}/{}/index.html", state.apps_dir, app)
    };

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

pub(crate) async fn redirect_to_app(Path(app): Path<String>) -> impl IntoResponse {
    axum::response::Redirect::to(&format!("/{}/", app))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_redirect_to_app() {
        let response = redirect_to_app(Path("myapp".to_string())).await.into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        
        let location = response.headers().get("location").unwrap();
        assert_eq!(location, "/myapp/");
    }
}
