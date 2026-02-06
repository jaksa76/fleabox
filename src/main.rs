mod auth;
mod cli;
mod error;
mod fs_utils;
mod private_data;
mod public_data;
mod static_pages;
mod user;

use crate::auth::AuthType;
use axum::{
    Router, middleware,
    routing::{delete, get, post, put},
};
use rsa::RsaPrivateKey;
use std::sync::RwLock;
use std::{collections::HashMap, env, sync::Arc};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) token_store: auth::TokenStore,
    pub(crate) apps_dir: String,
    pub(crate) rsa_private_key: Arc<RsaPrivateKey>,
    pub(crate) auth_type: AuthType,
    pub(crate) config: Option<Arc<cli::Config>>,
    pub(crate) dev_mode: bool,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let dev_mode = args.contains(&"--dev".to_string());

    if args.contains(&"--help".to_string()) {
        println!("fleabox - self-hosted app server");
        println!(
            "Usage: fleabox [--dev] [--apps-dir <dir>] [--port <port>] [--auth <type>] [--config <file>]"
        );
        println!();
        println!("Options:");
        println!("  --dev            Run in development mode (uses current user)");
        println!("  --apps-dir DIR   Path to apps directory (default: /srv/fleabox)");
        println!("  --port PORT      Port to listen on (default: 3000)");
        println!("  --auth TYPE      Authentication type: pam, config, or none (default: pam)");
        println!("                   - pam: Use system PAM authentication");
        println!("                   - config: Use config file with username/password");
        println!("                   - none: Use X-Remote-User header from reverse proxy");
        println!("  --config FILE    Path to config file (required for --auth config)");
        std::process::exit(0);
    }

    let apps_dir = match cli::parse_apps_dir_arg(&args) {
        Ok(dir) => dir,
        Err(msg) => {
            eprintln!("{}", msg);
            eprintln!(
                "\nUsage: fleabox [--dev] [--apps-dir <dir>] [--port <port>] [--auth <type>] [--config <file>]"
            );
            std::process::exit(1);
        }
    };

    let port = match cli::parse_port_arg(&args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{}", msg);
            eprintln!(
                "\nUsage: fleabox [--dev] [--apps-dir <dir>] [--port <port>] [--auth <type>] [--config <file>]"
            );
            std::process::exit(1);
        }
    };

    let auth_arg_present = args
        .iter()
        .any(|arg| arg.starts_with("--auth=") || arg == "--auth");
    let auth_type = if !auth_arg_present && dev_mode {
        AuthType::None
    } else {
        match cli::parse_auth_arg(&args) {
            Ok(auth) => auth,
            Err(msg) => {
                eprintln!("{}", msg);
                eprintln!(
                    "\nUsage: fleabox [--dev] [--apps-dir <dir>] [--port <port>] [--auth <type>] [--config <file>]"
                );
                std::process::exit(1);
            }
        }
    };

    if auth_type == AuthType::Pam {
        unsafe {
            if libc::getuid() != 0 {
                eprintln!("Error: --auth=pam requires running as root");
                std::process::exit(1);
            }
        }
    }

    let config = if auth_type == AuthType::Config {
        let config_path = args
            .iter()
            .position(|arg| arg.starts_with("--config="))
            .and_then(|pos| args[pos].strip_prefix("--config="))
            .map(|s| s.to_string())
            .or_else(|| {
                args.iter()
                    .position(|arg| arg == "--config")
                    .and_then(|pos| args.get(pos + 1))
                    .map(|s| s.to_string())
            });

        let config_path = match config_path {
            Some(path) => path,
            None => {
                eprintln!("Error: --auth config requires --config <file> argument");
                eprintln!(
                    "\nUsage: fleabox [--dev] [--apps-dir <dir>] [--port <port>] [--auth <type>] [--config <file>]"
                );
                std::process::exit(1);
            }
        };

        match cli::load_config(&config_path) {
            Ok(cfg) => Some(Arc::new(cfg)),
            Err(msg) => {
                eprintln!("{}", msg);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    println!("Generating RSA keypair...");
    let mut rng = rand::thread_rng();
    let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
    println!("RSA keypair generated successfully");

    let state = AppState {
        token_store: Arc::new(RwLock::new(HashMap::new())),
        apps_dir,
        rsa_private_key: Arc::new(rsa_private_key),
        auth_type: auth_type.clone(),
        config,
        dev_mode,
    };

    let api_routes = Router::new()
        .route("/api/:app_id/data/*path", get(private_data::api_get_data))
        .route("/api/:app_id/data/*path", put(private_data::api_put_data))
        .route(
            "/api/:app_id/data/*path",
            delete(private_data::api_delete_data),
        )
        .route("/api/:app_id/public/*path", get(public_data::api_get_public_data))
        .route("/api/:app_id/public/*path", put(public_data::api_put_public_data))
        .route(
            "/api/:app_id/public/*path",
            delete(public_data::api_delete_public_data),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::token_auth_middleware,
        ))
        .with_state(state.clone());

    let static_assets_routes = Router::new()
        .route("/", get(static_pages::homepage))
        .route("/:app/", get(static_pages::serve_app_index))
        .route("/:app", get(static_pages::redirect_to_app))
        .route("/:app/*file", get(static_pages::serve_app_file))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::public_page_auth_middleware,
        ))
        .with_state(state.clone());

    let public_data_routes = Router::new()
        .route("/:app_id/~:user_id/*path", get(public_data::api_get_user_public_data))
        .route("/:app_id/~:user_id/", get(public_data::api_get_user_public_data_root))
        .route("/:app_id/~:user_id", get(public_data::redirect_to_public_folder))
        .with_state(state.clone());

    let app = Router::new()
        .route("/login", get(auth::login_page))
        .route("/login", post(auth::login_handler))
        .route("/logout", get(auth::logout_handler))
        .merge(api_routes)
        .merge(static_assets_routes)
        .merge(public_data_routes)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();

    println!("Server running on http://0.0.0.0:{}", port);
    match auth_type {
        AuthType::Pam => println!("Authentication: PAM (system users)"),
        AuthType::Config => println!("Authentication: Config file"),
        AuthType::None => println!("Authentication: Reverse proxy (X-Remote-User header)"),
    }
    println!("Password encryption: RSA-2048 with OAEP");

    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::create_dir_all as std_create_dir_all;
    use tempfile::TempDir;

    #[test]
    fn test_validate_path_component_valid() {
        assert!(crate::fs_utils::validate_path_component("test").is_ok());
        assert!(crate::fs_utils::validate_path_component("test-file").is_ok());
        assert!(crate::fs_utils::validate_path_component("test_file").is_ok());
        assert!(crate::fs_utils::validate_path_component("test.txt").is_ok());
    }

    #[test]
    fn test_validate_path_component_dot() {
        assert!(crate::fs_utils::validate_path_component(".").is_err());
        assert!(crate::fs_utils::validate_path_component("..").is_err());
    }

    #[test]
    fn test_validate_path_component_empty() {
        assert!(crate::fs_utils::validate_path_component("").is_err());
    }

    #[test]
    fn test_validate_path_component_nul() {
        assert!(crate::fs_utils::validate_path_component("test\0file").is_err());
    }

    #[test]
    fn test_validate_path_component_windows_drive() {
        assert!(crate::fs_utils::validate_path_component("C:").is_err());
        assert!(crate::fs_utils::validate_path_component("D:").is_err());
    }

    #[test]
    fn test_validate_and_resolve_path_leading_slash() {
        let temp_dir = TempDir::new().unwrap();
        let result = crate::fs_utils::validate_and_resolve_path(temp_dir.path(), "/test");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_and_resolve_path_dot_components() {
        let temp_dir = TempDir::new().unwrap();
        assert!(crate::fs_utils::validate_and_resolve_path(temp_dir.path(), "./test").is_err());
        assert!(crate::fs_utils::validate_and_resolve_path(temp_dir.path(), "../test").is_err());
        assert!(
            crate::fs_utils::validate_and_resolve_path(temp_dir.path(), "test/../other").is_err()
        );
    }

    #[test]
    fn test_validate_and_resolve_path_double_slash() {
        let temp_dir = TempDir::new().unwrap();
        let result = crate::fs_utils::validate_and_resolve_path(temp_dir.path(), "test//file");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_and_resolve_path_valid_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        std::fs::File::create(&test_file).unwrap();

        let result = crate::fs_utils::validate_and_resolve_path(temp_dir.path(), "test.txt");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved, test_file.canonicalize().unwrap());
    }

    #[test]
    fn test_validate_and_resolve_path_valid_nested() {
        let temp_dir = TempDir::new().unwrap();
        let nested_dir = temp_dir.path().join("dir1").join("dir2");
        std_create_dir_all(&nested_dir).unwrap();
        let test_file = nested_dir.join("test.txt");
        std::fs::File::create(&test_file).unwrap();

        let result =
            crate::fs_utils::validate_and_resolve_path(temp_dir.path(), "dir1/dir2/test.txt");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_and_resolve_path_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let parent_dir = temp_dir.path().join("parent");
        std_create_dir_all(&parent_dir).unwrap();

        let result =
            crate::fs_utils::validate_and_resolve_path(temp_dir.path(), "parent/newfile.txt");
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_user_home_invalid() {
        let result = crate::user::get_user_home("nonexistent_user_12345");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_apps_dir_argument() {
        let args = vec!["fleabox".to_string()];
        let apps_dir = crate::cli::parse_apps_dir_arg(&args).unwrap();
        assert_eq!(apps_dir, "/srv/fleabox");

        let args = vec![
            "fleabox".to_string(),
            "--apps-dir".to_string(),
            "/custom/path".to_string(),
        ];
        let apps_dir = crate::cli::parse_apps_dir_arg(&args).unwrap();
        assert_eq!(apps_dir, "/custom/path");

        let args = vec![
            "fleabox".to_string(),
            "--apps-dir=/custom/path/equals".to_string(),
        ];
        let apps_dir = crate::cli::parse_apps_dir_arg(&args).unwrap();
        assert_eq!(apps_dir, "/custom/path/equals");

        let args = vec![
            "fleabox".to_string(),
            "--dev".to_string(),
            "--apps-dir".to_string(),
            "/another/path".to_string(),
        ];
        let apps_dir = crate::cli::parse_apps_dir_arg(&args).unwrap();
        assert_eq!(apps_dir, "/another/path");
    }

    #[test]
    fn test_parse_apps_dir_missing_value() {
        let args = vec!["fleabox".to_string(), "--apps-dir".to_string()];
        let result = crate::cli::parse_apps_dir_arg(&args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("requires a directory path argument")
        );

        let args = vec!["fleabox".to_string(), "--apps-dir=".to_string()];
        let result = crate::cli::parse_apps_dir_arg(&args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("requires a directory path argument")
        );
    }

    #[test]
    fn test_parse_apps_dir_followed_by_flag() {
        let args = vec![
            "fleabox".to_string(),
            "--apps-dir".to_string(),
            "--dev".to_string(),
        ];
        let result = crate::cli::parse_apps_dir_arg(&args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("requires a directory path argument")
        );
    }

    #[test]
    fn test_parse_auth_arg() {
        let args = vec!["fleabox".to_string()];
        assert_eq!(crate::cli::parse_auth_arg(&args).unwrap(), AuthType::Pam);

        let args = vec![
            "fleabox".to_string(),
            "--auth".to_string(),
            "config".to_string(),
        ];
        assert_eq!(crate::cli::parse_auth_arg(&args).unwrap(), AuthType::Config);

        let args = vec![
            "fleabox".to_string(),
            "--auth".to_string(),
            "none".to_string(),
        ];
        assert_eq!(crate::cli::parse_auth_arg(&args).unwrap(), AuthType::None);

        let args = vec!["fleabox".to_string(), "--auth=config".to_string()];
        assert_eq!(crate::cli::parse_auth_arg(&args).unwrap(), AuthType::Config);

        let args = vec!["fleabox".to_string(), "--auth=none".to_string()];
        assert_eq!(crate::cli::parse_auth_arg(&args).unwrap(), AuthType::None);

        let args = vec![
            "fleabox".to_string(),
            "--auth".to_string(),
            "invalid".to_string(),
        ];
        assert!(crate::cli::parse_auth_arg(&args).is_err());

        let args = vec!["fleabox".to_string(), "--auth=invalid".to_string()];
        assert!(crate::cli::parse_auth_arg(&args).is_err());
    }

    #[test]
    fn test_parse_port_arg() {
        let args = vec!["fleabox".to_string()];
        assert_eq!(crate::cli::parse_port_arg(&args).unwrap(), 3000);

        let args = vec![
            "fleabox".to_string(),
            "--port".to_string(),
            "8080".to_string(),
        ];
        assert_eq!(crate::cli::parse_port_arg(&args).unwrap(), 8080);

        let args = vec!["fleabox".to_string(), "--port=9090".to_string()];
        assert_eq!(crate::cli::parse_port_arg(&args).unwrap(), 9090);

        let args = vec![
            "fleabox".to_string(),
            "--port".to_string(),
            "not_a_number".to_string(),
        ];
        assert!(crate::cli::parse_port_arg(&args).is_err());

        let args = vec!["fleabox".to_string(), "--port=not_a_number".to_string()];
        assert!(crate::cli::parse_port_arg(&args).is_err());
    }
}
