use crate::auth::AuthType;
use serde::Deserialize;
use std::fs;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct UserConfig {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) data_dir: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Config {
    pub(crate) users: Vec<UserConfig>,
}

pub(crate) fn parse_auth_arg(args: &[String]) -> Result<AuthType, String> {
    // Check for --auth=value
    if let Some(pos) = args.iter().position(|arg| arg.starts_with("--auth=")) {
        let value = args[pos].strip_prefix("--auth=").unwrap();
        return match value {
            "pam" => Ok(AuthType::Pam),
            "config" => Ok(AuthType::Config),
            "none" => Ok(AuthType::None),
            _ => Err(format!(
                "Error: Invalid auth type '{}'. Valid options: pam, config, none",
                value
            )),
        };
    }

    // Check for --auth value
    if let Some(pos) = args.iter().position(|arg| arg == "--auth") {
        if let Some(value) = args.get(pos + 1) {
            return match value.as_str() {
                "pam" => Ok(AuthType::Pam),
                "config" => Ok(AuthType::Config),
                "none" => Ok(AuthType::None),
                _ => Err(format!(
                    "Error: Invalid auth type '{}'. Valid options: pam, config, none",
                    value
                )),
            };
        } else {
            return Err("Error: --auth requires an authentication type argument".to_string());
        }
    }

    Ok(AuthType::Pam) // Default
}

pub(crate) fn load_config(path: &str) -> Result<Config, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read config file: {}", e))?;

    let config: Config = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse config file: {}", e))?;

    if config.users.is_empty() {
        return Err("Config file must contain at least one user".to_string());
    }

    Ok(config)
}

pub(crate) fn parse_apps_dir_arg(args: &[String]) -> Result<String, String> {
    // Check for --apps-dir=value
    if let Some(pos) = args.iter().position(|arg| arg.starts_with("--apps-dir=")) {
        let value = args[pos].strip_prefix("--apps-dir=").unwrap();
        if value.is_empty() {
            return Err("Error: --apps-dir requires a directory path argument".to_string());
        }
        return Ok(value.to_string());
    }

    // Check for --apps-dir value
    if let Some(pos) = args.iter().position(|arg| arg == "--apps-dir") {
        match args.get(pos + 1) {
            Some(value) if !value.starts_with("--") && !value.is_empty() => {
                return Ok(value.to_string());
            }
            Some(value) if value.starts_with("--") => {
                return Err(format!(
                    "Error: --apps-dir requires a directory path argument, got '{}' instead",
                    value
                ));
            }
            _ => {
                return Err("Error: --apps-dir requires a directory path argument".to_string());
            }
        }
    }

    Ok("/srv/fleabox".to_string())
}

pub(crate) fn parse_port_arg(args: &[String]) -> Result<u16, String> {
    // Check for --port=value
    if let Some(pos) = args.iter().position(|arg| arg.starts_with("--port=")) {
        let value = args[pos].strip_prefix("--port=").unwrap();
        return value
            .parse::<u16>()
            .map_err(|_| format!("Error: Invalid port number '{}'", value));
    }

    // Check for --port value
    if let Some(pos) = args.iter().position(|arg| arg == "--port") {
        match args.get(pos + 1) {
            Some(value) => {
                return value
                    .parse::<u16>()
                    .map_err(|_| format!("Error: Invalid port number '{}'", value));
            }
            None => return Err("Error: --port requires a port number argument".to_string()),
        }
    }

    Ok(3000) // Default port
}
