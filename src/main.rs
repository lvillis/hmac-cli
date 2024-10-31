use clap::Parser;
use hmac::{Hmac, Mac, KeyInit};
use sha2::{Sha256, Sha384, Sha512};
use base64::engine::general_purpose;
use base64::Engine;
use chrono::Utc;
use std::error::Error;
use url::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use tracing::debug;
use tracing_subscriber::FmtSubscriber;
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;
use std::str::FromStr;
use dirs::home_dir;
use std::fs;
use std::time::Duration;

/// Define HMAC type aliases
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

/// HMAC Signer Trait
pub trait HmacSigner {
    fn generate_authorization_header(&self, method: &str, url: &str) -> Result<(String, String), Box<dyn Error>>;
}

/// Traefik HMAC Signer
pub struct TraefikSigner {
    pub ak: String,
    pub sk: String,
    pub algorithm: String,
}

impl HmacSigner for TraefikSigner {
    fn generate_authorization_header(&self, method: &str, url: &str) -> Result<(String, String), Box<dyn Error>> {
        let parsed_url = Url::parse(url)?;
        let host = match parsed_url.port() {
            Some(port) => format!("{}:{}", parsed_url.host_str().unwrap(), port),
            None => parsed_url.host_str().unwrap().to_string(),
        };
        let path = parsed_url.path();
        let query = parsed_url.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let full_path = format!("{}{}", path, query);

        let created = Utc::now().timestamp();
        let expires = created + 300; // 5 minutes validity

        // Build the signing string
        let signing_string = format!(
            "(request-target): {} {}\n(created): {}\n(expires): {}\nhost: {}",
            method.to_lowercase(),
            full_path,
            created,
            expires,
            host
        );

        debug!("Signing String:\n{}", signing_string);

        // Calculate HMAC signature
        let signature = match self.algorithm.as_str() {
            "hmac-sha256" => {
                let mut mac = HmacSha256::new_from_slice(self.sk.as_bytes())
                    .map_err(|_| "Invalid HMAC key length")?;
                mac.update(signing_string.as_bytes());
                let result = mac.finalize().into_bytes();
                general_purpose::STANDARD.encode(result)
            },
            "hmac-sha384" => {
                let mut mac = HmacSha384::new_from_slice(self.sk.as_bytes())
                    .map_err(|_| "Invalid HMAC key length")?;
                mac.update(signing_string.as_bytes());
                let result = mac.finalize().into_bytes();
                general_purpose::STANDARD.encode(result)
            },
            "hmac-sha512" => {
                let mut mac = HmacSha512::new_from_slice(self.sk.as_bytes())
                    .map_err(|_| "Invalid HMAC key length")?;
                mac.update(signing_string.as_bytes());
                let result = mac.finalize().into_bytes();
                general_purpose::STANDARD.encode(result)
            },
            _ => return Err("Unsupported HMAC algorithm".into()),
        };

        debug!("Generated signature: {}", signature);

        // Build the Authorization header
        let auth_header = format!(
            "Hmac keyId=\"{}\",algorithm=\"{}\",headers=\"(request-target) (created) (expires) host\",signature=\"{}\",created=\"{}\",expires=\"{}\"",
            self.ak,
            self.algorithm,
            signature,
            created,
            expires
        );

        Ok((signing_string, auth_header))
    }
}

/// Apisix HMAC Signer (Placeholder)
pub struct ApisixSigner {
    pub ak: String,
    pub sk: String,
    pub algorithm: String,
}

impl HmacSigner for ApisixSigner {
    fn generate_authorization_header(&self, _method: &str, _url: &str) -> Result<(String, String), Box<dyn Error>> {
        // TODO: Implement Apisix's HMAC authentication logic
        Err("Apisix HMAC signer not implemented".into())
    }
}

/// Higress HMAC Signer (Placeholder)
pub struct HigressSigner {
    pub ak: String,
    pub sk: String,
    pub algorithm: String,
}

impl HmacSigner for HigressSigner {
    fn generate_authorization_header(&self, _method: &str, _url: &str) -> Result<(String, String), Box<dyn Error>> {
        // TODO: Implement Higress's HMAC authentication logic
        Err("Higress HMAC signer not implemented".into())
    }
}

/// Supported Gateway Enum
enum Gateway {
    Traefik,
    Apisix,
    Higress,
}

impl FromStr for Gateway {
    type Err = String;

    fn from_str(input: &str) -> Result<Gateway, Self::Err> {
        match input.to_lowercase().as_str() {
            "traefik" => Ok(Gateway::Traefik),
            "apisix" => Ok(Gateway::Apisix),
            "higress" => Ok(Gateway::Higress),
            _ => Err(format!("Unsupported gateway: {}", input)),
        }
    }
}

/// Factory function to create the appropriate signer based on gateway type
fn create_signer(gateway: Gateway, ak: String, sk: String, algorithm: String) -> Box<dyn HmacSigner> {
    match gateway {
        Gateway::Traefik => Box::new(TraefikSigner { ak, sk, algorithm }),
        Gateway::Apisix => Box::new(ApisixSigner { ak, sk, algorithm }),
        Gateway::Higress => Box::new(HigressSigner { ak, sk, algorithm }),
    }
}

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Access Key ID (can be provided via config file `ak`)
    #[arg(short, long)]
    ak: Option<String>,

    /// Secret Key (can be provided via config file `sk`)
    #[arg(short, long)]
    sk: Option<String>,

    /// Request method (default: POST)
    #[arg(short, long, default_value = "POST")]
    method: String,

    /// Request URL
    #[arg(short, long)]
    url: String,

    /// Request body (JSON format)
    #[arg(short, long)]
    body: Option<String>,

    /// Gateway type (default: traefik)
    #[arg(short, long, default_value = "traefik", value_parser = ["apisix", "traefik", "higress"])]
    gateway: String,

    /// HMAC algorithm (default: hmac-sha256)
    #[arg(long, default_value = "hmac-sha256", value_parser = ["hmac-sha256", "hmac-sha384", "hmac-sha512"])]
    algorithm: String,
}

#[derive(Deserialize)]
struct Config {
    ak: Option<String>,
    sk: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize the logging subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Get the current user's home directory
    let home_dir = home_dir().ok_or("Unable to determine home directory")?;

    // Construct the path to the configuration file, e.g., ~/.hmac/config.toml
    let mut config_path = PathBuf::from(home_dir);
    config_path.push(".hmac");
    config_path.push("config.toml");

    // Load and parse the configuration file (if it exists)
    let config = if config_path.exists() {
        let config_content = fs::read_to_string(&config_path)?;
        toml::from_str::<Config>(&config_content)?
    } else {
        Config { ak: None, sk: None }
    };

    if config_path.exists() {
        debug!("Loaded configuration from {:?}", config_path);
    } else {
        debug!("No config.toml file found at {:?}", config_path);
    }

    let args = Args::parse();

    // Retrieve ak and sk, prioritizing command-line arguments over config file
    let ak = args.ak.or(config.ak).ok_or("Access Key (ak) is not provided. Use --ak or set it in config file.")?;
    let sk = args.sk.or(config.sk).ok_or("Secret Key (sk) is not provided. Use --sk or set it in config file.")?;

    // Parse the gateway type
    let gateway: Gateway = args.gateway.parse().map_err(|e| format!("Error parsing gateway: {}", e))?;

    // Create the corresponding signer
    let signer = create_signer(gateway, ak, sk, args.algorithm);

    // Generate the Authorization header
    let (signing_string, auth_header) = signer.generate_authorization_header(
        &args.method,
        &args.url,
    )?;

    debug!("Signing String:\n{}", signing_string);
    debug!("Authorization Header:\n{}", auth_header);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .build()?;
    let mut request = client
        .request(args.method.parse()?, &args.url)
        .header(AUTHORIZATION, auth_header);

    if let Some(body) = args.body {
        // Parse the body as JSON to ensure its validity
        let json_body: Value = serde_json::from_str(&body)
            .map_err(|e| format!("Invalid JSON body: {}", e))?;
        request = request
            .header(CONTENT_TYPE, "application/json")
            .body(json_body.to_string());
    }

    let response = request.send().await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    debug!("Response Status Code: {}", status);
    debug!("Response Body:\n{}", body);
    println!("{}", body);

    Ok(())
}
