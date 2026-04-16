//! Simple PIR server example.
//!
//! Demonstrates how to create and run a PIR server using the SDK.
//!
//! Usage:
//!   cargo run -p pir-sdk-server --example simple_server -- \
//!     --port 8091 \
//!     --db /path/to/snapshot.bin:900000
//!
//! Or with a TOML config:
//!   cargo run -p pir-sdk-server --example simple_server -- --config server.toml

use pir_sdk_server::{PirServerBuilder, ServerConfig};
use std::path::PathBuf;

fn parse_args() -> Result<ServerConfig, String> {
    let args: Vec<String> = std::env::args().collect();

    let mut config = ServerConfig::new();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                if i < args.len() {
                    let path = std::path::Path::new(&args[i]);
                    config = ServerConfig::load(path)
                        .map_err(|e| format!("Failed to load config: {}", e))?;
                }
            }
            "--port" | "-p" => {
                i += 1;
                if i < args.len() {
                    config.port = args[i]
                        .parse()
                        .map_err(|_| format!("Invalid port: {}", args[i]))?;
                }
            }
            "--db" | "-d" => {
                i += 1;
                if i < args.len() {
                    // Format: path:height or path:base_height:tip_height
                    let parts: Vec<&str> = args[i].split(':').collect();
                    match parts.len() {
                        2 => {
                            let path = PathBuf::from(parts[0]);
                            let height: u32 = parts[1]
                                .parse()
                                .map_err(|_| format!("Invalid height: {}", parts[1]))?;
                            config.add_full_db(&path, height);
                        }
                        3 => {
                            let path = PathBuf::from(parts[0]);
                            let base: u32 = parts[1]
                                .parse()
                                .map_err(|_| format!("Invalid base height: {}", parts[1]))?;
                            let tip: u32 = parts[2]
                                .parse()
                                .map_err(|_| format!("Invalid tip height: {}", parts[2]))?;
                            config.add_delta_db(&path, base, tip);
                        }
                        _ => {
                            return Err(format!(
                                "Invalid db format '{}'. Use path:height or path:base:tip",
                                args[i]
                            ));
                        }
                    }
                }
            }
            "--warmup" => {
                config.warmup = true;
            }
            "--no-warmup" => {
                config.warmup = false;
            }
            "--help" | "-h" => {
                println!("PIR Server Example");
                println!();
                println!("Usage: simple_server [OPTIONS]");
                println!();
                println!("Options:");
                println!("  --config, -c <file>     Load TOML configuration file");
                println!("  --port, -p <port>       Listen port (default: 8091)");
                println!("  --db, -d <path:height>  Add full snapshot database");
                println!("  --db, -d <path:base:tip> Add delta database");
                println!("  --warmup                Enable database warmup (default)");
                println!("  --no-warmup             Disable database warmup");
                println!("  --help, -h              Show this help");
                println!();
                println!("Example:");
                println!("  simple_server --port 8091 --db ./snapshot.bin:900000");
                std::process::exit(0);
            }
            arg => {
                return Err(format!("Unknown option: {}", arg));
            }
        }
        i += 1;
    }

    Ok(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if config.databases.is_empty() {
        eprintln!("Error: No databases configured. Use --db or --config.");
        eprintln!("Run with --help for usage information.");
        std::process::exit(1);
    }

    println!("=== PIR Server ===");
    println!();
    println!("Configuration:");
    println!("  Port: {}", config.port);
    println!("  Role: {:?}", config.role);
    println!("  Warmup: {}", config.warmup);
    println!("  Databases: {}", config.databases.len());

    for db in &config.databases {
        println!("    - {:?}", db);
    }

    println!();
    println!("Building server...");

    let mut builder = PirServerBuilder::new()
        .port(config.port)
        .warmup(config.warmup);

    // Forward parsed databases into the builder. Without this, the builder
    // would be empty even though the user passed --db or --config flags.
    for db in &config.databases {
        if db.is_delta() {
            builder = builder.add_delta_db(&db.path, db.base_height, db.height);
        } else {
            builder = builder.add_full_db(&db.path, db.height);
        }
    }

    let server = builder.build().await;

    match server {
        Ok(server) => {
            println!("Server built successfully!");
            println!();

            let catalog = server.catalog();
            println!("Loaded {} database(s):", catalog.databases.len());
            for db in &catalog.databases {
                println!(
                    "  [{}] {} {:?} height={} index_bins={} chunk_bins={}",
                    db.db_id, db.name, db.kind, db.height, db.index_bins, db.chunk_bins
                );
            }

            println!();
            println!("Starting server on port {}...", config.port);

            // Run server (blocks until shutdown)
            server.run().await?;
        }
        Err(e) => {
            eprintln!("Failed to build server: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
