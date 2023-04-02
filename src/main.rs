#[macro_use]
extern crate actix_web;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::{env, io};

use log::info;

use actix_web::{middleware, web, App, HttpServer};

use crate::types::HealthStatus;
use ip_network_table_deps_treebitmap::IpLookupTable;

mod bouncer;
mod config;
mod constants;
mod crowdsec;
mod errors;
mod types;
mod utils;

use crate::types::CacheAttributes;

#[actix_web::main]
async fn main() -> io::Result<()> {
    env::set_var("RUST_LOG", "info,actix_web=info,actix_server=info");
    env_logger::init();
    info!("Starting Bouncer.");

    info!("Reading configuration.");
    let config = config::read_config();
    let config_clone = config.clone();

    let health_status = Arc::new(Mutex::new(HealthStatus::new()));
    let health_status_clone = health_status.clone();
    let ipv4_table = Arc::new(Mutex::new(IpLookupTable::<Ipv4Addr, CacheAttributes>::new()));
    let ipv6_table = Arc::new(Mutex::new(IpLookupTable::<Ipv6Addr, CacheAttributes>::new()));
    let ipv4_table_clone = ipv4_table.clone();
    let ipv6_table_clone = ipv6_table.clone();

    match config.crowdsec_mode {
        config::CrowdSecMode::Stream => {
            info!("Starting CrowdSec stream update.");
            // Update the IP tables from CrowdSec stream.
            actix_rt::spawn(async move {
                crowdsec::stream(
                    config_clone,
                    health_status_clone,
                    ipv4_table_clone,
                    ipv6_table_clone,
                )
                .await;
            });
        }
        config::CrowdSecMode::None => {
            info!("No mode configured. Ask CrowdSec API every time.");
        }
        config::CrowdSecMode::Live => {
            info!("Live mode configured.");
        }
    }

    // API.
    info!("Starting HTTP server (API).");
    HttpServer::new(move || {
        App::new()
            // Enable the logger - always register actix-web Logger middleware last.
            .wrap(middleware::Logger::default())
            // App data.
            .app_data(web::Data::new(config.clone()))
            .app_data(web::Data::new(health_status.clone()))
            .app_data(web::Data::new(ipv4_table.clone()))
            .app_data(web::Data::new(ipv6_table.clone()))
            // Register HTTP requests handlers.
            .service(bouncer::authenticate)
            .service(bouncer::block_list)
            .service(bouncer::health)
    })
    .bind("0.0.0.0:9090")?
    .run()
    .await
}
