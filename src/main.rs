mod device;
mod peer;
mod service;
mod wireguard;

use crate::service::Service;

use anyhow::Result;
use env_logger::Env;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let mut service = Service::new().await?;

    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(5_000));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            _ = ticker.tick()      => { if let Err(e) = service.run().await { log::error!("{e}"); } }
            _ = sigterm.recv()     => { log::info!("SIGTERM, shutting down"); break; }
            _ = tokio::signal::ctrl_c() => { log::info!("SIGINT, shutting down"); break; }
        }
    }
    Ok(())
}
