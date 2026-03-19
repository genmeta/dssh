#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    genmeta_ssh3_server::init_session_tracing();
    tracing::info!("session child process starting");
    genmeta_ssh3_server::run_session_from_stdio().await?;
    tracing::info!("session child process exiting");
    Ok(())
}
