#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    genmeta_ssh3_client::init_client_tracing();
    genmeta_ssh3_client::run_env_client().await
}
