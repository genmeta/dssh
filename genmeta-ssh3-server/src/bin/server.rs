#[tokio::main]
async fn main() {
    let _guard = genmeta_ssh3_server::init_server_tracing();
    if let Err(error) = genmeta_ssh3_server::run_server_from_env().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
