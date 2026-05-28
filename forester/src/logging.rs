use tracing_subscriber::EnvFilter;

pub fn setup() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
}
