use clap::{Parser, Subcommand};
use photon_indexer::migration::{migrate_up, MigratorTrait, RingsMigrator};
use sea_orm_migration::sea_orm::{ConnectOptions, Database, DbConn};

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(short = 'v', long, global = true)]
    verbose: bool,

    #[arg(short = 's', long, global = true)]
    database_schema: Option<String>,

    #[arg(short = 'u', long, global = true)]
    database_url: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Up {
        #[arg(short = 'n', long)]
        num: Option<u32>,
    },
    Down {
        #[arg(short = 'n', long, default_value_t = 1)]
        num: u32,
    },
    Fresh,
    Refresh,
    Reset,
    Status,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    init_logging(args.verbose);

    let Some(url) = args
        .database_url
        .or_else(|| std::env::var("DATABASE_URL").ok())
    else {
        eprintln!("Environment variable 'DATABASE_URL' not set");
        std::process::exit(1);
    };
    let schema = args
        .database_schema
        .or_else(|| std::env::var("DATABASE_SCHEMA").ok())
        .unwrap_or_else(|| "public".to_owned());
    let mut connect_options = ConnectOptions::new(&url);
    connect_options.set_schema_search_path(schema);
    // All SQLite migration commands must retain one connection's schema state,
    // including fresh/refresh, which also change connection-local PRAGMAs.
    if url.starts_with("sqlite:") {
        connect_options.max_connections(1);
    }
    let db = match Database::connect(connect_options).await {
        Ok(db) => db,
        Err(err) => {
            eprintln!("Fail to acquire database connection: {err}");
            std::process::exit(1);
        }
    };

    let result = run(&db, args.command).await;

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

async fn run(db: &DbConn, command: Option<Command>) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Some(Command::Fresh) => RingsMigrator::fresh(db).await?,
        Some(Command::Refresh) => RingsMigrator::refresh(db).await?,
        Some(Command::Reset) => RingsMigrator::reset(db).await?,
        Some(Command::Status) => RingsMigrator::status(db).await?,
        Some(Command::Up { num }) => migrate_up(db, num).await?,
        Some(Command::Down { num }) => RingsMigrator::down(db, Some(num)).await?,
        None => migrate_up(db, None).await?,
    }
    Ok(())
}

fn init_logging(verbose: bool) {
    use tracing_subscriber::{prelude::*, EnvFilter};

    let filter = if verbose {
        "debug"
    } else {
        "sea_orm_migration=info"
    };
    let filter_layer = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));

    if verbose {
        let fmt_layer = tracing_subscriber::fmt::layer();
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt_layer)
            .init()
    } else {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_level(false)
            .without_time();
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt_layer)
            .init()
    };
}
