use clap::{Parser, Subcommand};
use photon_indexer::migration::{MigratorTrait, RingsMigrator};
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
    let connect_options = ConnectOptions::new(url)
        .set_schema_search_path(schema)
        .to_owned();
    let db = match Database::connect(connect_options).await {
        Ok(db) => db,
        Err(err) => {
            eprintln!("Fail to acquire database connection: {err}");
            std::process::exit(1);
        }
    };

    let result = run::<RingsMigrator>(&db, args.command).await;

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

async fn run<M>(db: &DbConn, command: Option<Command>) -> Result<(), Box<dyn std::error::Error>>
where
    M: MigratorTrait,
{
    match command {
        Some(Command::Fresh) => M::fresh(db).await?,
        Some(Command::Refresh) => M::refresh(db).await?,
        Some(Command::Reset) => M::reset(db).await?,
        Some(Command::Status) => M::status(db).await?,
        Some(Command::Up { num }) => M::up(db, num).await?,
        Some(Command::Down { num }) => M::down(db, Some(num)).await?,
        None => M::up(db, None).await?,
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
