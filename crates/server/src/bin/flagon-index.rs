//! Offline operator entry point. This process opens PostgreSQL, never an HTTP listener.
use server::index_maintenance::{USAGE, command_from_args, execute};

fn main() -> anyhow::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.as_slice() == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let command = command_from_args(&args)?;
    server::config::prepare_process_environment()?;
    let database_url = std::env::var("DATABASE_URL")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let db = server::Db::connect(&database_url)?;
            let result = execute(&db, command).await?;
            println!("{}", serde_json::to_string(&result)?);
            Ok(())
        })
}
