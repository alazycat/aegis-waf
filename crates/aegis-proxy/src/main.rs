use std::path::PathBuf;

use aegis_proxy::{run, Config};

struct Cli {
    config: PathBuf,
    check: bool,
}

fn parse_cli<I>(args: I) -> Result<Cli, String>
where
    I: IntoIterator<Item = String>,
{
    let mut config = None;
    let mut check = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config = Some(PathBuf::from(
                    args.next().ok_or("--config requires a path")?,
                ));
            }
            "--check" => check = true,
            "-h" | "--help" => {
                return Err("usage: aegis-proxy --config <path> [--check]".to_string());
            }
            other if other.starts_with("--config=") => {
                config = Some(PathBuf::from(&other["--config=".len()..]));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Cli {
        config: config.ok_or("--config <path> is required")?,
        check,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = parse_cli(std::env::args().skip(1)).map_err(anyhow::Error::msg)?;
    let config = Config::load(&cli.config)?;
    let rule_files = config.validate()?;
    if cli.check {
        println!("configuration OK: {} rule file(s)", rule_files.len());
        return Ok(());
    }
    run(config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_config_and_check_flags() {
        let cli = parse_cli(["--config".into(), "a.yaml".into(), "--check".into()]).unwrap();
        assert_eq!(cli.config, PathBuf::from("a.yaml"));
        assert!(cli.check);
    }

    #[test]
    fn rejects_missing_config() {
        assert!(parse_cli(["--check".into()]).is_err());
    }
}
