//! LostLoveProtocol Client CLI
//!
//! VPN клиент с поддержкой мимикрии.

use clap::{Parser, Subcommand};
use llp_client::{ClientConfig, VpnClient};
use std::path::PathBuf;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

/// Аргументы командной строки
#[derive(Parser, Debug)]
#[command(name = "llp-client")]
#[command(about = "LostLoveProtocol VPN Client", long_about = None)]
struct Args {
    /// Путь к конфигурационному файлу
    #[arg(short, long, default_value = "client.toml")]
    config: PathBuf,

    /// Уровень логирования (trace, debug, info, warn, error)
    #[arg(short, long)]
    log_level: Option<String>,

    /// Подкоманды
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Подключиться к VPN серверу
    Connect,

    /// Генерация примера конфигурации
    GenerateConfig {
        /// Путь для сохранения
        #[arg(short, long, default_value = "client.toml")]
        output: PathBuf,
    },

    /// Показать статус подключения
    Status,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Обработка подкоманд
    match args.command {
        Some(Commands::GenerateConfig { output }) => {
            if let Err(e) = generate_config(&output) {
                eprintln!("Ошибка генерации конфигурации: {}", e);
                std::process::exit(1);
            }
            println!("Конфигурация сохранена в: {}", output.display());
            return;
        }
        Some(Commands::Status) => {
            println!("Статус: Не реализовано");
            return;
        }
        None | Some(Commands::Connect) => {
            // Продолжаем с подключением
        }
    }

    // Загрузка конфигурации
    let config = match ClientConfig::from_file(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Ошибка загрузки конфигурации: {}", e);
            eprintln!("Создайте конфигурацию: llp-client generate-config");
            std::process::exit(1);
        }
    };

    // Инициализация логирования
    let log_level = args
        .log_level
        .as_ref()
        .unwrap_or(&config.logging.level)
        .parse::<Level>()
        .unwrap_or(Level::INFO);

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Не удалось установить global subscriber");

    // Проверка прав (TUN требует root/admin)
    #[cfg(unix)]
    {
        if !nix::unistd::Uid::effective().is_root() {
            eprintln!("Ошибка: Требуются права root для создания TUN интерфейса");
            eprintln!("Запустите: sudo llp-client");
            std::process::exit(1);
        }
    }

    #[cfg(windows)]
    {
        // TODO: Проверка прав администратора на Windows
    }

    info!("╔═══════════════════════════════════════════════════╗");
    info!("║      LostLoveProtocol Client v{}              ║", env!("CARGO_PKG_VERSION"));
    info!("╚═══════════════════════════════════════════════════╝");

    // Вывод конфигурации
    info!("Конфигурация:");
    info!("  • Сервер: {}", config.server_address());
    info!("  • Профиль мимикрии: {}", config.security.mimicry_profile);
    info!("  • TUN интерфейс: {}", config.vpn.tun_name);
    info!("  • MTU: {}", config.vpn.mtu);

    // Запуск клиента
    if let Err(e) = run_client(config).await {
        error!("Критическая ошибка клиента: {}", e);
        std::process::exit(1);
    }
}

/// Запуск клиента
async fn run_client(config: ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = VpnClient::new(config);

    // Подключение
    info!("Подключение к серверу...");
    client.connect().await?;

    info!("✓ VPN туннель активен");

    // Обработка Ctrl+C для graceful shutdown
    tokio::select! {
        result = client.run() => {
            if let Err(e) = result {
                error!("Ошибка работы клиента: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Получен сигнал Ctrl+C, отключение...");
            client.disconnect().await?;
        }
    }

    info!("Клиент остановлен");
    Ok(())
}

/// Генерация примера конфигурации
fn generate_config(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::default();
    config.to_file(path)?;
    Ok(())
}

// Платформо-специфичный импорт для проверки прав на Unix
#[cfg(unix)]
use nix;
