//! LostLoveProtocol Server
//!
//! VPN сервер с поддержкой мимикрии под российские сервисы.

mod config;
mod listener;
mod nat;
mod router;

use clap::Parser;
use config::ServerConfig;
use listener::LlpListener;
use llp_core::session::SessionManager;
use nat::NatGateway;
use router::Router;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

/// Аргументы командной строки
#[derive(Parser, Debug)]
#[command(name = "llp-server")]
#[command(about = "LostLoveProtocol VPN Server", long_about = None)]
struct Args {
    /// Путь к конфигурационному файлу
    #[arg(short, long, default_value = "server.toml")]
    config: PathBuf,

    /// Генерация примера конфигурации
    #[arg(long)]
    generate_config: Option<PathBuf>,

    /// Уровень логирования (trace, debug, info, warn, error)
    #[arg(short, long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Генерация конфигурации, если запрошено
    if let Some(path) = args.generate_config {
        if let Err(e) = generate_config(&path) {
            eprintln!("Ошибка генерации конфигурации: {}", e);
            std::process::exit(1);
        }
        println!("Конфигурация сохранена в: {}", path.display());
        return;
    }

    // Загрузка конфигурации
    let config = match ServerConfig::from_file(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Ошибка загрузки конфигурации: {}", e);
            eprintln!("Создайте конфигурацию: llp-server --generate-config server.toml");
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
        .with_thread_ids(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Не удалось установить global subscriber");

    info!("╔═══════════════════════════════════════════════════╗");
    info!("║      LostLoveProtocol Server v{}               ║", env!("CARGO_PKG_VERSION"));
    info!("╚═══════════════════════════════════════════════════╝");

    // Вывод конфигурации
    info!("Конфигурация:");
    info!("  • Адрес: {}", config.bind_address());
    info!("  • Макс. подключений: {}", config.network.max_connections);
    info!("  • VPN подсеть: {}", config.vpn.subnet);
    info!("  • Профиль мимикрии: {}", config.security.default_mimicry_profile);

    let config = Arc::new(config);

    // Запуск сервера
    if let Err(e) = run_server(config).await {
        error!("Критическая ошибка сервера: {}", e);
        std::process::exit(1);
    }
}

/// Запуск сервера
async fn run_server(config: Arc<ServerConfig>) -> Result<(), Box<dyn std::error::Error>> {
    // Создание менеджера сессий
    let session_manager = Arc::new(RwLock::new(SessionManager::with_lifetime(
        config.session_lifetime(),
    )));

    // Создание роутера
    let router = Router::new(Arc::clone(&session_manager));
    let router_handle = router.handle();

    // Создание NAT gateway
    let nat = NatGateway::default(); // TODO: Получить внешний IP

    // Запуск роутера в отдельной задаче
    tokio::spawn(async move {
        router.run().await;
    });

    // Создание и запуск listener
    let listener = LlpListener::bind(
        Arc::clone(&config),
        session_manager.clone(),
        router_handle,
    )
    .await?;

    // Запуск фоновой задачи для очистки истёкших сессий
    let session_manager_cleanup = session_manager.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            let mut manager = session_manager_cleanup.write().await;
            let removed = manager.cleanup_expired();
            if removed > 0 {
                info!("Очищено {} истёкших сессий", removed);
            }
        }
    });

    // Обработка сигналов для graceful shutdown
    tokio::select! {
        result = listener.run() => {
            if let Err(e) = result {
                error!("Ошибка listener: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Получен сигнал Ctrl+C, остановка сервера...");
        }
    }

    info!("Сервер остановлен");
    Ok(())
}

/// Генерация примера конфигурации
fn generate_config(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::default();
    config.to_file(path)?;
    Ok(())
}
