//! LostLoveProtocol Server
//!
//! VPN сервер с поддержкой мимикрии под российские сервисы.

mod client_handler;
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
use std::net::{IpAddr, Ipv4Addr};
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

    /// Экспорт клиентской конфигурации
    #[arg(long)]
    export_client_config: Option<PathBuf>,

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

    // Экспорт клиентской конфигурации
    if let Some(path) = args.export_client_config {
        if let Err(e) = export_client_config(&args.config, &path) {
            eprintln!("Ошибка экспорта клиентской конфигурации: {}", e);
            std::process::exit(1);
        }
        println!("Клиентская конфигурация сохранена в: {}", path.display());
        return;
    }

    // Загрузка конфигурации
    let config = match ServerConfig::from_file(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            // Попытка автоматически создать конфигурацию
            if !args.config.exists() {
                println!("⚠ Конфигурационный файл не найден: {}", args.config.display());
                println!("📝 Создание конфигурации по умолчанию...");

                if let Err(gen_err) = generate_config(&args.config) {
                    eprintln!("Ошибка создания конфигурации: {}", gen_err);
                    std::process::exit(1);
                }

                println!("✓ Конфигурация создана: {}", args.config.display());
                println!();
                println!("📋 Необходимые действия:");
                println!("  1. Отредактируйте файл конфигурации под ваши нужды");
                println!("  2. Убедитесь, что указаны правильные параметры сети");
                println!("  3. Запустите сервер снова: llp-server");
                println!();
                std::process::exit(0);
            } else {
                eprintln!("Ошибка загрузки конфигурации: {}", e);
                eprintln!("Проверьте файл: {}", args.config.display());
                std::process::exit(1);
            }
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
async fn run_server(config: Arc<ServerConfig>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Создание менеджера сессий
    let session_manager = Arc::new(RwLock::new(SessionManager::with_lifetime(
        config.session_lifetime(),
    )));

    // Создание роутера
    let router = Router::new(Arc::clone(&session_manager));
    let router_handle = router.handle();

    // Создание NAT gateway
    let _nat = NatGateway::default(); // TODO: Получить внешний IP

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

/// Получение внешнего IP адреса сервера
fn get_public_ip() -> Option<String> {
    use std::process::Command;

    // Пробуем несколько методов определения публичного IP
    let methods = vec![
        // Метод 1: через ip route (работает на VPS)
        ("ip route get 1.1.1.1 | grep -oP 'src \\K\\S+'", "sh"),
        // Метод 2: через hostname -I
        ("hostname -I | awk '{print $1}'", "sh"),
        // Метод 3: через внешний сервис (если есть интернет)
        ("curl -s ifconfig.me", "sh"),
    ];

    for (cmd, shell) in methods {
        if let Ok(output) = Command::new(shell).arg("-c").arg(cmd).output() {
            if output.status.success() {
                let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !ip.is_empty() && ip.contains('.') {
                    return Some(ip);
                }
            }
        }
    }

    None
}

/// Экспорт клиентской конфигурации
fn export_client_config(
    server_config_path: &PathBuf,
    client_config_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;

    // Загрузка конфигурации сервера
    let server_config = ServerConfig::from_file(server_config_path)?;

    // Получение внешнего адреса сервера
    let server_address = if server_config.network.bind_ip == IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) {
        // Пытаемся автоматически определить публичный IP
        if let Some(public_ip) = get_public_ip() {
            println!("✓ Автоматически определён публичный IP: {}", public_ip);
            format!("{}:{}", public_ip, server_config.network.port)
        } else {
            println!("⚠ Не удалось автоматически определить публичный IP");
            format!("your-server-ip:{}", server_config.network.port)
        }
    } else {
        server_config.bind_address().to_string()
    };

    // Создание клиентской конфигурации
    let client_config = format!(
        r#"# LostLoveProtocol Client Configuration
# Сгенерировано автоматически из серверной конфигурации

[server]
address = "{}"

[vpn]
interface_name = "llp0"
# IP адрес клиента в VPN сети (должен быть уникальным для каждого клиента)
ip_address = "10.8.0.2"
subnet_mask = "255.255.255.0"
mtu = {}

[security]
# Профиль мимикрии должен совпадать с сервером
mimicry_profile = "{}"
enable_replay_protection = true
max_packet_age_sec = 60

[reconnect]
enable = true
initial_delay_ms = 1000
max_delay_ms = 30000
max_attempts = 0  # 0 = бесконечно

[logging]
level = "info"
"#,
        server_address,
        server_config.vpn.mtu,
        server_config.security.default_mimicry_profile
    );

    // Сохранение в файл
    fs::write(client_config_path, client_config)?;

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║   Клиентская конфигурация успешно создана       ║");
    println!("╚══════════════════════════════════════════════════╝\n");
    println!("📁 Файл: {}", client_config_path.display());
    println!("\n⚠️  ВАЖНО:");
    println!("   1. Замените 'your-server-ip' на реальный IP/домен сервера");
    println!("   2. Измените ip_address для каждого клиента (10.8.0.2, 10.8.0.3, и т.д.)");
    println!("   3. Скопируйте этот файл на клиентскую машину");
    println!("\n💡 Для Windows клиента:");
    println!("   Скопируйте файл в папку: client\\configs\\");
    println!();

    Ok(())
}
