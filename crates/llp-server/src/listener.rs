//! UDP Listener для принятия подключений клиентов
//!
//! Этот модуль отвечает за:
//! - Прослушивание UDP порта
//! - Обработку handshake с клиентами
//! - Регистрацию сессий
//! - Маршрутизацию пакетов между клиентами

use llp_core::{
    crypto::{AeadCipher, SessionKey},
    handshake::ServerHandshake,
    packet::MimicryProfile,
    session::SessionManager,
};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::client_handler::ClientHandler;
use crate::client_registry::ClientRegistry;
use crate::config::ServerConfig;
use crate::nat::NatGateway;
use crate::router::RouterHandle;

/// Результат обработки подключения
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Состояние handshake для клиента
enum HandshakeState {
    /// Ожидаем CLIENT_HELLO
    WaitingClientHello,
    /// Ожидаем CLIENT_VERIFY (сохранён server handshake, session_id, profile)
    WaitingClientVerify(ServerHandshake, u64, MimicryProfile),
}

/// Информация о подключённом клиенте
struct ClientSession {
    session_id: u64,
    session_key: SessionKey,
    receive_counter: u64,
    vpn_ip: IpAddr,
}

/// UDP Listener сервера
pub struct LlpListener {
    /// Конфигурация сервера
    config: Arc<ServerConfig>,
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Менеджер сессий
    session_manager: Arc<RwLock<SessionManager>>,
    /// Роутер для передачи данных
    router: RouterHandle,
    /// NAT gateway для маршрутизации
    nat_gateway: Option<Arc<RwLock<NatGateway>>>,
    /// Реестр клиентов для обратной маршрутизации
    client_registry: Arc<ClientRegistry>,
    /// Состояния handshake для клиентов (peer_addr -> state)
    handshake_states: Arc<RwLock<HashMap<SocketAddr, HandshakeState>>>,
    /// Подключённые клиенты (peer_addr -> session info)
    client_sessions: Arc<RwLock<HashMap<SocketAddr, ClientSession>>>,
}

impl LlpListener {
    /// Создать новый listener
    pub async fn bind(
        config: Arc<ServerConfig>,
        session_manager: Arc<RwLock<SessionManager>>,
        router: RouterHandle,
        nat_gateway: Option<Arc<RwLock<NatGateway>>>,
        client_registry: Arc<ClientRegistry>,
    ) -> Result<Self> {
        let bind_addr = config.bind_address();
        let socket = UdpSocket::bind(bind_addr).await?;

        info!("LLP сервер запущен на {} (UDP)", bind_addr);

        Ok(Self {
            config,
            socket: Arc::new(socket),
            session_manager,
            router,
            nat_gateway,
            client_registry,
            handshake_states: Arc::new(RwLock::new(HashMap::new())),
            client_sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Запустить listener (основной цикл)
    pub async fn run(self) -> Result<()> {
        let socket = self.socket.clone();
        let listener = Arc::new(self);
        let mut buf = vec![0u8; 65536]; // Максимальный размер UDP пакета

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    if len == 0 {
                        continue;
                    }

                    let packet = buf[..len].to_vec();
                    let listener_clone = Arc::clone(&listener);

                    // Обработка пакета в отдельной задаче
                    tokio::spawn(async move {
                        if let Err(e) = listener_clone.handle_packet(packet, peer_addr).await {
                            debug!("Ошибка обработки пакета от {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Ошибка приёма UDP пакета: {}", e);
                }
            }
        }
    }

    /// Обработка входящего пакета
    async fn handle_packet(&self, packet: Vec<u8>, peer_addr: SocketAddr) -> Result<()> {
        // Сначала проверяем, есть ли подключённая сессия
        let has_session = {
            let sessions = self.client_sessions.read().await;
            sessions.contains_key(&peer_addr)
        };

        if has_session {
            // Клиент уже подключён - это VPN пакет
            self.handle_vpn_packet(packet, peer_addr).await
        } else {
            // Клиент не подключён - это handshake пакет
            self.handle_handshake_packet(packet, peer_addr).await
        }
    }

    /// Обработка handshake пакета
    async fn handle_handshake_packet(&self, packet: Vec<u8>, peer_addr: SocketAddr) -> Result<()> {
        let mut states = self.handshake_states.write().await;

        // Получаем или создаём состояние
        let state = states.entry(peer_addr).or_insert(HandshakeState::WaitingClientHello);

        match state {
            HandshakeState::WaitingClientHello => {
                // Это должен быть CLIENT_HELLO
                debug!("Получен CLIENT_HELLO от {} ({} байт)", peer_addr, packet.len());

                let mut rng = OsRng;
                let session_id = rand::random::<u64>();
                let mut server_handshake = ServerHandshake::new(&mut rng, session_id);

                // Обработка CLIENT_HELLO
                let (server_hello, mimicry_profile) = server_handshake
                    .process_client_hello(&mut rng, &packet)?;

                // Отправка SERVER_HELLO
                self.socket.send_to(&server_hello, peer_addr).await?;
                debug!("Отправлен SERVER_HELLO к {} ({} байт)", peer_addr, server_hello.len());

                // Обновляем состояние (сохраняем session_id отдельно)
                *state = HandshakeState::WaitingClientVerify(server_handshake, session_id, mimicry_profile);
            }
            HandshakeState::WaitingClientVerify(server_handshake, session_id_stored, mimicry_profile) => {
                // Это должен быть CLIENT_VERIFY
                debug!("Получен CLIENT_VERIFY от {}", peer_addr);

                server_handshake.process_client_verify(&packet)?;

                // Отправка SERVER_VERIFY
                let server_verify = server_handshake.send_server_verify()?;
                self.socket.send_to(&server_verify, peer_addr).await?;
                debug!("Отправлен SERVER_VERIFY к {}", peer_addr);

                // Handshake завершён
                let session_id = *session_id_stored;
                let session_key = server_handshake
                    .session_key()
                    .ok_or("Сессионный ключ не получен")?
                    .clone();

                info!(
                    "Handshake завершён: session_id={}, profile={}, peer={}",
                    session_id, mimicry_profile, peer_addr
                );

                // Регистрация сессии
                {
                    let mut manager = self.session_manager.write().await;
                    manager.add_session(session_id, session_key.clone(), *mimicry_profile)?;
                }

                info!("Клиент зарегистрирован: session_id={}", session_id);

                // Вычисляем VPN IP на основе session_id
                let vpn_ip = IpAddr::V4(Ipv4Addr::new(
                    10,
                    8,
                    0,
                    (2 + (session_id % 253)) as u8,
                ));

                // Сохраняем информацию о сессии для обработки VPN пакетов
                {
                    let mut sessions = self.client_sessions.write().await;
                    sessions.insert(peer_addr, ClientSession {
                        session_id,
                        session_key: session_key.clone(),
                        receive_counter: 0,
                        vpn_ip,
                    });
                }

                // Запуск обработчика клиента
                let socket_clone = Arc::clone(&self.socket);
                let nat_clone = self.nat_gateway.clone();
                let registry_clone = Arc::clone(&self.client_registry);

                let handler = ClientHandler::new_udp(
                    session_id,
                    socket_clone,
                    peer_addr,
                    session_key,
                    nat_clone,
                    registry_clone,
                );

                tokio::spawn(async move {
                    if let Err(e) = handler.run().await {
                        error!("Ошибка обработчика клиента {}: {}", session_id, e);
                    }
                });

                // Удаляем состояние handshake
                states.remove(&peer_addr);
            }
        }

        Ok(())
    }

    /// Обработка VPN пакета от уже подключённого клиента
    async fn handle_vpn_packet(&self, packet: Vec<u8>, peer_addr: SocketAddr) -> Result<()> {
        // Ищем сессию клиента
        let mut sessions = self.client_sessions.write().await;

        if let Some(session) = sessions.get_mut(&peer_addr) {
            let session_id = session.session_id;
            let vpn_ip = session.vpn_ip;

            // Создаём дешифратор для этого пакета
            let decrypt_cipher = AeadCipher::new(&session.session_key, session_id);

            // Обрабатываем пакет через ClientHandler
            if let Err(e) = ClientHandler::handle_incoming_packet(
                session_id,
                &packet,
                &decrypt_cipher,
                &self.nat_gateway,
                &mut session.receive_counter,
                &self.client_registry,
                vpn_ip,
            ).await {
                debug!("Ошибка обработки VPN пакета от {}: {}", peer_addr, e);
            }
        } else {
            debug!("Получен VPN пакет от неизвестного клиента: {}", peer_addr);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::Router;

    #[tokio::test]
    async fn test_listener_bind() {
        use crate::client_registry::ClientRegistry;

        let config = Arc::new(ServerConfig::default());
        let session_manager = Arc::new(RwLock::new(SessionManager::new()));
        let router = Router::new(session_manager.clone());
        let router_handle = router.handle();
        let client_registry = Arc::new(ClientRegistry::new());

        // Пробуем забиндить на случайный порт
        let mut test_config = (*config).clone();
        test_config.network.port = 0; // OS выберет свободный порт
        let test_config = Arc::new(test_config);

        let result = LlpListener::bind(test_config, session_manager, router_handle, None, client_registry).await;
        assert!(result.is_ok());
    }
}
