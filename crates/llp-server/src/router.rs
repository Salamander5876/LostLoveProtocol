//! Роутер для маршрутизации пакетов между клиентами
//!
//! Этот модуль отвечает за:
//! - Регистрацию подключённых клиентов
//! - Приём пакетов от клиентов
//! - Расшифровку и валидацию пакетов
//! - Маршрутизацию IP пакетов
//! - Отправку пакетов клиентам

use bytes::Bytes;
use llp_core::{
    packet::MimicryProfile,
    session::SessionManager,
};
use llp_mimicry::PacketWrapper;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info};

use crate::nat::NatGateway;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Команды для роутера
#[derive(Debug)]
#[allow(dead_code)]
pub enum RouterCommand {
    /// Зарегистрировать нового клиента
    RegisterClient {
        session_id: u64,
        stream: TcpStream,
        profile: MimicryProfile,
    },
    /// Отправить пакет клиенту
    SendToClient {
        session_id: u64,
        data: Bytes,
    },
    /// Удалить клиента
    RemoveClient {
        session_id: u64,
    },
}

/// Handle для взаимодействия с роутером
#[derive(Clone)]
pub struct RouterHandle {
    tx: mpsc::UnboundedSender<RouterCommand>,
}

impl RouterHandle {
    /// Зарегистрировать клиента
    pub async fn register_client(
        &self,
        session_id: u64,
        stream: TcpStream,
        profile: MimicryProfile,
    ) -> Result<()> {
        self.tx
            .send(RouterCommand::RegisterClient {
                session_id,
                stream,
                profile,
            })
            .map_err(|e| format!("Не удалось отправить команду: {}", e))?;
        Ok(())
    }

    /// Отправить данные клиенту
    #[allow(dead_code)]
    pub async fn send_to_client(&self, session_id: u64, data: Bytes) -> Result<()> {
        self.tx
            .send(RouterCommand::SendToClient { session_id, data })
            .map_err(|e| format!("Не удалось отправить команду: {}", e))?;
        Ok(())
    }

    /// Удалить клиента
    #[allow(dead_code)]
    pub async fn remove_client(&self, session_id: u64) -> Result<()> {
        self.tx
            .send(RouterCommand::RemoveClient { session_id })
            .map_err(|e| format!("Не удалось отправить команду: {}", e))?;
        Ok(())
    }
}

/// Информация о подключённом клиенте
#[allow(dead_code)]
struct ClientInfo {
    session_id: u64,
    stream: TcpStream,
    wrapper: PacketWrapper,
    vpn_ip: Option<IpAddr>,
}

/// Роутер пакетов
#[allow(dead_code)]
pub struct Router {
    /// Менеджер сессий
    session_manager: Arc<RwLock<SessionManager>>,
    /// Подключённые клиенты: session_id -> ClientInfo
    clients: HashMap<u64, ClientInfo>,
    /// Маппинг VPN IP -> session_id
    ip_to_session: HashMap<IpAddr, u64>,
    /// NAT gateway
    nat_gateway: Option<NatGateway>,
    /// Канал команд
    rx: mpsc::UnboundedReceiver<RouterCommand>,
    /// Sender для handle
    tx: mpsc::UnboundedSender<RouterCommand>,
}

impl Router {
    /// Создать новый роутер
    pub fn new(session_manager: Arc<RwLock<SessionManager>>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        Self {
            session_manager,
            clients: HashMap::new(),
            ip_to_session: HashMap::new(),
            nat_gateway: None,
            rx,
            tx,
        }
    }

    /// Получить handle для взаимодействия с роутером
    pub fn handle(&self) -> RouterHandle {
        RouterHandle {
            tx: self.tx.clone(),
        }
    }

    /// Установить NAT gateway
    #[allow(dead_code)]
    pub fn set_nat_gateway(&mut self, nat: NatGateway) {
        self.nat_gateway = Some(nat);
    }

    /// Запустить роутер (основной цикл)
    pub async fn run(mut self) {
        info!("Роутер запущен");

        while let Some(command) = self.rx.recv().await {
            match command {
                RouterCommand::RegisterClient {
                    session_id,
                    stream,
                    profile,
                } => {
                    if let Err(e) = self.register_client(session_id, stream, profile).await {
                        error!("Ошибка регистрации клиента {}: {}", session_id, e);
                    }
                }
                RouterCommand::SendToClient { session_id, data } => {
                    if let Err(e) = self.send_to_client(session_id, data).await {
                        error!("Ошибка отправки клиенту {}: {}", session_id, e);
                    }
                }
                RouterCommand::RemoveClient { session_id } => {
                    self.remove_client(session_id).await;
                }
            }
        }

        info!("Роутер остановлен");
    }

    /// Зарегистрировать клиента
    async fn register_client(
        &mut self,
        session_id: u64,
        stream: TcpStream,
        profile: MimicryProfile,
    ) -> Result<()> {
        let wrapper = PacketWrapper::new(profile);

        let client_info = ClientInfo {
            session_id,
            stream,
            wrapper,
            vpn_ip: None, // TODO: Назначить IP из пула
        };

        self.clients.insert(session_id, client_info);

        info!("Клиент {} зарегистрирован в роутере", session_id);

        // Запустить задачу чтения для этого клиента
        let handle = self.handle();
        let session_manager = Arc::clone(&self.session_manager);

        tokio::spawn(async move {
            if let Err(e) =
                Self::client_read_loop(session_id, handle, session_manager).await
            {
                error!("Ошибка в client_read_loop для {}: {}", session_id, e);
            }
        });

        Ok(())
    }

    /// Цикл чтения от клиента
    async fn client_read_loop(
        _session_id: u64,
        _handle: RouterHandle,
        _session_manager: Arc<RwLock<SessionManager>>,
    ) -> Result<()> {
        // TODO: Реализовать чтение пакетов от клиента
        // Пока заглушка
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        Ok(())
    }

    /// Отправить данные клиенту
    async fn send_to_client(&mut self, session_id: u64, data: Bytes) -> Result<()> {
        let client = self
            .clients
            .get_mut(&session_id)
            .ok_or("Клиент не найден")?;

        // Обернуть данные в мимикрию
        let wrapped = client.wrapper.wrap(&data)?;

        // Отправить через TCP
        client.stream.write_u32(wrapped.len() as u32).await?;
        client.stream.write_all(&wrapped).await?;
        client.stream.flush().await?;

        debug!("Отправлено {} байт клиенту {}", wrapped.len(), session_id);

        Ok(())
    }

    /// Удалить клиента
    async fn remove_client(&mut self, session_id: u64) {
        if let Some(client) = self.clients.remove(&session_id) {
            if let Some(ip) = client.vpn_ip {
                self.ip_to_session.remove(&ip);
            }

            // Удалить сессию из менеджера
            let mut manager = self.session_manager.write().await;
            let _ = manager.remove_session(session_id);

            info!("Клиент {} удалён из роутера", session_id);
        }
    }

    /// Маршрутизация IP пакета
    #[allow(dead_code)]
    async fn route_ip_packet(&mut self, _packet: &[u8]) -> Result<()> {
        // TODO: Парсинг IP заголовка и маршрутизация
        // Заглушка на будущее
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_handle() {
        let session_manager = Arc::new(RwLock::new(SessionManager::new()));
        let router = Router::new(session_manager);
        let handle = router.handle();

        // Handle должен быть клонируемым
        let handle2 = handle.clone();
        assert!(std::mem::size_of_val(&handle2) > 0);
    }
}
