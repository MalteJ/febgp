use log::*;
use tokio::net::TcpStream;
use std::sync::mpsc::{Receiver, Sender};
use zettabgp::prelude::*;
use std::time::Duration;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::task::yield_now;
use crate::febgp::BgpPeer;

const BGP_PORT: u16 = 179;

pub struct BgpSession {
    _remote: BgpPeer,
    params: BgpSessionParams,
    rx_event: Receiver<BgpEvent>,
    tx_event: Sender<BgpEvent>,
    tx_socket: Option<WriteHalf<TcpStream>>,

    status: BgpState,
    _connect_retry_counter: u32,
    _connect_retry_timer: u32,
    _connect_retry_time: u32,
    _hold_timer: u32,
    _hold_time: u32,
    _keepalive_timer: u32,
    _keepalive_time: u32,
}

impl BgpSession {
    pub fn new(params: BgpSessionParams, rx: Receiver<BgpEvent>, tx: Sender<BgpEvent>, peer: BgpPeer) -> Self {
        BgpSession{
            params: params,
            rx_event: rx,
            tx_event: tx,
            tx_socket: None,
            _remote: peer,
            status: BgpState::Idle,
            _connect_retry_counter: 0,
            _connect_retry_timer: 0,
            _connect_retry_time: 0,
            _hold_timer: 0,
            _hold_time: 0,
            _keepalive_timer: 0,
            _keepalive_time: 0,
        }
    }
    async fn connect(&mut self) {
        match TcpStream::connect(format!("{}:{}", "[2001:db8::1]", BGP_PORT)).await {
            Ok(socket) => {
                let (rx, tx) = split(socket);
                self.tx_socket = Some(tx);

                let tx_event = self.tx_event.clone();
                //let sock = self.socket.as_mut().unwrap();
                let params = self.params.clone();

                tokio::spawn(async move {
                    BgpSession::receive(params, rx, tx_event).await;
                });

                warn!("Transport established!");
                self.tx_event.send(BgpEvent::TransportEstablished).unwrap();
            }
            Err(_) => {
                error!("Failed to establish connection with {}", "2001:db8::1");
                self.tx_event.send(BgpEvent::TransportClosed).unwrap();

            }
        }
    }

    async fn receive(params: BgpSessionParams, mut rx: ReadHalf<TcpStream>, tx: Sender<BgpEvent>) {
        warn!("Started receive thread");

        let mut buf = [0u8; 32768];

        loop {
            yield_now().await;
            match rx.read_exact(&mut buf[0..19]).await {
                Ok(_) => {
                    let message_head = params.decode_message_head(&buf).unwrap();
                    match message_head.0 {

                        // OPEN
                        BgpMessageType::Open => {
                            rx.read_exact(&mut buf[0..message_head.1]).await.unwrap();
                            let mut msg = BgpOpenMessage::new();
                            msg.decode_from(&params, &buf[0..message_head.1]).unwrap();
                            //info!("Connected to AS {}, hold-time: {}, router-id: {:?}, capabilities: {:?}",
                            //    msg.as_num,
                            //    msg.hold_time,
                            //    msg.router_id,
                            //    msg.caps);
                            tx.send(BgpEvent::OpenMessageReceived).unwrap();
                        },

                        // KEEPALIVE
                        BgpMessageType::Keepalive => {
                            tx.send(BgpEvent::KeepaliveReceived).unwrap();
                        },

                        // UPDATE
                        BgpMessageType::Update => {
                            rx.read_exact(&mut buf[0..message_head.1]).await.unwrap();
                            let mut msg = BgpUpdateMessage::new();
                            msg.decode_from(&params, &buf[0..message_head.1]).unwrap();
                            //debug!("Update: {:?}", msg);

                            tx.send(BgpEvent::UpdateMessageReceived).unwrap();
                        },

                        // NOTIFICATION
                        BgpMessageType::Notification => {
                            rx.read_exact(&mut buf[0..message_head.1]).await.unwrap();
                            let mut msg = BgpNotificationMessage::new();
                            msg.decode_from(&params, &buf[0..message_head.1]).unwrap();
                            tx.send(BgpEvent::NotificationMessageReceived).unwrap();
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to read from socket: {}", e);
                    drop(rx);
                    tx.send(BgpEvent::TransportClosed).unwrap();
                    return;
                }
            }
        }
    }

    async fn send_open(&mut self) {
        let mut buf = [0u8; 32768];

        let open_my = self.params.open_message();
        let open_sz = open_my.encode_to(&self.params, &mut buf[19..]).unwrap();
        let to_send = self.params.prepare_message_buf(&mut buf, BgpMessageType::Open, open_sz).unwrap();

        match self.tx_socket {
            Some(ref mut tx_socket) => {
                tx_socket.write_all(&buf[0..to_send]).await.unwrap();
            },
            None => {
                error!("Failed to send Open message");
                self.tx_event.send(BgpEvent::TransportClosed).unwrap();
            }
        }

        self.tx_event.send(BgpEvent::OpenMessageSent).unwrap();
    }

    async fn send_keepalive(&mut self) {
        let mut buf = [0u8; 32768];

        let keepalive_message = BgpKeepaliveMessage{};
        let open_sz = keepalive_message.encode_to(&self.params, &mut buf[19..]).unwrap();
        let to_send = self.params.prepare_message_buf(&mut buf, BgpMessageType::Keepalive, open_sz).unwrap();

        match self.tx_socket {
            Some(ref mut tx_socket) => {
                tx_socket.write_all(&buf[0..to_send]).await.unwrap();
            },
            None => {
                error!("Failed to send Keepalive message");
                self.tx_event.send(BgpEvent::TransportClosed).unwrap();
            }
        }
    }

    async fn send_updates(&mut self) {
        debug!("Sending updates");
    }

    async fn reset_connection(&mut self) {
        match self.tx_socket {
            Some(ref mut tx_socket) => {
                tx_socket.shutdown().await.unwrap();
            },
            None => {}
        }

        self.tx_event.send(BgpEvent::TransportClosed).unwrap();
    }

    async fn get_event(&mut self) -> BgpEvent {
        self.rx_event.recv().unwrap()
    }

    pub async fn start(&mut self) -> Result<(), String> {
        if self.status != BgpState::Idle {
            return Err(String::from("BGP FSM not in idle state!"));
        }
        self.tx_event.send(BgpEvent::ManualStart).expect("TODO: panic message");
        self.run_fsm().await;
        
        Ok(())
    }

    fn set_state(&mut self, state: BgpState) {
        info!("BGP Status: {:?}", state);
        self.status = state;
    }

    async fn run_fsm(&mut self) {
        loop {
            yield_now().await;
            match self.status {

                BgpState::Idle => {
                    match self.get_event().await {

                        BgpEvent::ManualStart => {
                            info!("Idle: ManualStart");
                            self.set_state(BgpState::Connect);
                            self.connect().await;
                        },
                        event => {
                            error!("Idle: Unexpected event received. Event: {:?}", event);
                            self.reset_connection().await;
                        },
                    }
                }

                BgpState::Active => {
                    match self.get_event().await {
                        BgpEvent::TransportClosed => {
                            info!("Active: TransportClosed - waiting 3s before trying to reconnect...");
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            self.connect().await;
                        },
                        BgpEvent::TransportEstablished => {
                            info!("Active: TransportEstablished");
                            self.send_open().await;
                        },

                        BgpEvent::OpenMessageSent => {
                            info!("Active: OpenMessageSent");
                            self.set_state(BgpState::OpenSent);
                        }

                        BgpEvent::OpenMessageReceived => {
                            info!("Active: OpenMessageReceived");
                            self.set_state(BgpState::OpenConfirm);
                        }

                        event => {
                            info!("Active: Unexpected event received. Event: {:?}", event);
                            self.reset_connection().await;
                        },

                    }
                }

                BgpState::Connect => {
                    match self.get_event().await {

                        BgpEvent::TransportEstablished => {
                            info!("Connect: TransportEstablished");
                            self.send_open().await;
                        },

                        BgpEvent::TransportClosed => {
                            info!("Connect: TransportClosed - waiting 3s before trying to reconnect...");
                            self.set_state(BgpState::Active);
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            self.connect().await;
                        },

                        BgpEvent::OpenMessageSent => {
                            info!("Connect: OpenMessageSent");
                            self.set_state(BgpState::OpenSent);
                        }

                        BgpEvent::OpenMessageReceived => {
                            info!("Connect: OpenMessageReceived");
                            self.set_state(BgpState::OpenConfirm);
                        }

                        event => {
                            error!("Connect: Unexpected event received. Event: {:?}", event);
                            self.reset_connection().await;
                        },
                    }
                }

                BgpState::OpenSent => {
                    match self.get_event().await {

                        BgpEvent::TransportClosed => {
                            info!("OpenSent: TransportClosed - waiting 3s before trying to reconnect...");
                            self.set_state(BgpState::Active);
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            self.connect().await;
                        },

                        BgpEvent::OpenMessageReceived => {
                            info!("OpenSent: OpenMessageReceived");
                            self.set_state(BgpState::OpenConfirm);
                        }

                        event => {
                            error!("OpenSent: Unexpected event received. Event: {:?}", event);
                            self.reset_connection().await;
                        },
                    }
                }

                BgpState::OpenConfirm => {
                    match self.get_event().await {

                        BgpEvent::KeepaliveReceived => {
                            info!("OpenConfirm: KeepaliveReceived");
                            self.set_state(BgpState::Established);
                            self.send_keepalive().await;
                            self.send_updates().await;
                        }

                        BgpEvent::TransportClosed => {
                            info!("OpenConfirm: TransportClosed - waiting 3s before trying to reconnect...");
                            self.set_state(BgpState::Active);
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            self.connect().await;
                        },

                        event => {
                            error!("OpenConfirm: Unexpected event received. Event: {:?}", event);
                            self.reset_connection().await;
                        },
                    }
                }

                BgpState::Established => {
                    match self.get_event().await {

                        BgpEvent::TransportClosed => {
                            info!("Established: TransportClosed - waiting 3s before trying to reconnect...");
                            self.set_state(BgpState::Active);
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            self.connect().await;
                        },

                        BgpEvent::KeepaliveReceived => {
                            info!("Established: KeepaliveReceived");
                            self.send_keepalive().await;
                        }

                        BgpEvent::UpdateMessageReceived => {
                            info!("Established: UpdateMessageReceived");
                            // TODO: Implement
                        }

                        event => {
                            error!("Established: Unexpected event received. Event: {:?}", event);
                            //self.reset_connection().await;
                        },
                    }
                }
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum BgpState {
    /// The initial state where BGP is idle and not attempting to connect.
    Idle,

    /// BGP actively retries to connect after a failed attempt.
    Active,

    /// BGP is attempting to establish a TCP connection.
    Connect,

    /// BGP has sent an OPEN message and is waiting for a response.
    OpenSent,

    /// BGP has received a valid OPEN message and is waiting for KEEPALIVE.
    OpenConfirm,

    /// The BGP session is fully established, and routes are exchanged.
    Established,
}

/// Enum representing BGP events that trigger FSM state transitions.
#[derive(Debug, PartialEq)]
pub enum BgpEvent {
    /// Operator manually starts the BGP session.
    ManualStart,
    // Operator manually stops the BGP session.
    // TODO: ManualStop,
    // Operator clears the BGP session.
    // TODO: ManualClear,
    // Operator restarts the BGP session.
    // TODO: ManualRestart,
    /// TCP transport connection is successfully established.
    TransportEstablished,
    /// TCP transport connection is closed or fails.
    TransportClosed,
    /// The FSM has sent an OPEN message.
    OpenMessageSent,
    /// The FSM receives a KEEPALIVE message.
    OpenMessageReceived,
    /// The FSM receives a KEEPALIVE message.
    KeepaliveReceived,
    /// The FSM receives an UPDATE message.
    UpdateMessageReceived,
    /// The FSM receives a NOTIFICATION message.
    NotificationMessageReceived,
    // Hold timer expires.
    // TODO: HoldTimerExpired,
    // Keepalive timer expires.
    // TODO: KeepaliveTimerExpired,
    // Connection retry timer expires.
    // TODO: ConnectionRetryTimerExpired,
    // The FSM receives an event indicating a collision with another BGP session.
    // TODO: CollisionDetected,
}

/// Trait to print BGP Notification messages with human-readable details.
#[allow(unused)]
pub trait NotificationPrinter {
    fn print(&self);
}

impl NotificationPrinter for BgpNotificationMessage {
    fn print(&self) {
        let description = match (self.error_code, self.error_subcode) {
            // Message Header Errors (Error Code 1)
            (1, 1) => "Message Header Error: Connection Not Synchronized",
            (1, 2) => "Message Header Error: Bad Message Length",
            (1, 3) => "Message Header Error: Bad Message Type",

            // OPEN Message Errors (Error Code 2)
            (2, 1) => "OPEN Message Error: Unsupported Version Number",
            (2, 2) => "OPEN Message Error: Bad Peer AS",
            (2, 3) => "OPEN Message Error: Bad BGP Identifier",
            (2, 4) => "OPEN Message Error: Unsupported Optional Parameter",

            // Update Message Errors (Error Code 3)
            (3, 1) => "UPDATE Message Error: Malformed Attribute List",
            (3, 2) => "UPDATE Message Error: Unrecognized Well-Known Attribute",
            (3, 3) => "UPDATE Message Error: Missing Well-Known Attribute",
            (3, 4) => "UPDATE Message Error: Attribute Flags Error",
            (3, 5) => "UPDATE Message Error: Attribute Length Error",
            (3, 6) => "UPDATE Message Error: Invalid ORIGIN Attribute",
            (3, 7) => "UPDATE Message Error: AS Routing Loop",
            (3, 8) => "UPDATE Message Error: Invalid NEXT_HOP Attribute",
            (3, 9) => "UPDATE Message Error: Optional Attribute Error",
            (3, 10) => "UPDATE Message Error: Invalid Network Field",
            (3, 11) => "UPDATE Message Error: Malformed AS_PATH",

            // Hold Timer Expired (Error Code 4)
            (4, 0) => "Hold Timer Expired",

            // FSM Errors (Error Code 5)
            (5, 0) => "FSM Error",

            // Cease (Error Code 6)
            (6, 1) => "Cease: Maximum Number of Prefixes Reached",
            (6, 2) => "Cease: Administrative Shutdown",
            (6, 3) => "Cease: Peer Deconfigured",
            (6, 4) => "Cease: Administrative Reset",
            (6, 5) => "Cease: Connection Rejected",
            (6, 6) => "Cease: Other Configuration Change",
            (6, 7) => "Cease: Connection Collision Resolution",
            (6, 8) => "Cease: Out of Resources",

            // Unknown errors
            _ => "Unknown Notification Error",
        };

        println!("BGP Notification:");
        println!("  Error Code: {:?}", self.error_code);
        println!("  Error Subcode: {:?}", self.error_subcode);
        println!("  Description: {}", description);
        /* TODO
        if !self.data.is_empty() {
            println!("  Additional Data: {:?}", self.data);
        }

         */
    }
}