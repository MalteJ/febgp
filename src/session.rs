use log::{debug, error, info, warn};
use std::net::{Shutdown, TcpStream};
use zettabgp::{BgpMessage, BgpSessionParams};
use std::sync::mpsc::{Receiver, Sender};
use zettabgp::message::{BgpMessageType, BgpOpenMessage, BgpUpdateMessage};
use zettabgp::prelude::{BgpKeepaliveMessage, BgpNotificationMessage};
use std::io::{Read, Write};
use crate::febgp::BgpPeer;

const BGP_PORT: u16 = 179;

pub struct BgpSession {
    _remote: BgpPeer,
    socket: Option<TcpStream>,
    params: BgpSessionParams,
    rx_event: Receiver<BgpEvent>,
    tx_event: Sender<BgpEvent>,

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
            _remote: peer,
            status: BgpState::Idle,
            _connect_retry_counter: 0,
            _connect_retry_timer: 0,
            _connect_retry_time: 0,
            _hold_timer: 0,
            _hold_time: 0,
            _keepalive_timer: 0,
            socket: None,
            _keepalive_time: 0,
        }
    }
    async fn connect(&mut self) -> BgpState {
        info!("mutating to connect state");
        self.status = BgpState::Connect;

        match TcpStream::connect(format!("{}:{}", "[2001:db8::1]", BGP_PORT)) {
            Ok(socket) => {
                self.socket = Some(socket);
                self.tx_event.send(BgpEvent::TransportEstablished).unwrap();

                let tx = self.tx_event.clone();
                let sock = self.socket.as_mut().unwrap().try_clone().unwrap();
                let params = self.params.clone();
                std::thread::spawn(move || {
                    BgpSession::receive(params, sock, tx);
                });

                BgpState::Connect
            }
            Err(_) => {
                error!("Failed to establish connection with {}", "2001:db8::1");
                self.tx_event.send(BgpEvent::TransportClosed).unwrap();
                BgpState::Active
            }
        }
    }

    fn receive(params: BgpSessionParams, mut socket: TcpStream, tx: Sender<BgpEvent>) {
        debug!("Started receive thread");

        let mut buf = [0 as u8; 32768];

        loop {
            match socket.read_exact(&mut buf[0..19]) {
                Ok(_) => {
                    let message_head = params.decode_message_head(&buf).unwrap();
                    match message_head.0 {

                        // OPEN
                        BgpMessageType::Open => {
                            socket.read_exact(&mut buf[0..message_head.1]).unwrap();
                            let mut msg = BgpOpenMessage::new();
                            msg.decode_from(&params, &buf[0..message_head.1]).unwrap();
                            info!("Connected to AS {}, hold-time: {}, router-id: {:?}, capabilities: {:?}",
                                msg.as_num,
                                msg.hold_time,
                                msg.router_id,
                                msg.caps);
                            tx.send(BgpEvent::OpenMessageReceived).unwrap();
                        },

                        // KEEPALIVE
                        BgpMessageType::Keepalive => {
                            debug!("Keepalive received from {}", socket.peer_addr().unwrap());
                            tx.send(BgpEvent::KeepaliveReceived).unwrap();
                        },

                        // UPDATE
                        BgpMessageType::Update => {
                            socket.read_exact(&mut buf[0..message_head.1]).unwrap();
                            debug!("Update received from {}", socket.peer_addr().unwrap());
                            let mut msg = BgpUpdateMessage::new();
                            debug!("message_head: {:?}", message_head);
                            debug!("msg size: {}", message_head.1);
                            msg.decode_from(&params, &buf[0..message_head.1]).unwrap();
                            debug!("Update received from {}: {:?}", socket.peer_addr().unwrap(), msg);

                            tx.send(BgpEvent::UpdateMessageReceived).unwrap();
                        },

                        // NOTIFICATION
                        BgpMessageType::Notification => {
                            socket.read_exact(&mut buf[0..message_head.1]).unwrap();
                            let mut msg = BgpNotificationMessage::new();
                            msg.decode_from(&params, &buf[0..message_head.1]).unwrap();
                            warn!("Notification received from {}: {}", socket.peer_addr().unwrap(), msg);
                            tx.send(BgpEvent::NotificationMessageReceived).unwrap();
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to read from socket: {}", e);
                    tx.send(BgpEvent::TransportClosed).unwrap();
                    return;
                }
            }
        }
    }

    async fn send_open(&mut self) -> BgpState {
        let mut buf = [0 as u8; 32768];

        let open_my = self.params.open_message();
        let open_sz = open_my.encode_to(&self.params, &mut buf[19..]).unwrap();
        let to_send = self.params.prepare_message_buf(&mut buf, BgpMessageType::Open, open_sz).unwrap();

        self.socket.as_mut().unwrap().write_all(&buf[0..to_send]).unwrap();

        self.tx_event.send(BgpEvent::OpenMessageSent).unwrap();
        BgpState::OpenSent
    }

    async fn send_keepalive(&mut self) {
        let mut buf = [0 as u8; 32768];

        let keepalive_message = BgpKeepaliveMessage{};
        let open_sz = keepalive_message.encode_to(&self.params, &mut buf[19..]).unwrap();
        let to_send = self.params.prepare_message_buf(&mut buf, BgpMessageType::Keepalive, open_sz).unwrap();

        self.socket.as_mut().unwrap().write_all(&buf[0..to_send]).unwrap();
        debug!("Keepalive sent");
    }

    async fn send_updates(&mut self) {
        debug!("Sending updates");
    }

    fn reset_connection(&mut self) -> BgpState {
        self.socket.as_mut().unwrap().shutdown(Shutdown::Both).unwrap();

        BgpState::Idle
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

    async fn run_fsm(&mut self) {
        loop {
            match self.status {

                BgpState::Idle => {
                    info!("BGP State: Idle");
                    match self.get_event().await {

                        BgpEvent::ManualStart => {
                            debug!("BGP Event: ManualStart");
                            self.status = self.connect().await;
                        },
                        event => {
                            error!("Unexpected event received. State: {:?}, Event: {:?}", self.status, event);
                            self.status = self.reset_connection();
                        },
                    }
                }

                BgpState::Active => {
                    info!("BGP State: Active");
                    info!("Session entered Active state");
                    self.status = self.connect().await
                }

                BgpState::Connect => {
                    info!("BGP State: Connect");
                    match self.get_event().await {

                        BgpEvent::TransportEstablished => {
                            debug!("BGP Event: TransportEstablished");
                            self.status = self.send_open().await;
                        },

                        BgpEvent::TransportClosed => {
                            debug!("BGP Event: TransportClosed");
                            self.status = BgpState::Active;
                            self.status = self.connect().await;
                        },

                        event => {
                            error!("Unexpected event received. State: {:?}, Event: {:?}", self.status, event);
                            self.status = self.reset_connection();
                        },
                    }
                }

                BgpState::OpenSent => {
                    info!("BGP State: OpenSent");
                    match self.get_event().await {

                        BgpEvent::OpenMessageSent => {
                            debug!("BGP Event: OpenMessageSent");
                        }

                        BgpEvent::OpenMessageReceived => {
                            debug!("BGP Event: OpenMessageReceived");
                            self.status = BgpState::OpenConfirm;
                            self.send_keepalive().await;
                        }

                        event => {
                            error!("Unexpected event received. State: {:?}, Event: {:?}", self.status, event);
                            self.status = self.reset_connection();
                        },
                    }
                }

                BgpState::OpenConfirm => {
                    info!("BGP State: OpenConfirm");
                    match self.get_event().await {

                        BgpEvent::KeepaliveReceived => {
                            debug!("BGP Event: KeepaliveReceived");
                            self.status = BgpState::Established;
                            self.send_updates().await;
                        }

                        event => {
                            error!("Unexpected event received. State: {:?}, Event: {:?}", self.status, event);
                            self.status = self.reset_connection();
                        },
                    }
                }

                BgpState::Established => {
                    info!("BGP State: Established");
                    match self.get_event().await {

                        BgpEvent::KeepaliveReceived => {
                            debug!("BGP Event: KeepaliveReceived");
                            self.send_keepalive().await;
                        }

                        BgpEvent::UpdateMessageReceived => {
                            debug!("BGP Event: UpdateMessageReceived");
                            // TODO: Implement
                        }

                        event => {
                            error!("Unexpected event received. State: {:?}, Event: {:?}", self.status, event);
                            self.status = self.reset_connection();
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