use std::io::{self, Read, Write};
use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const BGP_MARKER: [u8; 16] = [0xFF; 16];
pub const BGP_VERSION: u8 = 4;
pub const BGP_HEADER_LEN: usize = 19;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
}

impl TryFrom<u8> for MessageType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MessageType::Open),
            2 => Ok(MessageType::Update),
            3 => Ok(MessageType::Notification),
            4 => Ok(MessageType::Keepalive),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid BGP message type: {}", value),
            )),
        }
    }
}

/// BGP message header for synchronous I/O.
///
/// Used by the legacy `Session` struct and unit tests.
/// The async `TcpTransport` handles header parsing internally.
#[allow(dead_code)]
#[derive(Debug)]
pub struct Header {
    pub length: u16,
    pub msg_type: MessageType,
}

#[allow(dead_code)]
impl Header {
    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut marker = [0u8; 16];
        reader.read_exact(&mut marker)?;

        if marker != BGP_MARKER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid BGP marker",
            ));
        }

        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf)?;
        let length = u16::from_be_bytes(buf);

        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf)?;
        let msg_type = MessageType::try_from(type_buf[0])?;

        Ok(Header { length, msg_type })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&BGP_MARKER)?;
        writer.write_all(&self.length.to_be_bytes())?;
        writer.write_all(&[self.msg_type as u8])?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct OpenMessage {
    pub version: u8,
    pub asn: u16,
    pub hold_time: u16,
    pub router_id: Ipv4Addr,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone)]
pub enum Capability {
    MultiProtocol { afi: u16, safi: u8 },
    FourOctetAs { asn: u32 },
    /// Unknown or unsupported capability (preserved for completeness).
    Unknown { code: u8, data: Vec<u8> },
}

impl Capability {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(8);
        match self {
            Capability::MultiProtocol { afi, safi } => {
                buf.put_u8(1); // Type 1
                buf.put_u8(4); // Length 4
                buf.put_u16(*afi);
                buf.put_u8(0); // Reserved
                buf.put_u8(*safi);
            }
            Capability::FourOctetAs { asn } => {
                buf.put_u8(65); // Type 65
                buf.put_u8(4); // Length 4
                buf.put_u32(*asn);
            }
            Capability::Unknown { code, data } => {
                buf.put_u8(*code);
                buf.put_u8(data.len() as u8);
                buf.put_slice(data);
            }
        }
        buf.freeze()
    }

    pub fn decode(data: &mut impl Buf) -> io::Result<Self> {
        if data.remaining() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Capability too short",
            ));
        }

        let cap_type = data.get_u8();
        let cap_len = data.get_u8() as usize;

        if data.remaining() < cap_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Capability data too short",
            ));
        }

        let cap = match cap_type {
            1 => {
                // Multiprotocol
                if cap_len != 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid multiprotocol capability length",
                    ));
                }
                let afi = data.get_u16();
                let _reserved = data.get_u8();
                let safi = data.get_u8();
                Capability::MultiProtocol { afi, safi }
            }
            65 => {
                // 4-octet AS
                if cap_len != 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid 4-octet AS capability length",
                    ));
                }
                let asn = data.get_u32();
                Capability::FourOctetAs { asn }
            }
            _ => {
                // Unknown capability, preserve it
                let mut cap_data = vec![0u8; cap_len];
                data.copy_to_slice(&mut cap_data);
                Capability::Unknown { code: cap_type, data: cap_data }
            }
        };

        Ok(cap)
    }
}

impl OpenMessage {
    /// Create a new OPEN message with specified address families.
    pub fn new_with_families(
        asn: u32,
        hold_time: u16,
        router_id: Ipv4Addr,
        ipv4_unicast: bool,
        ipv6_unicast: bool,
    ) -> Self {
        let mut capabilities = Vec::new();

        // Add address family capabilities
        if ipv4_unicast {
            capabilities.push(Capability::MultiProtocol { afi: 1, safi: 1 });
        }
        if ipv6_unicast {
            capabilities.push(Capability::MultiProtocol { afi: 2, safi: 1 });
        }

        // 4-octet AS support
        capabilities.push(Capability::FourOctetAs { asn });

        Self {
            version: BGP_VERSION,
            asn: if asn > 65535 { 23456 } else { asn as u16 }, // AS_TRANS if > 16-bit
            hold_time,
            router_id,
            capabilities,
        }
    }

    /// Create a new OPEN message with default address families (IPv6 only for BGP unnumbered).
    pub fn new(asn: u32, hold_time: u16, router_id: Ipv4Addr) -> Self {
        Self::new_with_families(asn, hold_time, router_id, false, true)
    }

    pub fn encode(&self) -> Bytes {
        let mut opt_params = BytesMut::new();

        // Encode capabilities as optional parameter type 2
        let mut cap_data = BytesMut::new();
        for cap in &self.capabilities {
            cap_data.put(cap.encode());
        }

        if !cap_data.is_empty() {
            opt_params.put_u8(2); // Parameter type: Capabilities
            opt_params.put_u8(cap_data.len() as u8);
            opt_params.put(cap_data);
        }

        let mut msg = BytesMut::with_capacity(10 + opt_params.len());
        msg.put_u8(self.version);
        msg.put_u16(self.asn);
        msg.put_u16(self.hold_time);
        msg.put_slice(&self.router_id.octets());
        msg.put_u8(opt_params.len() as u8);
        msg.put(opt_params);

        msg.freeze()
    }

    pub fn decode(data: &mut impl Buf) -> io::Result<Self> {
        if data.remaining() < 10 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OPEN message too short",
            ));
        }

        let version = data.get_u8();
        let asn = data.get_u16();
        let hold_time = data.get_u16();
        let mut router_id_bytes = [0u8; 4];
        data.copy_to_slice(&mut router_id_bytes);
        let router_id = Ipv4Addr::from(router_id_bytes);
        let opt_param_len = data.get_u8() as usize;

        let mut capabilities = Vec::new();

        if opt_param_len > 0 && data.remaining() >= opt_param_len {
            let mut opt_data = data.copy_to_bytes(opt_param_len);

            while opt_data.remaining() >= 2 {
                let param_type = opt_data.get_u8();
                let param_len = opt_data.get_u8() as usize;

                if opt_data.remaining() < param_len {
                    break;
                }

                if param_type == 2 {
                    // Capabilities
                    let mut cap_buf = opt_data.copy_to_bytes(param_len);
                    while cap_buf.has_remaining() {
                        match Capability::decode(&mut cap_buf) {
                            Ok(cap) => {
                                capabilities.push(cap);
                            }
                            Err(_) => break,
                        }
                    }
                } else {
                    opt_data.advance(param_len);
                }
            }
        }

        Ok(Self {
            version,
            asn,
            hold_time,
            router_id,
            capabilities,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        let body = self.encode();
        let length = (BGP_HEADER_LEN + body.len()) as u16;

        let mut buf = BytesMut::with_capacity(length as usize);
        buf.put_slice(&BGP_MARKER);
        buf.put_u16(length);
        buf.put_u8(MessageType::Open as u8);
        buf.put(body);
        buf.freeze()
    }
}

pub struct KeepaliveMessage;

impl KeepaliveMessage {
    pub fn to_bytes() -> Bytes {
        let mut buf = BytesMut::with_capacity(BGP_HEADER_LEN);
        buf.put_slice(&BGP_MARKER);
        buf.put_u16(BGP_HEADER_LEN as u16);
        buf.put_u8(MessageType::Keepalive as u8);
        buf.freeze()
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Open(OpenMessage),
    Update(Bytes),
    Notification { code: u8, subcode: u8, data: Vec<u8> },
    Keepalive,
}

impl Message {
    /// Read a BGP message from a synchronous reader.
    ///
    /// Used by the legacy `Session` struct and unit tests.
    /// The async `TcpTransport` handles message reading internally.
    #[allow(dead_code)]
    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let header = Header::read(reader)?;

        let body_len = header.length as usize - BGP_HEADER_LEN;
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            reader.read_exact(&mut body)?;
        }

        match header.msg_type {
            MessageType::Open => {
                let mut buf = Bytes::from(body);
                let open = OpenMessage::decode(&mut buf)?;
                Ok(Message::Open(open))
            }
            MessageType::Update => Ok(Message::Update(Bytes::from(body))),
            MessageType::Notification => {
                let mut buf = Bytes::from(body);
                let code = if buf.has_remaining() { buf.get_u8() } else { 0 };
                let subcode = if buf.has_remaining() { buf.get_u8() } else { 0 };
                let data = if buf.has_remaining() {
                    buf.to_vec()
                } else {
                    Vec::new()
                };
                Ok(Message::Notification { code, subcode, data })
            }
            MessageType::Keepalive => Ok(Message::Keepalive),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ==================== MessageType Tests ====================

    #[test]
    fn test_message_type_try_from_valid() {
        assert_eq!(MessageType::try_from(1).unwrap(), MessageType::Open);
        assert_eq!(MessageType::try_from(2).unwrap(), MessageType::Update);
        assert_eq!(MessageType::try_from(3).unwrap(), MessageType::Notification);
        assert_eq!(MessageType::try_from(4).unwrap(), MessageType::Keepalive);
    }

    #[test]
    fn test_message_type_try_from_invalid() {
        assert!(MessageType::try_from(0).is_err());
        assert!(MessageType::try_from(5).is_err());
        assert!(MessageType::try_from(255).is_err());
    }

    // ==================== Header Tests ====================

    #[test]
    fn test_header_write_read_roundtrip() {
        let header = Header {
            length: 29,
            msg_type: MessageType::Open,
        };

        let mut buf = Vec::new();
        header.write(&mut buf).unwrap();

        assert_eq!(buf.len(), BGP_HEADER_LEN);

        let mut cursor = Cursor::new(buf);
        let decoded = Header::read(&mut cursor).unwrap();

        assert_eq!(decoded.length, 29);
        assert_eq!(decoded.msg_type, MessageType::Open);
    }

    #[test]
    fn test_header_format() {
        let header = Header {
            length: 19,
            msg_type: MessageType::Keepalive,
        };

        let mut buf = Vec::new();
        header.write(&mut buf).unwrap();

        // Check marker (16 bytes of 0xFF)
        assert_eq!(&buf[0..16], &BGP_MARKER);
        // Check length (big-endian u16)
        assert_eq!(&buf[16..18], &[0x00, 0x13]); // 19 in big-endian
        // Check message type
        assert_eq!(buf[18], 4); // Keepalive
    }

    #[test]
    fn test_header_invalid_marker() {
        let mut buf = vec![0x00; 19]; // Invalid marker (not all 0xFF)
        buf[16] = 0x00;
        buf[17] = 0x13;
        buf[18] = 4;

        let mut cursor = Cursor::new(buf);
        let result = Header::read(&mut cursor);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid BGP marker"));
    }

    #[test]
    fn test_header_invalid_message_type() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&19u16.to_be_bytes());
        buf.push(99); // Invalid message type

        let mut cursor = Cursor::new(buf);
        let result = Header::read(&mut cursor);

        assert!(result.is_err());
    }

    // ==================== Capability Tests ====================

    #[test]
    fn test_capability_multiprotocol_encode_decode() {
        let cap = Capability::MultiProtocol { afi: 2, safi: 1 }; // IPv6 unicast
        let encoded = cap.encode();

        assert_eq!(&encoded[..], &[1, 4, 0, 2, 0, 1]); // Type=1, Len=4, AFI=2, Reserved=0, SAFI=1

        let mut buf = encoded;
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(buf.remaining(), 0);

        match decoded {
            Capability::MultiProtocol { afi, safi } => {
                assert_eq!(afi, 2);
                assert_eq!(safi, 1);
            }
            _ => panic!("Expected MultiProtocol capability"),
        }
    }

    #[test]
    fn test_capability_four_octet_as_encode_decode() {
        let cap = Capability::FourOctetAs { asn: 65001 };
        let encoded = cap.encode();

        assert_eq!(&encoded[..], &[65, 4, 0, 0, 0xFD, 0xE9]); // Type=65, Len=4, ASN=65001

        let mut buf = encoded;
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(buf.remaining(), 0);

        match decoded {
            Capability::FourOctetAs { asn } => {
                assert_eq!(asn, 65001);
            }
            _ => panic!("Expected FourOctetAs capability"),
        }
    }

    #[test]
    fn test_capability_four_octet_as_large_asn() {
        let cap = Capability::FourOctetAs { asn: 4200000001 };
        let encoded = cap.encode();

        let mut buf = encoded;
        let decoded = Capability::decode(&mut buf).unwrap();

        match decoded {
            Capability::FourOctetAs { asn } => {
                assert_eq!(asn, 4200000001);
            }
            _ => panic!("Expected FourOctetAs capability"),
        }
    }

    #[test]
    fn test_capability_decode_too_short() {
        let mut data = Bytes::from_static(&[1]); // Only 1 byte
        let result = Capability::decode(&mut data);
        assert!(result.is_err());
    }

    #[test]
    fn test_capability_decode_data_too_short() {
        let mut data = Bytes::from_static(&[1, 4, 0, 2]); // Says length is 4 but only 2 bytes of data
        let result = Capability::decode(&mut data);
        assert!(result.is_err());
    }

    #[test]
    fn test_capability_decode_invalid_multiprotocol_length() {
        let mut data = Bytes::from_static(&[1, 3, 0, 2, 1]); // MultiProtocol with length 3 instead of 4
        let result = Capability::decode(&mut data);
        assert!(result.is_err());
    }

    #[test]
    fn test_capability_decode_unknown_type() {
        let mut data = Bytes::from_static(&[99, 2, 0x12, 0x34]); // Unknown capability type 99
        let cap = Capability::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        // Returns Unknown capability with preserved data
        match cap {
            Capability::Unknown { code, data } => {
                assert_eq!(code, 99);
                assert_eq!(data, vec![0x12, 0x34]);
            }
            _ => panic!("Expected Unknown capability"),
        }
    }

    // ==================== OpenMessage Tests ====================

    #[test]
    fn test_open_message_new_16bit_asn() {
        let open = OpenMessage::new(65001, 180, Ipv4Addr::new(1, 2, 3, 4));

        assert_eq!(open.version, BGP_VERSION);
        assert_eq!(open.asn, 65001);
        assert_eq!(open.hold_time, 180);
        assert_eq!(open.router_id, Ipv4Addr::new(1, 2, 3, 4));
        // IPv6 unicast + FourOctetAs (default is IPv6 only for BGP unnumbered)
        assert_eq!(open.capabilities.len(), 2);
    }

    #[test]
    fn test_open_message_new_32bit_asn() {
        let open = OpenMessage::new(4200000001, 180, Ipv4Addr::new(1, 2, 3, 4));

        // Should use AS_TRANS (23456) for 16-bit field
        assert_eq!(open.asn, 23456);

        // Should have 4-octet AS capability with real ASN
        let four_octet_cap = open.capabilities.iter().find(|c| {
            matches!(c, Capability::FourOctetAs { asn } if *asn == 4200000001)
        });
        assert!(four_octet_cap.is_some());
    }

    #[test]
    fn test_open_message_encode_decode_roundtrip() {
        let original = OpenMessage::new(65001, 180, Ipv4Addr::new(10, 0, 0, 1));
        let encoded = original.encode();
        let mut buf = encoded;
        let decoded = OpenMessage::decode(&mut buf).unwrap();

        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.asn, original.asn);
        assert_eq!(decoded.hold_time, original.hold_time);
        assert_eq!(decoded.router_id, original.router_id);
        assert_eq!(decoded.capabilities.len(), original.capabilities.len());
    }

    #[test]
    fn test_open_message_to_bytes_format() {
        let open = OpenMessage {
            version: 4,
            asn: 65001,
            hold_time: 180,
            router_id: Ipv4Addr::new(1, 2, 3, 4),
            capabilities: vec![],
        };

        let bytes = open.to_bytes();

        // Check header
        assert_eq!(&bytes[0..16], &BGP_MARKER);
        // Length should be header (19) + body (10 for OPEN with no capabilities)
        let length = u16::from_be_bytes([bytes[16], bytes[17]]);
        assert_eq!(length, 29);
        // Message type
        assert_eq!(bytes[18], MessageType::Open as u8);
        // Version
        assert_eq!(bytes[19], 4);
        // ASN
        assert_eq!(u16::from_be_bytes([bytes[20], bytes[21]]), 65001);
        // Hold time
        assert_eq!(u16::from_be_bytes([bytes[22], bytes[23]]), 180);
        // Router ID
        assert_eq!(&bytes[24..28], &[1, 2, 3, 4]);
        // Opt param length (0 for no capabilities)
        assert_eq!(bytes[28], 0);
    }

    #[test]
    fn test_open_message_decode_too_short() {
        let mut data = Bytes::from_static(&[4, 0, 1, 0, 180]); // Only 5 bytes, need at least 10
        let result = OpenMessage::decode(&mut data);
        assert!(result.is_err());
    }

    #[test]
    fn test_open_message_decode_minimal() {
        // Minimal valid OPEN: version + asn + hold_time + router_id + opt_param_len
        let mut data = Bytes::from_static(&[
            4,          // version
            0xFD, 0xE9, // ASN 65001
            0, 180,     // hold_time 180
            10, 0, 0, 1, // router_id 10.0.0.1
            0,          // opt_param_len 0
        ]);

        let decoded = OpenMessage::decode(&mut data).unwrap();

        assert_eq!(decoded.version, 4);
        assert_eq!(decoded.asn, 65001);
        assert_eq!(decoded.hold_time, 180);
        assert_eq!(decoded.router_id, Ipv4Addr::new(10, 0, 0, 1));
        assert!(decoded.capabilities.is_empty());
    }

    #[test]
    fn test_open_message_with_capabilities_roundtrip() {
        let original = OpenMessage {
            version: 4,
            asn: 65002,
            hold_time: 90,
            router_id: Ipv4Addr::new(192, 168, 1, 1),
            capabilities: vec![
                Capability::MultiProtocol { afi: 1, safi: 1 }, // IPv4 unicast
                Capability::MultiProtocol { afi: 2, safi: 1 }, // IPv6 unicast
                Capability::FourOctetAs { asn: 65002 },
            ],
        };

        let encoded = original.encode();
        let mut buf = encoded;
        let decoded = OpenMessage::decode(&mut buf).unwrap();

        assert_eq!(decoded.version, 4);
        assert_eq!(decoded.asn, 65002);
        assert_eq!(decoded.hold_time, 90);
        assert_eq!(decoded.router_id, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(decoded.capabilities.len(), 3);
    }

    // ==================== KeepaliveMessage Tests ====================

    #[test]
    fn test_keepalive_message_format() {
        let bytes = KeepaliveMessage::to_bytes();

        assert_eq!(bytes.len(), BGP_HEADER_LEN);
        assert_eq!(&bytes[0..16], &BGP_MARKER);
        assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]), 19);
        assert_eq!(bytes[18], MessageType::Keepalive as u8);
    }

    // ==================== Message::read Tests ====================

    #[test]
    fn test_message_read_keepalive() {
        let bytes = KeepaliveMessage::to_bytes();
        let mut cursor = Cursor::new(bytes.to_vec());

        let msg = Message::read(&mut cursor).unwrap();

        assert!(matches!(msg, Message::Keepalive));
    }

    #[test]
    fn test_message_read_open() {
        let open = OpenMessage::new(65001, 180, Ipv4Addr::new(1, 2, 3, 4));
        let bytes = open.to_bytes();
        let mut cursor = Cursor::new(bytes.to_vec());

        let msg = Message::read(&mut cursor).unwrap();

        match msg {
            Message::Open(decoded) => {
                assert_eq!(decoded.asn, 65001);
                assert_eq!(decoded.hold_time, 180);
                assert_eq!(decoded.router_id, Ipv4Addr::new(1, 2, 3, 4));
            }
            _ => panic!("Expected Open message"),
        }
    }

    #[test]
    fn test_message_read_update() {
        let update_body: &[u8] = &[0x00, 0x00, 0x00, 0x00]; // Minimal UPDATE body
        let length = (BGP_HEADER_LEN + update_body.len()) as u16;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&BGP_MARKER);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.push(MessageType::Update as u8);
        bytes.extend_from_slice(update_body);

        let mut cursor = Cursor::new(bytes);
        let msg = Message::read(&mut cursor).unwrap();

        match msg {
            Message::Update(body) => {
                assert_eq!(&body[..], update_body);
            }
            _ => panic!("Expected Update message"),
        }
    }

    #[test]
    fn test_message_read_notification() {
        let code = 6u8; // Cease
        let subcode = 4u8; // Administrative Reset
        let data = vec![0x01, 0x02, 0x03];

        let body_len = 2 + data.len();
        let length = (BGP_HEADER_LEN + body_len) as u16;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&BGP_MARKER);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.push(MessageType::Notification as u8);
        bytes.push(code);
        bytes.push(subcode);
        bytes.extend_from_slice(&data);

        let mut cursor = Cursor::new(bytes);
        let msg = Message::read(&mut cursor).unwrap();

        match msg {
            Message::Notification {
                code: c,
                subcode: s,
                data: d,
            } => {
                assert_eq!(c, 6);
                assert_eq!(s, 4);
                assert_eq!(d, vec![0x01, 0x02, 0x03]);
            }
            _ => panic!("Expected Notification message"),
        }
    }

    #[test]
    fn test_message_read_notification_minimal() {
        // Notification with only code and subcode, no data
        let length = (BGP_HEADER_LEN + 2) as u16;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&BGP_MARKER);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.push(MessageType::Notification as u8);
        bytes.push(2); // code
        bytes.push(1); // subcode

        let mut cursor = Cursor::new(bytes);
        let msg = Message::read(&mut cursor).unwrap();

        match msg {
            Message::Notification { code, subcode, data } => {
                assert_eq!(code, 2);
                assert_eq!(subcode, 1);
                assert!(data.is_empty());
            }
            _ => panic!("Expected Notification message"),
        }
    }

    #[test]
    fn test_message_read_notification_empty_body() {
        // Edge case: Notification with empty body (code and subcode default to 0)
        let length = BGP_HEADER_LEN as u16;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&BGP_MARKER);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.push(MessageType::Notification as u8);

        let mut cursor = Cursor::new(bytes);
        let msg = Message::read(&mut cursor).unwrap();

        match msg {
            Message::Notification { code, subcode, data } => {
                assert_eq!(code, 0);
                assert_eq!(subcode, 0);
                assert!(data.is_empty());
            }
            _ => panic!("Expected Notification message"),
        }
    }

    #[test]
    fn test_message_read_multiple_sequential() {
        // Test reading multiple messages from a stream
        let mut bytes = BytesMut::new();
        bytes.put(KeepaliveMessage::to_bytes());
        bytes.put(KeepaliveMessage::to_bytes());
        bytes.put(OpenMessage::new(65001, 180, Ipv4Addr::new(1, 1, 1, 1)).to_bytes());

        let mut cursor = Cursor::new(bytes.to_vec());

        let msg1 = Message::read(&mut cursor).unwrap();
        assert!(matches!(msg1, Message::Keepalive));

        let msg2 = Message::read(&mut cursor).unwrap();
        assert!(matches!(msg2, Message::Keepalive));

        let msg3 = Message::read(&mut cursor).unwrap();
        assert!(matches!(msg3, Message::Open(_)));
    }
}
