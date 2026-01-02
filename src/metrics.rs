//! Prometheus metrics for FeBGP.

use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder};
use std::sync::OnceLock;

/// Global metrics registry.
static REGISTRY: OnceLock<Registry> = OnceLock::new();

/// BGP session state gauge (1 if in state, 0 otherwise).
static SESSION_STATE: OnceLock<IntGaugeVec> = OnceLock::new();

/// Total routes in RIB.
static RIB_ROUTES_TOTAL: OnceLock<IntGaugeVec> = OnceLock::new();

/// Best routes in RIB.
static RIB_ROUTES_BEST: OnceLock<IntGaugeVec> = OnceLock::new();

/// BGP messages sent.
static MESSAGES_SENT: OnceLock<IntCounterVec> = OnceLock::new();

/// BGP messages received.
static MESSAGES_RECEIVED: OnceLock<IntCounterVec> = OnceLock::new();

/// Session state changes.
static SESSION_STATE_CHANGES: OnceLock<IntCounterVec> = OnceLock::new();

/// Initialize the metrics registry and all metrics.
pub fn init() {
    let registry = REGISTRY.get_or_init(Registry::new);

    // Session state gauge: labels are peer (interface) and state
    let session_state = IntGaugeVec::new(
        Opts::new("bgp_session_state", "BGP session state (1 if active)"),
        &["peer", "state"],
    )
    .expect("metric creation");
    registry
        .register(Box::new(session_state.clone()))
        .ok(); // Ignore if already registered
    SESSION_STATE.get_or_init(|| session_state);

    // RIB routes total
    let rib_total = IntGaugeVec::new(
        Opts::new("bgp_rib_routes_total", "Total routes in RIB"),
        &["afi"],
    )
    .expect("metric creation");
    registry.register(Box::new(rib_total.clone())).ok();
    RIB_ROUTES_TOTAL.get_or_init(|| rib_total);

    // RIB routes best
    let rib_best = IntGaugeVec::new(
        Opts::new("bgp_rib_routes_best", "Best routes in RIB"),
        &["afi"],
    )
    .expect("metric creation");
    registry.register(Box::new(rib_best.clone())).ok();
    RIB_ROUTES_BEST.get_or_init(|| rib_best);

    // Messages sent
    let sent = IntCounterVec::new(
        Opts::new("bgp_messages_sent_total", "BGP messages sent"),
        &["peer", "type"],
    )
    .expect("metric creation");
    registry.register(Box::new(sent.clone())).ok();
    MESSAGES_SENT.get_or_init(|| sent);

    // Messages received
    let received = IntCounterVec::new(
        Opts::new("bgp_messages_received_total", "BGP messages received"),
        &["peer", "type"],
    )
    .expect("metric creation");
    registry.register(Box::new(received.clone())).ok();
    MESSAGES_RECEIVED.get_or_init(|| received);

    // Session state changes
    let state_changes = IntCounterVec::new(
        Opts::new(
            "bgp_session_state_changes_total",
            "BGP session state transitions",
        ),
        &["peer", "from", "to"],
    )
    .expect("metric creation");
    registry.register(Box::new(state_changes.clone())).ok();
    SESSION_STATE_CHANGES.get_or_init(|| state_changes);
}

/// Record a session state change.
pub fn record_session_state(peer: &str, state: &str) {
    if let Some(gauge) = SESSION_STATE.get() {
        // Clear all states for this peer first
        for s in &["Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established"] {
            gauge.with_label_values(&[peer, s]).set(0);
        }
        // Set the current state
        gauge.with_label_values(&[peer, state]).set(1);
    }
}

/// Record a session state transition.
pub fn record_state_change(peer: &str, from: &str, to: &str) {
    if let Some(counter) = SESSION_STATE_CHANGES.get() {
        counter.with_label_values(&[peer, from, to]).inc();
    }
}

/// Record a message sent.
pub fn record_message_sent(peer: &str, msg_type: &str) {
    if let Some(counter) = MESSAGES_SENT.get() {
        counter.with_label_values(&[peer, msg_type]).inc();
    }
}

/// Record a message received.
pub fn record_message_received(peer: &str, msg_type: &str) {
    if let Some(counter) = MESSAGES_RECEIVED.get() {
        counter.with_label_values(&[peer, msg_type]).inc();
    }
}

/// Update RIB route counts.
pub fn update_rib_counts(ipv4_total: i64, ipv4_best: i64, ipv6_total: i64, ipv6_best: i64) {
    if let Some(total) = RIB_ROUTES_TOTAL.get() {
        total.with_label_values(&["ipv4"]).set(ipv4_total);
        total.with_label_values(&["ipv6"]).set(ipv6_total);
    }
    if let Some(best) = RIB_ROUTES_BEST.get() {
        best.with_label_values(&["ipv4"]).set(ipv4_best);
        best.with_label_values(&["ipv6"]).set(ipv6_best);
    }
}

/// Gather and encode all metrics in Prometheus text format.
pub fn gather() -> String {
    let registry = match REGISTRY.get() {
        Some(r) => r,
        None => return String::new(),
    };

    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    encoder.encode_to_string(&metric_families).unwrap_or_default()
}
