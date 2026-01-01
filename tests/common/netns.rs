use std::process::{Command, Child, Stdio};
use std::io;
use std::path::PathBuf;
use tempfile::TempDir;

/// A network namespace with automatic cleanup
pub struct NetNs {
    pub name: String,
    /// Temp directory for FRR runtime files (sockets, pid files)
    pub run_dir: TempDir,
}

impl NetNs {
    /// Create a new network namespace
    pub fn new(name: &str) -> io::Result<Self> {
        let run_dir = tempfile::tempdir()?;

        let status = Command::new("ip")
            .args(["netns", "add", name])
            .status()?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create netns {}", name),
            ));
        }

        // Bring up loopback
        let status = Command::new("ip")
            .args(["netns", "exec", name, "ip", "link", "set", "lo", "up"])
            .status()?;

        if !status.success() {
            // Clean up the namespace we just created
            let _ = Command::new("ip").args(["netns", "del", name]).status();
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to bring up loopback in {}", name),
            ));
        }

        Ok(Self {
            name: name.to_string(),
            run_dir,
        })
    }

    /// Spawn a long-running process in this namespace
    pub fn spawn(&self, cmd: &str, args: &[&str]) -> io::Result<Child> {
        Command::new("ip")
            .args(["netns", "exec", &self.name, cmd])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    /// Get the run directory path
    pub fn run_dir_path(&self) -> PathBuf {
        self.run_dir.path().to_path_buf()
    }
}

impl Drop for NetNs {
    fn drop(&mut self) {
        // Kill any processes still running in the namespace
        let _ = Command::new("ip")
            .args(["netns", "pids", &self.name])
            .output()
            .map(|output| {
                if let Ok(pids) = String::from_utf8(output.stdout) {
                    for pid in pids.lines() {
                        let _ = Command::new("kill").args(["-9", pid]).status();
                    }
                }
            });

        // Delete the namespace
        let _ = Command::new("ip")
            .args(["netns", "del", &self.name])
            .status();
    }
}

/// Create a veth pair connecting two namespaces
pub fn create_veth_pair(
    ns1: &NetNs,
    iface1: &str,
    ns2: &NetNs,
    iface2: &str,
) -> io::Result<()> {
    // Create the veth pair in ns1 with a temporary peer name
    // (both ends can't have the same name in the same namespace)
    let temp_peer = format!("{}_tmp", iface2);
    let status = Command::new("ip")
        .args([
            "netns", "exec", &ns1.name,
            "ip", "link", "add", iface1, "type", "veth", "peer", "name", &temp_peer,
        ])
        .status()?;

    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to create veth pair",
        ));
    }

    // Move the peer to ns2
    let status = Command::new("ip")
        .args([
            "netns", "exec", &ns1.name,
            "ip", "link", "set", &temp_peer, "netns", &ns2.name,
        ])
        .status()?;

    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to move veth to second namespace",
        ));
    }

    // Rename the peer in ns2 to the desired name
    let status = Command::new("ip")
        .args([
            "netns", "exec", &ns2.name,
            "ip", "link", "set", &temp_peer, "name", iface2,
        ])
        .status()?;

    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to rename {} to {}", temp_peer, iface2),
        ));
    }

    // Bring up both interfaces
    let status = Command::new("ip")
        .args(["netns", "exec", &ns1.name, "ip", "link", "set", iface1, "up"])
        .status()?;

    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to bring up {}", iface1),
        ));
    }

    let status = Command::new("ip")
        .args(["netns", "exec", &ns2.name, "ip", "link", "set", iface2, "up"])
        .status()?;

    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to bring up {}", iface2),
        ));
    }

    Ok(())
}

/// Wait for a condition with timeout
pub fn wait_for<F>(mut condition: F, timeout_secs: u64, poll_ms: u64) -> bool
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let poll = std::time::Duration::from_millis(poll_ms);

    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        std::thread::sleep(poll);
    }
    false
}
