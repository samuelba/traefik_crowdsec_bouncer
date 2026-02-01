/// Attributes for the IP entry in the lookup table.
pub struct CacheAttributes {
    /// Whether the IP is allowed or not.
    pub allowed: bool,
    /// The expiration time of the IP.
    pub expiration_time: i64,
}

impl CacheAttributes {
    pub fn new(allowed: bool, expiration_time: i64) -> CacheAttributes {
        CacheAttributes {
            allowed,
            expiration_time,
        }
    }
}

/// The health status of the application.
pub struct HealthStatus {
    pub live_status: bool,
    pub stream_status: bool,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthStatus {
    pub fn new() -> HealthStatus {
        HealthStatus {
            live_status: true,
            stream_status: true,
        }
    }
    pub fn healthy(&self) -> bool {
        self.live_status && self.stream_status
    }
}
