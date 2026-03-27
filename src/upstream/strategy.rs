use serde::{Deserialize, Serialize};

/// Upstream DNS server selection strategy.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamStrategy {
    #[default]
    Sequential,
    RoundRobin,
    LowestLatency,
}

impl std::fmt::Display for UpstreamStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sequential => write!(f, "sequential"),
            Self::RoundRobin => write!(f, "round-robin"),
            Self::LowestLatency => write!(f, "lowest-latency"),
        }
    }
}

impl std::str::FromStr for UpstreamStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sequential" => Ok(Self::Sequential),
            "round-robin" => Ok(Self::RoundRobin),
            "lowest-latency" => Ok(Self::LowestLatency),
            other => Err(format!("unknown strategy: {other}")),
        }
    }
}
