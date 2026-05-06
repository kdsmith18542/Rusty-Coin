//! Network Simulation Tests
//! Per remediation plan Phase 4.1 - Network Simulation
//! Per spec 09 Section 9.3.7

mod network_simulation;

// Re-export tests from submodules
use network_simulation::high_volume::*;
use network_simulation::latency::*;
use network_simulation::malicious_peers::*;
use network_simulation::network_partition::*;
