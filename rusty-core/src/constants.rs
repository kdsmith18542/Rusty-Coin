/// OxideSend quorum lifetime in blocks (10,000 blocks ~ 17.36 days at 2.5 min/block)
/// Spec: [06_masternode_protocol_spec.md §6.5.1](https://github.com/rusty-coin/specs/blob/main/docs/specs/06_masternode_protocol_spec.md#651-oxidesend-instant-transaction-service)
pub const QUORUM_EXPIRATION_BLOCKS: u64 = 10_000;

/// Coinbase maturity period in blocks
pub const COINBASE_MATURITY_PERIOD_BLOCKS: u64 = 100;

/// Masternode collateral amount in satoshis
/// Spec: [06_masternode_protocol_spec.md §6.2.1](https://github.com/rusty-coin/specs/blob/main/docs/specs/06_masternode_protocol_spec.md#621-masternode-collateral)
pub const MASTERNODE_COLLATERAL_AMOUNT: u64 = 10_000;

/// Threshold for lock_time interpretation (timestamps vs. block heights)
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Minimum value for a transaction output to not be considered 'dust'
pub const DUST_LIMIT: u64 = 500; // 500 satoshis

/// Maximum block size in bytes
pub const MAX_BLOCK_SIZE: u64 = 1_000_000; // 1 MB (example)

/// Maximum script size in bytes
pub const MAX_SCRIPT_BYTES: usize = 10_000;

/// Maximum number of opcodes in a script
pub const MAX_OPCODE_COUNT: usize = 200;

/// Maximum stack items during script execution
pub const MAX_STACK_DEPTH: usize = 1000;

/// Maximum signature operations per transaction
pub const MAX_SIG_OPS: usize = 20;

/// Number of blocks after which a ticket transitions from Pending to Live
pub const POS_FINALITY_DEPTH: u64 = 1;

/// Maximum sequence number for a transaction input
pub const MAX_SEQUENCE: u32 = 0xFFFFFFFF; // Denotes a transaction input with disabled lock_time

/// Percentage of a ticket's value to be burned for non-participation.
pub const NON_PARTICIPATION_SLASH_PERCENTAGE: f64 = 0.10; // 10%

/// Percentage of a masternode's collateral to be burned for malicious behavior.
pub const MALICIOUS_BEHAVIOR_SLASH_PERCENTAGE: f64 = 1.0; // 100%

/// Minimum reputation score for masternodes to participate in FerrousShield mixing
/// Spec: [06_masternode_protocol_spec.md §6.5.2](https://github.com/rusty-coin/specs/blob/main/docs/specs/06_masternode_protocol_spec.md#652-ferrousshield-trust-minimized-privacy)
pub const MIN_MN_REPUTATION: u32 = 50; 