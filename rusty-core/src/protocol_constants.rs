// Protocol constants for Rusty Coin, as per protocol specifications

/// Masternode Protocol Constants
pub const MASTERNODE_COLLATERAL_AMOUNT: u64 = 26000_00000000; // 26,000 RUST in satoshis

/// PoSe (Proof of Service) Constants
pub const POSE_CHALLENGE_PERIOD_BLOCKS: u32 = 60; // ~2.5 hours
pub const POSE_RESPONSE_TIMEOUT_SECONDS: u32 = 60;
pub const MAX_POSE_FAILURES: u32 = 3;
pub const NON_PARTICIPATION_SLASH_PERCENTAGE: f64 = 0.05; // 5%
pub const MALICIOUS_BEHAVIOR_SLASH_PERCENTAGE: f64 = 1.0; // 100%
pub const SUSPENSION_PERIOD_BLOCKS: u32 = 100;
pub const RESET_FAILURES_PERIOD: u32 = 100;

/// OxideSend Constants
pub const OXIDESEND_QUORUM_SIZE: u32 = 12; // 10-15 range
pub const OXIDESEND_MIN_QUORUM_SIGS_REQUIRED: u32 = 10; // 80% of quorum
pub const OXIDESEND_LOCK_DURATION_BLOCKS: u32 = 5;

/// FerrousShield Constants
pub const FERROUSSHIELD_QUORUM_SIZE: u32 = 6; // 5-7 range

/// PoS Ticket Constants
pub const TARGET_LIVE_TICKETS: u32 = 20000;
pub const TICKET_PRICE_ADJUSTMENT_PERIOD: u32 = 2016; // ~3.5 days
pub const TICKET_EXPIRATION_PERIOD_BLOCKS: u32 = 4096; // ~7 days
pub const VOTERS_PER_BLOCK: u32 = 5;
pub const POS_FINALITY_DEPTH: u32 = 1;
pub const MIN_VALID_VOTES_REQUIRED: u32 = 3; // 60% of VOTERS_PER_BLOCK
pub const INITIAL_TICKET_PRICE: u64 = 100_00000000; // 100 RUST initial price
pub const MAX_TICKET_PRICE: u64 = 10000_00000000; // 10,000 RUST max
pub const MIN_TICKET_PRICE: u64 = 1_00000000; // 1 RUST min
pub const TICKET_PRICE_ADJUSTMENT_K_P: f64 = 0.05; // Proportionality constant

/// PoS Slashing Constants
pub const GRACE_PERIOD_BLOCKS: u32 = 10;
pub const NON_PARTICIPATION_TICKET_SLASH_PERCENTAGE: f64 = 0.01; // 1%
pub const MALICIOUS_TICKET_SLASH_PERCENTAGE: f64 = 1.0; // 100%
pub const SLASH_FORGIVENESS_PERIOD: u32 = 100;

/// Governance Constants
pub const PROPOSAL_STAKE_AMOUNT: u64 = 1000_00000000; // 1000 RUST
pub const POS_VOTING_QUORUM_PERCENTAGE: f64 = 0.20; // 20%
pub const MN_VOTING_QUORUM_PERCENTAGE: f64 = 0.50; // 50%
pub const POS_APPROVAL_PERCENTAGE: f64 = 0.75; // 75%
pub const MN_APPROVAL_PERCENTAGE: f64 = 0.66; // 66%
pub const ACTIVATION_DELAY_BLOCKS: u32 = 100;

/// General Network Constants
pub const SATOSHIS_PER_RUST: u64 = 100000000; // 1 RUST = 100M satoshis
pub const BLOCKS_PER_DAY: u32 = 576; // Assuming 2.5 min blocks
