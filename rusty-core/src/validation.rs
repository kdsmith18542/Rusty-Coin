// Protocol compliance validation helpers
use crate::protocol_constants::*;

pub fn validate_masternode_collateral(amount: u64) -> bool {
    amount >= MASTERNODE_COLLATERAL_AMOUNT
}

pub fn calculate_ticket_price(current_live_tickets: u32, last_adjustment_price: u64) -> u64 {
    let target = TARGET_LIVE_TICKETS as f64;
    let current = current_live_tickets as f64;
    let adjustment_factor = 1.0 + TICKET_PRICE_ADJUSTMENT_K_P * ((current - target) / target);
    let new_price = (last_adjustment_price as f64) * adjustment_factor;
    (new_price as u64).clamp(MIN_TICKET_PRICE, MAX_TICKET_PRICE)
}

pub fn check_governance_quorum(
    pos_votes: u32,
    mn_votes: u32,
    total_tickets: u32,
    total_masternodes: u32,
) -> (bool, bool) {
    let pos_quorum = (pos_votes as f64) >= (total_tickets as f64) * POS_VOTING_QUORUM_PERCENTAGE;
    let mn_quorum = (mn_votes as f64) >= (total_masternodes as f64) * MN_VOTING_QUORUM_PERCENTAGE;
    (pos_quorum, mn_quorum)
}

pub fn check_governance_approval(
    pos_yes: u32,
    pos_total: u32,
    mn_yes: u32,
    mn_total: u32,
) -> (bool, bool) {
    let pos_approval = (pos_yes as f64) >= (pos_total as f64) * POS_APPROVAL_PERCENTAGE;
    let mn_approval = (mn_yes as f64) >= (mn_total as f64) * MN_APPROVAL_PERCENTAGE;
    (pos_approval, mn_approval)
}
