# Rusty Coin Protocol Flows

This document details the key protocol flows and interactions within the Rusty Coin system.

## Block Production and Validation Flow

```mermaid
sequenceDiagram
    participant Miner
    participant Mempool
    participant Consensus
    participant P2P
    participant Masternode
    participant Storage
    
    Note over Miner,Storage: Block Production Phase
    Miner->>Mempool: Request Block Template
    Mempool->>Consensus: Validate Transactions
    Consensus->>Storage: Check UTXO Set
    Storage-->>Consensus: UTXO Status
    Consensus-->>Mempool: Validation Results
    Mempool-->>Miner: Block Template
    
    Note over Miner,Storage: Mining Phase
    Miner->>Miner: Solve Proof of Work
    Miner->>P2P: Broadcast Block
    
    Note over Miner,Storage: Validation Phase
    P2P->>Consensus: Receive Block
    Consensus->>Consensus: Validate Block Header
    Consensus->>Consensus: Validate Transactions
    Consensus->>Storage: Update UTXO Set
    Consensus->>Storage: Store Block
    
    Note over Miner,Storage: Propagation Phase
    Consensus->>P2P: Accept Block
    P2P->>Masternode: Propagate to Masternodes
    Masternode->>Masternode: Validate and Store
    P2P->>P2P: Propagate to Peers
```

## Masternode Quorum Formation Flow

```mermaid
sequenceDiagram
    participant Network
    participant MN1 as Masternode 1
    participant MN2 as Masternode 2
    participant MN3 as Masternode 3
    participant DKG as DKG Protocol
    participant Quorum
    
    Note over Network,Quorum: Quorum Selection Phase
    Network->>MN1: Quorum Selection Event
    Network->>MN2: Quorum Selection Event
    Network->>MN3: Quorum Selection Event
    
    Note over Network,Quorum: DKG Phase
    MN1->>DKG: Initialize DKG Session
    MN2->>DKG: Join DKG Session
    MN3->>DKG: Join DKG Session
    
    DKG->>MN1: Generate Key Share
    DKG->>MN2: Generate Key Share
    DKG->>MN3: Generate Key Share
    
    MN1->>DKG: Broadcast Commitment
    MN2->>DKG: Broadcast Commitment
    MN3->>DKG: Broadcast Commitment
    
    DKG->>DKG: Verify Commitments
    DKG->>MN1: Key Share Verification
    DKG->>MN2: Key Share Verification
    DKG->>MN3: Key Share Verification
    
    Note over Network,Quorum: Quorum Formation
    MN1->>Quorum: Register with Threshold Key
    MN2->>Quorum: Register with Threshold Key
    MN3->>Quorum: Register with Threshold Key
    
    Quorum->>Network: Quorum Active
```

## Governance Proposal Flow

```mermaid
sequenceDiagram
    participant Proposer
    participant Governance
    participant Masternode
    participant Network
    participant Consensus
    
    Note over Proposer,Consensus: Proposal Submission
    Proposer->>Governance: Submit Proposal
    Governance->>Governance: Validate Proposal
    Governance->>Governance: Lock Collateral
    Governance->>Network: Broadcast Proposal
    
    Note over Proposer,Consensus: Voting Phase
    Network->>Masternode: Proposal Notification
    Masternode->>Governance: Cast Vote
    Governance->>Governance: Record Vote
    Governance->>Governance: Update Tally
    
    Note over Proposer,Consensus: Execution Phase
    Governance->>Governance: Check Voting Deadline
    Governance->>Governance: Validate Approval
    Governance->>Consensus: Execute Parameter Change
    Consensus->>Consensus: Apply Changes
    Governance->>Proposer: Return/Slash Collateral
    
    Note over Proposer,Consensus: Finalization
    Governance->>Network: Broadcast Execution
    Network->>Network: Update Parameters
```

## Sidechain Two-Way Peg Flow

```mermaid
sequenceDiagram
    participant User
    participant Mainchain
    participant Federation
    participant Sidechain
    participant Validator
    
    Note over User,Validator: Peg-In Process
    User->>Mainchain: Lock Assets
    Mainchain->>Federation: Peg-In Request
    Federation->>Federation: Validate Lock Transaction
    Federation->>Federation: Generate Threshold Signature
    Federation->>Sidechain: Mint Assets
    Sidechain->>User: Assets Available
    
    Note over User,Validator: Sidechain Operations
    User->>Sidechain: Transfer Assets
    Sidechain->>Sidechain: Process Transactions
    Sidechain->>Validator: Validate State
    
    Note over User,Validator: Peg-Out Process
    User->>Sidechain: Burn Assets
    Sidechain->>Federation: Peg-Out Request
    Federation->>Federation: Validate Burn Transaction
    Federation->>Federation: Generate Threshold Signature
    Federation->>Mainchain: Unlock Assets
    Mainchain->>User: Assets Available
```

## Cross-Chain Transaction Flow

```mermaid
sequenceDiagram
    participant UserA as User (Chain A)
    participant ChainA as Sidechain A
    participant Federation
    participant ChainB as Sidechain B
    participant UserB as User (Chain B)
    
    Note over UserA,UserB: Cross-Chain Transfer
    UserA->>ChainA: Initiate Transfer
    ChainA->>ChainA: Burn Assets
    ChainA->>Federation: Cross-Chain Request
    
    Federation->>Federation: Validate Burn Proof
    Federation->>Federation: Generate Merkle Proof
    Federation->>Federation: Create Threshold Signature
    
    Federation->>ChainB: Submit Mint Request
    ChainB->>ChainB: Validate Proof
    ChainB->>ChainB: Mint Assets
    ChainB->>UserB: Assets Available
    
    Note over UserA,UserB: Confirmation
    ChainB->>Federation: Confirm Mint
    Federation->>ChainA: Update Status
    ChainA->>UserA: Transfer Complete
```

## Fraud Proof Challenge Flow

```mermaid
sequenceDiagram
    participant Challenger
    participant FraudSystem
    participant Accused
    participant Validator
    participant Network
    
    Note over Challenger,Network: Challenge Phase
    Challenger->>FraudSystem: Submit Fraud Proof
    FraudSystem->>FraudSystem: Validate Proof Format
    FraudSystem->>FraudSystem: Lock Challenge Bond
    FraudSystem->>Network: Broadcast Challenge
    
    Note over Challenger,Network: Response Phase
    Network->>Accused: Challenge Notification
    Accused->>FraudSystem: Submit Response
    FraudSystem->>FraudSystem: Validate Response
    
    Note over Challenger,Network: Verification Phase
    FraudSystem->>Validator: Request Verification
    Validator->>Validator: Verify Evidence
    Validator->>Validator: Check Counter-Evidence
    Validator->>FraudSystem: Verification Result
    
    Note over Challenger,Network: Resolution Phase
    alt Fraud Proven
        FraudSystem->>Challenger: Award Reward
        FraudSystem->>Accused: Apply Penalty
        FraudSystem->>Network: Broadcast Fraud Confirmation
    else Fraud Disproven
        FraudSystem->>Accused: Return Bond
        FraudSystem->>Challenger: Apply Penalty
        FraudSystem->>Network: Broadcast Challenge Rejection
    end
```

## P2P Network Synchronization Flow

```mermaid
sequenceDiagram
    participant NewNode
    participant BootstrapNode
    participant Peer1
    participant Peer2
    participant Network
    
    Note over NewNode,Network: Initial Connection
    NewNode->>BootstrapNode: Connect
    BootstrapNode->>NewNode: Peer List
    NewNode->>Peer1: Connect
    NewNode->>Peer2: Connect
    
    Note over NewNode,Network: Block Synchronization
    NewNode->>Peer1: Request Block Headers
    Peer1->>NewNode: Block Headers
    NewNode->>NewNode: Validate Headers
    
    NewNode->>Peer2: Request Blocks
    Peer2->>NewNode: Block Data
    NewNode->>NewNode: Validate Blocks
    NewNode->>NewNode: Update Chain State
    
    Note over NewNode,Network: Mempool Synchronization
    NewNode->>Network: Request Mempool
    Network->>NewNode: Transaction Pool
    NewNode->>NewNode: Validate Transactions
    
    Note over NewNode,Network: Ongoing Synchronization
    Network->>NewNode: New Block Announcement
    NewNode->>Network: Request Block
    Network->>NewNode: Block Data
    NewNode->>NewNode: Validate and Apply
```

## Transaction Lifecycle Flow

```mermaid
stateDiagram-v2
    [*] --> Created: User Creates Transaction
    Created --> Validated: Validate Signature & Format
    Validated --> Mempool: Add to Memory Pool
    Mempool --> Pending: Waiting for Block Inclusion
    Pending --> Included: Miner Includes in Block
    Included --> Confirmed: Block Confirmed
    Confirmed --> Finalized: Multiple Confirmations
    
    Validated --> Rejected: Validation Failed
    Mempool --> Expired: Transaction Timeout
    Pending --> Replaced: Higher Fee Transaction
    
    Rejected --> [*]
    Expired --> [*]
    Replaced --> [*]
    Finalized --> [*]
    
    note right of Validated
        Checks:
        - Signature validity
        - Input availability
        - Fee sufficiency
        - Script validation
    end note
    
    note right of Confirmed
        Block included in
        longest chain with
        sufficient work
    end note
```

## Masternode Service Flow

```mermaid
graph TB
    subgraph "Service Request Flow"
        A[Service Request] --> B{Quorum Available?}
        B -->|Yes| C[Select Quorum]
        B -->|No| D[Form New Quorum]
        
        C --> E[Distribute Request]
        D --> F[DKG Process]
        F --> C
        
        E --> G[Process Request]
        G --> H[Generate Partial Signatures]
        H --> I[Combine Signatures]
        I --> J[Return Result]
    end
    
    subgraph "Quorum Management"
        K[Monitor Quorum Health]
        K --> L{Quorum Valid?}
        L -->|Yes| M[Continue Service]
        L -->|No| N[Rotate Quorum]
        N --> F
        M --> K
    end
    
    subgraph "Service Types"
        O[OxideSend Mixing]
        P[FerrousShield Privacy]
        Q[Cross-Chain Validation]
        R[Governance Execution]
    end
    
    J --> O
    J --> P
    J --> Q
    J --> R
```

These protocol flows provide a comprehensive view of how the various components of the Rusty Coin system interact to provide secure, scalable, and efficient blockchain operations.
