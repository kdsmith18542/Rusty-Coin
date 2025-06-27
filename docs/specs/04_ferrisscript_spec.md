Rusty Coin Formal Protocol Specifications: 04 - Transaction Model & FerrisScript
Spec Version: 1.0.0
Status: Draft
Last Updated: June 18, 2025
Author(s): Rusty Coin Core Team

Dependencies: 00_overview.md, 01_block_structure.md, rusty_crypto_spec.md (for cryptographic primitives like Ed25519, BLAKE3).

4.1 Overview
This document formally defines Rusty Coin's transaction model, which is based on the Unspent Transaction Output (UTXO) paradigm. It also provides a comprehensive specification of FerrisScript, the simple, non-Turing complete, stack-based scripting language used to lock and unlock these UTXOs. The design prioritizes security, predictability, and efficiency in transaction validation.

4.2 Unspent Transaction Output (UTXO) Model
Rusty Coin utilizes the UTXO model, a fundamental design choice providing robust security, scalability, and enhanced privacy characteristics compared to account-based models.

4.2.1 Core Concepts

UTXO: An Unspent Transaction Output is a discrete unit of $RUST, representing an output from a previous transaction that has not yet been spent. Each UTXO is uniquely identified by its (TxID, VOutIndex) pair (Transaction ID and its zero-based output index within that transaction).

Transaction Inputs: Each TxInput in a transaction explicitly references a specific UTXO from a previous transaction. The script_sig within the TxInput provides the data and instructions necessary to satisfy the script_pubkey of the referenced UTXO.

Transaction Outputs: Each TxOutput in a transaction creates a new UTXO. It specifies a value (amount of RUST) and a script_pubkey (locking script) that defines the conditions under which this new UTXO can be spent in the future.

4.2.2 Transaction Validation (UTXO-Specific)

For a transaction to be considered valid and included in a block, the following UTXO-related rules MUST be enforced by the rusty-consensus module:

Valid Inputs: Each TxInput MUST reference a UTXO that currently exists in the network's UTXO_SET (the set of all unspent outputs) and has not been previously spent.

Double-Spend Prevention: No TxInput within the same transaction or within the same block (for transactions in the mempool) may reference the same UTXO more than once.

Value Conservation: The sum of values of all TxInputs (the referenced UTXOs) MUST be greater than or equal to the sum of values of all TxOutputs in the transaction.

Transaction Fees: The difference between the total input value and total output value is considered the transaction fee. This fee is implicitly claimed by the miner of the block that includes the transaction.

Fee = (Sum of Input Values) - (Sum of Output Values)

Fee MUST be greater than or equal to MIN_RELAY_FEE_PER_BYTE * TransactionSizeInBytes.

Dust Limit: Each TxOutput.value MUST be greater than or equal to DUST_LIMIT (a minimum value to prevent UTXO bloat and tiny, unspendable outputs).

Script Validation: The script_sig of each TxInput, when executed in conjunction with the script_pubkey of the referenced UTXO, MUST successfully evaluate to TRUE. (Detailed in Section 4.3).

4.3 FerrisScript Specification
FerrisScript is a non-Turing complete, stack-based scripting language designed specifically for Rusty Coin's UTXO locking and unlocking conditions. Its simplicity enhances security and predictability.

4.3.1 Execution Model

Virtual Machine (VM): FerrisScript is executed on a simple, stack-based virtual machine.

Data Stack: The VM operates using a single data stack. All instructions (opcodes) manipulate byte arrays (elements) on this stack.

Script Evaluation: To validate a TxInput (i.e., to prove the right to spend a UTXO):

The script_sig from the TxInput is executed. Any data pushes by script_sig are placed onto the data stack.

The script_pubkey from the referenced TxOutput (UTXO being spent) is then executed. Its operations utilize the existing data on the stack (from script_sig) and may push/pop further elements.

Validation Rule: For the TxInput to be valid, the combined execution of script_sig and script_pubkey MUST result in exactly one non-empty (i.e., TRUE) element remaining on the top of the data stack. All other elements on the stack below this final TRUE element are ignored for validation.

Script Failure: If any opcode encounters an invalid state (e.g., stack underflow, invalid opcode, cryptographic verification failure) or if the final stack state is not TRUE (or is empty), the script immediately fails, rendering the entire transaction invalid.

4.3.2 Data Types

All elements manipulated on the FerrisScript stack are byte arrays (Vec<u8>).

Boolean Representation:

TRUE: Any non-empty byte array that does not contain only zero bytes.

FALSE: An empty byte array ([]) or a byte array consisting entirely of zero bytes (e.g., [0x00], [0x00, 0x00]).

4.3.3 Script Limits (MUST be enforced by rusty-consensus)

To prevent denial-of-service attacks and ensure predictable validation times:

MAX_SCRIPT_BYTES: Maximum byte size for any script_sig or script_pubkey. (e.g., 10,000 bytes).

MAX_OPCODE_COUNT: Maximum number of opcodes allowed per script. (e.g., 200 opcodes).

MAX_STACK_DEPTH: Maximum number of elements allowed on the data stack at any point during execution. (e.g., 100 elements).

MAX_SIG_OPS: Maximum number of signature verification operations (OP_CHECKSIG, OP_CHECKMULTISIG) allowed within a single transaction. (e.g., 20 sig ops). This limit helps control cryptographic processing load per transaction.

4.3.4 Opcodes Specification

Each opcode is represented by a single byte.

Opcode Name

Hex Value

Description

Stack Effect (Before -> After)

OP_0

0x00

Pushes an empty byte array (FALSE) onto the stack.

... -> ..., []

OP_PUSHDATA1

0x4C

The next byte contains the number of bytes to be pushed from the following data.

... -> ..., data

OP_PUSHDATA2

0x4D

The next two bytes (little-endian) contain the number of bytes to be pushed from the following data.

... -> ..., data

OP_PUSHDATA4

0x4E

The next four bytes (little-endian) contain the number of bytes to be pushed from the following data.

... -> ..., data

OP_1 to OP_16

0x51-0x60

Pushes the number 1 to 16 as a single byte [0x01] to [0x10] respectively.

... -> ..., [N]

OP_DUP

0x76

Duplicates the top stack item. Requires at least one item on stack.

... A -> ..., A, A

OP_HASH160

0xA9

Pops A. Pushes RIPEMD160(SHA256(A)). Requires one item on stack.

... A -> ..., Hash160(A)

OP_EQUAL

0x87

Pops A, Pops B. Pushes TRUE if A == B (byte-for-byte comparison), else FALSE. Requires two items on stack.

... A B -> ..., (A==B)

OP_EQUALVERIFY

0x88

Pops A, Pops B. Fails script if A != B. Equivalent to OP_EQUAL OP_VERIFY. Requires two items on stack.

... A B -> ...

OP_CHECKSIG

0xAC

Pops PublicKey, Pops Signature. Verifies Signature is valid for PublicKey against the transaction hash (hash of the transaction with all script_sigs removed and prev_out_script_pubkeys substituted). Pushes TRUE/FALSE. Requires two items.

... Signature PublicKey -> ..., (Bool)

OP_CHECKMULTISIG

0xAE

Pops N (number of public keys), then N PublicKeys (from P_N to P_1). Pops M (number of signatures), then M Signatures (from S_M to S_1). Pops a dummy element (historical bug, ignored). Verifies that M signatures match M of N public keys. Pushes TRUE/FALSE. Requires 2+M+N items.

... [dummy] Sigs PublicKeys -> ..., (Bool)

OP_CHECKLOCKTIMEVERIFY

0xB1

Pops LockTime. Fails script if the transaction's lock_time (from Transaction header) is not met (i.e., current block height or timestamp is less than LockTime). Requires one item.

... LockTime -> ...

OP_CHECKSEQUENCEVERIFY

0xB2

Pops Sequence. Fails script if the transaction input's sequence (from TxInput) does not meet Sequence (relative lock time) or if LockTime bit is set. Requires one item.

... Sequence -> ...

OP_VERIFY

0x69

Pops A. Fails script if A is FALSE. Equivalent to OP_IF ... OP_ENDIF without an OP_ELSE branch. Requires one item.

... A -> ...

OP_RETURN

0x6A

Pops A. Marks the transaction output as unspendable and allows for inclusion of arbitrary data. Typically used for small amounts of data that don't represent value transfer.

... A -> ...

OP_NOP

0x61

Does nothing. No effect on the stack.

... -> ...

4.6 Standard Transaction Script Examples
4.6.1 Pay-to-Public-Key-Hash (P2PKH)

Purpose: The most common transaction type, spending to a hash of a public key. This is the standard form for Rusty Coin addresses.

TxOutput.script_pubkey (Locking Script):

OP_DUP                   // Duplicate the public key
OP_HASH160               // Hash the duplicated public key
[20-byte-pubkey-hash]    // Push the expected public key hash
OP_EQUALVERIFY           // Check if hashes match; fail if not
OP_CHECKSIG              // Verify the signature with the public key

TxInput.script_sig (Unlocking Script):

[Signature]              // Push the signature of the transaction
[PublicKey]              // Push the full public key

Execution Flow (P2PKH):

[Signature] is pushed onto stack. Stack: [Sig]

[PublicKey] is pushed onto stack. Stack: [Sig], [PubKey]

OP_DUP duplicates [PubKey]. Stack: [Sig], [PubKey], [PubKey]

OP_HASH160 hashes the top [PubKey]. Stack: [Sig], [PubKey], [PubKeyHash_calculated]

[20-byte-pubkey-hash] (from the UTXO's script_pubkey) is pushed. Stack: [Sig], [PubKey], [PubKeyHash_calculated], [PubKeyHash_expected]

OP_EQUALVERIFY compares PubKeyHash_calculated and PubKeyHash_expected. If they don't match, script fails. If they match, these two items are popped. Stack: [Sig], [PubKey]

OP_CHECKSIG pops Sig and PubKey. It verifies Sig is a valid signature for the transaction (excluding script_sig and substituting script_pubkey) using PubKey. Pushes TRUE or FALSE. Stack: [TRUE/FALSE]

Final result on stack: TRUE for a valid spend.