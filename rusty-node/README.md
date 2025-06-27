# Rusty Node

This is the `rusty-node` binary crate for the Rusty Coin project. It handles the core operations of a Rusty Coin node, including configuration management, logging, and graceful shutdown.

## Features Implemented

- **Configuration Parsing (RNODE_001):** Uses `confy` to load and store node configuration from TOML files, with support for default values.
- **Structured Logging (RNODE_002):** Integrates `tracing` with `tracing-subscriber` for detailed and customizable logging output.
- **Orchestration (RNODE_003):** Implements basic graceful shutdown handling using `tokio::signal::ctrl_c`.

## Getting Started

To run the `rusty-node`, navigate to the `rusty-node` directory and execute the following command:

```bash
cargo run
```

### Configuration

The node configuration is stored in a file named `node-config.toml` within your system's configuration directory (e.g., `C:\Users\<YourUsername>\AppData\Roaming\rusty-coin` on Windows). If the file does not exist, a default configuration will be used and saved.

You can modify the `NodeConfig` struct in `src/main.rs` to change default values or add new configuration parameters.

### Logging

Logging output is displayed on the console. You can configure `tracing-subscriber` for more advanced logging options (e.g., output to a file, JSON format) by modifying the `tracing_subscriber::fmt::init()` call in `src/main.rs`.

### Graceful Shutdown

The node will shut down gracefully upon receiving a `Ctrl+C` signal. This allows for proper cleanup and state saving before the application exits.