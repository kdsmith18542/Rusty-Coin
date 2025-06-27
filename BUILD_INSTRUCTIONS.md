# Rusty Coin Build Instructions

## Building rusty-p2p with full libp2p features

The `rusty-p2p` crate defines a `full` feature that enables all necessary libp2p features including mDNS, Kademlia, Noise, Yamux, and more.

To build the project with the full libp2p features enabled, use the following command:

```bash
cargo build -p rusty-p2p --features full
```

Or to build the entire workspace with the full feature enabled for rusty-p2p:

```bash
cargo build --features rusty-p2p/full
```

## Notes

- Ensure that when running or testing the project, the `full` feature is enabled for `rusty-p2p` to avoid missing libp2p functionality.
- If using IDEs or other build tools, configure them to pass the `--features rusty-p2p/full` flag accordingly.
- This enables support for TCP, mDNS, Kademlia DHT, Noise protocol, Yamux multiplexing, and other libp2p features required by Rusty Coin.

## Troubleshooting

If you encounter issues related to missing libp2p features, verify that the `full` feature is enabled during build.

For more information, see the `rusty-p2p/Cargo.toml` file.

---

This document is intended to help developers build the Rusty Coin project correctly with all necessary networking features.
