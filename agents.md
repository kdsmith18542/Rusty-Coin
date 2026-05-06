# AI Agent Guidelines for Rusty-Coin

This document provides instructions and context for AI agents working on the Rusty-Coin repository. Following these guidelines ensures consistency, maintainability, and a clean workspace.

## Core Principles

1. **Keep it Clean**: Do not leave behind session artifacts, temporary reports, or progress logs in the repository.
2. **Follow .gitignore**: Always respect the `.gitignore` rules. If you create new types of temporary files, update `.gitignore` accordingly.
3. **Modular First**: Rusty-Coin is a modular workspace. When adding features, place them in the appropriate crate or create a new crate if necessary.
4. **Track the Lockfile**: Since this is a binary-focused project, always ensure `Cargo.lock` is updated and committed alongside `Cargo.toml` changes.

## Development Workflow

- **Testing**: Run `cargo test` and the relevant integration scripts in `scripts/` before committing.
- **Formatting**: Use `cargo fmt` to maintain consistent code style.
- **Documentation**: Update root and component-level READMEs when adding significant features.

## Anti-Patterns to Avoid

- **Root Clutter**: Do not add `.md` or `.txt` files to the root unless they are standard repository documentation (LICENSE, README, etc.).
- **Backup Files**: Do not commit `*.backup` or `*.rs.bk` files.
- **Large Metadata**: Avoid committing large generated JSON files like `cargo_metadata.json`.

## Communication

When summarizing work for the user, focus on high-level changes and impact rather than listing every file changed, unless specifically asked.

---
*This file is intended for use by AI agents like Antigravity, Claude, and others helping to build Rusty-Coin.*
