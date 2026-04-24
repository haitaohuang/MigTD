# Custom Copilot Agents

This document describes the custom Copilot agents available for MigTD development. These agents are specialized workflows designed to accelerate common development tasks in VS Code.

## Available Agents

### cargo-deny-resolver

**Location:** `.github/agents/cargo-deny-resolver.agent.md`

**Purpose:** Resolves Cargo Deny security issues and dependency conflicts

**When to use:**
- Cargo Deny workflow failures (advisories, banned crates, unauthorized sources)
- RUSTSEC security advisories need fixing
- Dependency updates break the build
- Need to validate dependency changes against full CI test suite

**How to invoke in VS Code:**
```
@cargo-deny-resolver: The Cargo Deny check failed on advisories. Help me fix the vulnerable dependencies.
```

**What it does:**
1. Diagnoses the issue by running `cargo deny check` locally
2. Analyzes GitHub workflow logs if on a PR
3. Updates vulnerable dependencies in `Cargo.toml`
4. Verifies fixes pass all CI tests:
   - format.yml (Clippy, Rustfmt)
   - main.yml (multi-matrix builds)
   - integration-emu.yml (emulation & integration tests)
   - library.yml (library crate tests)

**Important:** The agent will **never** modify `deny.toml` to bypass security checks. It focuses on fixing actual dependency issues.

**Example scenarios:**
- "Run cargo deny check and fix any advisories"
- "Update dependencies to resolve CVE-2024-XXXXX"
- "Help me validate this dependency update against all CI tests"

## Creating New Agents

To create additional custom agents:

1. Create a new file in `.github/agents/` with extension `.agent.md`
2. Include YAML frontmatter with `name` and `description`
3. Add clear guidelines on:
   - When the agent should be used
   - What tools it prioritizes/avoids
   - Example invocation scenarios
4. Update this `AGENTS.md` file with the agent description

For detailed guidelines, see the [agent-customization skill](https://github.com/GitHub/copilot-chat/wiki/Skill-agent-customization).
