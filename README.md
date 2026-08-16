# Ferrous Sandbox

A **capability-secured WASI runtime** for safely running untrusted guest code
inside an AI-driven IDE. Ferrous Sandbox is the execution core of
[Ferrous](https://github.com/Ferrousagent/ferrous) — an AI IDE where an agent
and a human collaborate on one machine.

The security core is open source so it can be audited. Everything the sandbox
grants — filesystem roots, environment variables, loopback ports, resource
budgets — is explicit, deny-by-default, and tested.

## What it provides

- **Embedded Wasmtime, not a subprocess** — WASI components run in-process
  under a JIT with no shell fallback, ever. Native process execution is a
  separate, explicitly-granted path.
- **Capability grants** — filesystem access is rooted in a sandboxed directory
  (cap-std; symlink and `..` escapes are structurally impossible), environment
  variables are allowlisted before they are even read from the host, and
  network access is a per-port allowlist over loopback only.
- **Resource limits** — memory, output budget, wall-clock timeout, and
  instruction fuel bound every guest.
- **Cancellation** — a running guest can be interrupted mid-flight via the
  Wasmtime epoch mechanism; queued sessions can be cancelled before they start.
- **Streaming** — live `SessionEvent` output (started / output chunks /
  exited / cancelled) delivered while the guest still runs.
- **Human-in-the-loop approval** — risky actions (filesystem writes, network,
  environment reads, native execution) park for a human decision before they
  run, and every decision lands in an auditable trail.
- **`unsafe_code = "forbid"`** — the crate contains zero `unsafe`.

## Usage

```rust
use wasi_runtime::{ActionBroker, CommandRequest, ExecutionMode};

let broker = ActionBroker::new()?;
let component = broker.compile_component(&wat_bytes)?;
let receiver = broker.submit_streaming(component, CommandRequest {
    id: 1,
    program: "hello".into(),
    mode: ExecutionMode::Wasi,
    grant: /* CapabilityGrant::workspace(...) */,
    // ...
})?;

for event in receiver { /* Started, Output(bytes), Exited { code } */ }
```

Read the [crate docs](https://docs.rs/wasi-runtime) for the full contract:
`CommandRequest` / `SessionState` / `BrokerOutcome` are the UI-agnostic
boundary the rest of Ferrous hangs off.

## Development

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Requires Rust 1.97.1 (pinned in `rust-toolchain.toml`). CI runs the full
matrix — fmt, clippy (warnings denied), tests, docs (broken links are errors),
bench compilation, license/advisory checks — on Linux, macOS, and Windows.

## Security model

Deny-by-default, three layers:

1. **The component boundary** — only validated WASI components are admitted;
   no AOT artifacts or serialized modules.
2. **The capability boundary** — filesystem, environment, and network are
   granted explicitly and enforced by the host (cap-std directories, env
   allowlists, per-port socket checks). Guests get no handle outside their
   grants.
3. **The resource boundary** — memory, fuel, output, and wall-clock limits
   bound every guest, with cancellation as the escape hatch.

Red-team tests prove the boundaries: a guest with a symlinked working
directory that escapes the grant is denied before it starts, and read-only
commands run without approval while writes park for a human.

## License

MIT OR Apache-2.0 — dual licensed, at your option.
