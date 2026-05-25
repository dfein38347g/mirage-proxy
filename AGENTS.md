# mirage-proxy — agent guide

Single Rust binary, reverse proxy that detects and substitutes secrets/PII before they reach LLM APIs.

## Commands

```bash
cargo build                     # debug build
cargo build --release           # release (LTO + stripped)
cargo test                      # all tests (76 unit tests, no integration tests)
cargo clippy                    # lint
cargo fmt                       # format
cargo build --target aarch64-unknown-linux-gnu  # cross-compile (needs gcc-aarch64-linux-gnu)
```

Release: push `v*` tag → CI builds 5 targets + creates GitHub release + updates Homebrew tap.

## Architecture

- `src/main.rs` — CLI with clap; service install/uninstall (launchd/systemd/Task Scheduler); wrapper script generation; daemon entrypoint
- `src/proxy.rs` — HTTP proxy core (hyper 1.x + tokio runtime): decompress → detect → substitute → forward → reverse on response; SSE streaming with cross-chunk boundary buffer (128 bytes) at SSE event boundaries (`\n\n`); `rehydrate_sse_body()` for SSE-aware rehydration with cross-chunk tool_calls joining; `smart_redact()` is the detection+substitution orchestrator for both streaming and non-streaming paths
- `src/redactor.rs` — detection engine: regex + entropy; three confidence tiers (High/Medium/Low)
- `src/patterns.rs` — 129 auto-generated secret patterns from Gitleaks + secrets-patterns-db
- `src/faker.rs` — plausible fake generation (format/length-preserving, session-consistent); `add_custom_mapping` derives regex-bounded rehydration from pattern string; `FakerMaps.custom_regexes` stores per-substitute rehydration regexes
- `src/session.rs` — per-conversation faker instances; session ID derived from `mirage_session` field, model name, or "default"
- `src/providers.rs` — 28+ provider route mappings (path prefix → upstream URL)
- `src/config.rs` — YAML config with sensitivity levels (low/medium/high/paranoid), rules, audit log config
- `src/vault.rs` — AES-256-GCM + Argon2id encrypted vault for cross-session fake↔original persistence
- `src/stats.rs` — request counter, displayed every 5s on stderr

## Repository context

- **This repo**: `dfein38347g/mirage-proxy` (fork, `main` branch)
- **Upstream**: `chandika/mirage-proxy` — original author, Homebrew tap owner
- **Goal**: Data-layer defense against secret exfiltration to LLM APIs — substitute plausible fakes (not `[REDACTED]`) so models behave normally
- **No open PRs** on this fork
- **Upstream PR #3** (`--no-stream`/`force_no_stream`) merged into this fork's `main`
- **No open issues** on upstream or fork

## Merged features (on fork `main`)

| PR | Branch | Feature |
|----|--------|---------|
| #1 | `force-no-stream` | `--no-stream` CLI flag / `force_no_stream` config — SSE buffered rehydration for split PII tokens |
| #2 | `fix/rehydration-sentence-period` | Sentence-period boundary detection for IP rehydration when followed by `. `, `."`, `.'`, `.)`, `.]`, `.}`, or `.` at EOS |
| #3 | `custom-patterns-v2` | `custom_patterns` config section — user-defined regex substitutions with session-consistent fakes |
| #4 | `custom-upstream-providers` | `custom_providers` config section — configurable OpenAI-compatible API provider routing |
| #9 | `fix/regex-bounded-rehydration-v2` | Regex-bounded rehydration for custom patterns: derives `\b`-aware rehydration regex from pattern, escapes metacharacters, sorts overlapping substitutes by length, first-write-wins for multi-origin matches |

## Key behaviors

- **Multi-provider proxy by default**: routes `/anthropic → api.anthropic.com`, `/openai → api.openai.com`, etc.
- **Shadow mode** (`--shadow` / `--dry-run`): pass-through with logging, no substitution
- **Sensitivity tiers** control what gets substituted; Low substitutes only high-confidence vendor-prefixed secrets, Medium (default) adds medium-confidence PII, High substitutes everything, Paranoid enforces regardless of rules
- **JWT / hex digest / SRI values are hard-skipped** (false-positive guard)
- **Signed thinking blocks, binary/multipart payloads are skipped**
- **Custom patterns** (`custom_patterns` in config): user-defined regex → substitute with session-consistent fakes. Rehydration uses the same `\b` boundary logic as the detection pattern (derived from the pattern string). Falls back to unconditional `.replace()` when the original doesn't appear literally in the pattern. Metacharacters in substitutes are escaped.
- **Custom providers** (`custom_providers` in config): arbitrary OpenAI-compatible API provider routing
- **SSE buffering** (`--no-stream` / `force_no_stream`): collect streaming chunks before rehydrating (prevents split-PII leakage). Without buffering, the streaming path uses SSE event boundary (`\n\n`) splits so tool_calls arguments within the same chunk are joined and rehydrated.

## Config

Zero config default. Override at `~/.config/mirage/mirage.yaml` or `--config <path>`. See `mirage.default.yaml`.

## Session consistency

Same value → same fake within a session. `mirage_session` field in request body overrides auto-detection. Vault (`MIRAGE_VAULT_KEY`) persists mappings across daemon restarts.

Fake token format: `__f_N__` where N is a sequential integer; embedded inline in place of real values. Two replacement strategies: `replace_token()` for plain substitution, `replace_token_bounded()` for word-boundary matching (used for IPs and other non-substring values). Custom patterns use regex `\b` boundaries for rehydration (derived from the pattern string), with `regex::escape()` on the substitute to prevent metacharacter injection. `mirage why <decoy>` works for both built-in and custom pattern mappings.

## Wrapper model

`--setup` creates per-tool wrapper scripts in `~/.mirage/bin/` that set `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, etc. and `exec` the real binary. Tools: claude, codex, cursor, aider, opencode. Each gets a `-direct` bypass variant.
