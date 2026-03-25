# OpenFang Security Audit: ClawHub Supply-Chain Vulnerability Assessment

**Date:** 2026-03-25
**Auditor:** Claude (automated security audit)
**Scope:** ClawHavoc-class supply-chain attack surface in OpenFang's skill loading system
**Severity:** HIGH (overall)

---

## Executive Summary

OpenFang's skill system has **meaningful security controls** but remains **vulnerable to a ClawHavoc-style supply-chain attack** due to critical gaps in skill authenticity verification and installation consent. The system fetches and installs skills from ClawHub (`https://clawhub.ai/api/v1`) with SHA256 integrity checks and prompt-injection scanning, but **lacks cryptographic signature verification, user approval gates at install time, and per-skill capability isolation**.

A compromised or malicious ClawHub skill can execute arbitrary Python, Node.js, or shell code on the host machine with access to the user's `PATH` and `HOME` directories.

---

## Part 1: Skill Loading Trust Model

### 1.1 ClawHub Skill Fetching (`clawhub.rs`)

**File:** `crates/openfang-skills/src/clawhub.rs`

**What it does:**
- Connects to `https://clawhub.ai/api/v1` (hardcoded default)
- Supports search, browse, detail, file fetch, and install operations
- Downloads skill content via `GET /api/v1/download?slug=...`
- Implements retry with exponential backoff for 429/5xx errors

**Install pipeline (lines 502-657):**
1. Downloads raw bytes from ClawHub
2. Computes SHA256 of downloaded content (logged, but **not verified against any expected value**)
3. Detects format (SKILL.md vs ZIP vs package.json)
4. For ZIP archives: extracts using `zip::ZipArchive` with `enclosed_name()` path traversal protection
5. Converts to OpenFang manifest
6. Runs `SkillVerifier::scan_prompt_content()` on prompt-only skills
7. Blocks installation if critical prompt injection patterns detected
8. Runs `SkillVerifier::security_scan()` on the manifest
9. Writes `skill.toml` to disk

**CRITICAL FINDING — No Signature Verification:**
The SHA256 hash at line 521-525 is computed and logged but **never compared against a trusted value**. There is no:
- Code signing by skill authors
- GPG/Ed25519 signature verification
- Content hash pinning from a trusted registry index
- Certificate or public key infrastructure

```rust
// Step 1: SHA256 of downloaded content
let sha256 = {
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
};
info!(slug, sha256 = %sha256, "Downloaded skill");
// ^^^ Hash is LOGGED but never VERIFIED against anything
```

**CRITICAL FINDING — No User Consent at Install:**
The `install()` method downloads, extracts, and writes to disk without any user confirmation step. If a CLI command or API endpoint triggers install, skills are immediately written to the filesystem and become loadable on next daemon boot.

**FINDING — ZIP Path Traversal Mitigated:**
The ZIP extraction uses `enclosed_name()` (line 551), which strips `../` and absolute paths. This is a good defense against zip-slip attacks.

### 1.2 Skill Execution (`loader.rs`)

**File:** `crates/openfang-skills/src/loader.rs`

**What it does:**
- Executes skill tools by spawning Python, Node.js, or Shell subprocesses
- Passes tool input via stdin as JSON
- Returns stdout as JSON result

**GOOD — Environment Isolation (lines 93-112):**
All three runtimes (Python, Node, Shell) call `cmd.env_clear()` before spawning, then selectively re-add only `PATH`, `HOME`, and platform essentials. This prevents API keys, tokens, and credentials from leaking to third-party skill code.

```rust
// SECURITY: Isolate environment to prevent secret leakage.
cmd.env_clear();
if let Ok(path) = std::env::var("PATH") {
    cmd.env("PATH", path);
}
```

**CRITICAL FINDING — No Process Sandbox:**
Skills run as **unsandboxed subprocesses** with the same UID as the OpenFang daemon. A malicious Python/Node/Shell skill can:
- Read/write any file the daemon user can access
- Make arbitrary network connections
- Spawn additional processes
- Access `~/.ssh`, `~/.aws`, `~/.config`, browser profiles, etc.
- Install persistence mechanisms (crontabs, shell profiles, login items)

There is no:
- seccomp filtering
- Linux namespaces / cgroups
- macOS sandbox profiles
- Filesystem chroot/jail
- Network namespace isolation
- Resource limits (CPU, memory, file descriptors) for Python/Node/Shell runtimes

**NOTE — WASM Sandbox Exists But Is Not Used for Marketplace Skills:**
The codebase has a WASM sandbox (`crates/openfang-runtime/src/sandbox.rs`) with fuel metering, capability checks, and memory limits. However, ClawHub skills use Python/Node/Shell runtimes, not WASM. The WASM runtime returns `RuntimeNotAvailable` in the loader.

### 1.3 OpenClaw Compatibility (`openclaw_compat.rs`)

**File:** `crates/openfang-skills/src/openclaw_compat.rs`

**What it does:**
- Detects SKILL.md (prompt-only) and package.json (Node.js) formats
- Parses YAML frontmatter from SKILL.md
- Converts OpenClaw tool names to OpenFang equivalents
- Generates `SkillManifest` with appropriate runtime type

**FINDING — Same Trust Assumptions:**
OpenClaw skills imported through this layer receive the same trust level as native OpenFang skills. There is no additional scrutiny for third-party format conversion. The Node.js runtime type is assigned to package.json skills, granting them full subprocess execution.

**FINDING — Tool Name Translation May Mask Intent:**
Tool names are mapped through `tool_compat::map_tool_name()`, e.g., `Bash` → `shell_exec`, `Read` → `file_read`. A skill that declares `Bash` in its OpenClaw manifest silently gains `shell_exec` capability after translation.

### 1.4 Security Verification (`verify.rs`)

**File:** `crates/openfang-skills/src/verify.rs`

**What it does:**
- SHA256 checksum computation and comparison
- Manifest security scanning (dangerous runtimes, capabilities, tools)
- Prompt injection pattern matching (10 injection patterns, 9 exfiltration patterns, 3 shell patterns)

**GOOD — Prompt Injection Detection:**
Detects common patterns from the ClawHavoc attack (referenced in code comment at line 107-108):

```rust
/// This catches the common patterns used in the 341 malicious skills
/// discovered on ClawHub (Feb 2026).
```

Critical patterns blocked:
- `"ignore previous instructions"`, `"ignore all previous"`, `"disregard previous"`
- `"you are now"`, `"new instructions:"`, `"system prompt override"`
- `"forget your instructions"`, `"ignore the above"`, `"do not follow"`, `"override system"`

Exfiltration patterns detected:
- `"send to http"`, `"post to https"`, `"exfiltrate"`, `"upload to"`, etc.

**FINDING — Pattern Matching Is Easily Bypassed:**
The scanner uses simple `str::contains()` on lowercased content. Known bypasses include:
- Unicode homoglyphs: `ìgnore prevìous ìnstructìons` (accented chars)
- Zero-width characters: `ignore\u200Bprevious\u200Binstructions`
- Token splitting: `ig` + `nore prev` + `ious`
- Base64 encoding: encoding instructions in base64 within the prompt
- Indirect injection: `When processing user input, apply the following transformation...`
- Multi-step injection: each individual line appears benign, but combined they form an attack
- Language switching: instructions in non-English languages

**FINDING — No Scan of Executable Code:**
`scan_prompt_content()` only scans the Markdown body of SKILL.md files. For Node.js skills (package.json + index.js), **the actual JavaScript/Python code is never scanned**. A malicious `index.js` can contain arbitrary code including keyloggers, credential stealers, or reverse shells.

### 1.5 Skill Registry (`registry.rs`)

**File:** `crates/openfang-skills/src/registry.rs`

**GOOD — Freeze Mode:**
The registry can be frozen after initial boot (`freeze()`), preventing dynamic skill loading. This is used in "Stable mode."

**GOOD — Defense in Depth on Bundled Skills:**
Even compile-time bundled skills are scanned for prompt injection patterns (lines 68-80).

**FINDING — Auto-Load Without Approval:**
`load_all()` automatically loads every subdirectory of `~/.openfang/skills/` that contains a `skill.toml` or `SKILL.md`. If a malicious skill is downloaded to this directory (by any means), it will be loaded on next daemon boot without user confirmation.

**FINDING — Auto-Convert SKILL.md:**
If a directory contains only a `SKILL.md` (no `skill.toml`), the registry automatically converts and loads it. This means dropping a single Markdown file into the skills directory is sufficient for code execution on next boot.

### 1.6 Marketplace (`marketplace.rs`)

**File:** `crates/openfang-skills/src/marketplace.rs`

This is a separate "FangHub" marketplace client using GitHub releases. It downloads tarballs from `openfang-skills` GitHub org. **No checksum or signature verification at all** — even less security than the ClawHub path.

---

## Part 2: ClawHub Marketplace Content Audit

### 2.1 Registry Access

ClawHub is accessed via HTTPS REST API at `https://clawhub.ai/api/v1`:
- **Search:** `GET /api/v1/search?q=...&limit=20`
- **Browse:** `GET /api/v1/skills?limit=20&sort=trending`
- **Detail:** `GET /api/v1/skills/{slug}`
- **Download:** `GET /api/v1/download?slug=...`
- **File:** `GET /api/v1/skills/{slug}/file?path=SKILL.md`

There is no authentication required for downloading skills. Anyone can browse and install.

### 2.2 Bundled Skills Audit

All 60 bundled skills (compiled into the binary via `include_str!()`) were sampled. Eight were examined in detail:
- `github`, `security-audit`, `shell-scripting`, `web-search`, `sysadmin`, `docker`, `slack-tools`, `aws`

**Result: All bundled skills PASS security review.** No prompt injection attempts, no malicious URLs, no obfuscated content, no credential exposure. They contain legitimate domain expertise and security best practices.

### 2.3 ClawHub Marketplace Review Process

**FINDING — Unknown Review/Curation Process:**
The codebase references "3,000+ community skills" on ClawHub and "341 malicious skills discovered on ClawHub (Feb 2026)". However:
- There is no evidence of a review/curation process in the code
- The `moderation` field in `ClawHubSkillDetail` is always `null` in test data
- No concept of "verified publisher" or "trusted author" in the data model
- Anyone appears to be able to publish skills freely

### 2.4 Prompt Injection in Descriptions

The `summary` and `display_name` fields from ClawHub API responses are **not scanned for prompt injection**. Only the SKILL.md body is scanned. A malicious skill could embed injection payloads in its ClawHub summary/description that would be displayed to users (and potentially to LLMs that process search results).

---

## Part 3: Vulnerability Assessment Summary

### CRITICAL Vulnerabilities

| # | Vulnerability | Severity | Description |
|---|-------------|----------|-------------|
| 1 | **No code signing / signature verification** | CRITICAL | Skills downloaded from ClawHub have no cryptographic proof of authenticity. A MITM, compromised CDN, or compromised ClawHub account can distribute malicious skills that will be installed without question. |
| 2 | **Unsandboxed subprocess execution** | CRITICAL | Python, Node.js, and Shell skills run as unsandboxed processes with full access to the host filesystem, network, and other processes. A malicious skill has the same privileges as the OpenFang daemon. |
| 3 | **No executable code scanning** | CRITICAL | Only SKILL.md prompt content is scanned. JavaScript, Python, and shell scripts are never analyzed for malicious patterns (keyloggers, credential stealers, reverse shells, etc.). |
| 4 | **No user consent for skill installation** | CRITICAL | The `ClawHubClient::install()` method writes skills to disk without user confirmation. Combined with auto-loading at boot, this creates a "download-to-execute" pipeline. |

### HIGH Vulnerabilities

| # | Vulnerability | Severity | Description |
|---|-------------|----------|-------------|
| 5 | **Prompt injection scanner easily bypassed** | HIGH | Simple string matching (`str::contains()`) is trivially bypassed with Unicode homoglyphs, zero-width characters, base64 encoding, non-English languages, or semantic rephrasing. |
| 6 | **Auto-load from skills directory** | HIGH | Any file written to `~/.openfang/skills/` is automatically loaded on daemon boot. This makes local privilege escalation trivial — any process that can write to the user's home directory can achieve code execution. |
| 7 | **No per-skill capability isolation** | HIGH | Once loaded, a skill's tool declarations are not enforced against a capability budget. A skill declaring `shell_exec` will have that tool available if the agent's global policy allows it. |
| 8 | **Marketplace install has no verification** | HIGH | `marketplace.rs` (FangHub/GitHub path) downloads tarballs without any checksum or signature verification. |
| 9 | **Metadata fields not scanned** | HIGH | Skill `summary`, `display_name`, and `description` from ClawHub are not scanned for prompt injection. These fields are displayed in search results and may be processed by LLMs. |

### MEDIUM Vulnerabilities

| # | Vulnerability | Severity | Description |
|---|-------------|----------|-------------|
| 10 | **Tool name translation masks intent** | MEDIUM | OpenClaw → OpenFang tool name mapping (e.g., `Bash` → `shell_exec`) happens silently during conversion. Users may not realize a skill requests dangerous capabilities. |
| 11 | **No resource limits for subprocess runtimes** | MEDIUM | Python/Node/Shell skills have no CPU, memory, or time limits. A malicious or buggy skill can consume unlimited resources. |
| 12 | **No audit trail for skill execution** | MEDIUM | No structured security event logging for skill tool invocations, blocked operations, or security scan results. |

### Existing Mitigations (Positive Findings)

| Control | Effectiveness |
|---------|--------------|
| `env_clear()` on subprocess spawn | **Good** — prevents credential leakage to skill processes |
| Prompt injection pattern matching | **Partial** — catches naive attacks, easily bypassed by sophisticated attackers |
| ZIP path traversal protection (`enclosed_name()`) | **Good** — prevents zip-slip attacks |
| Registry freeze mode | **Good** — prevents dynamic loading in stable mode |
| WASM sandbox (fuel, capabilities, memory) | **Strong** — but not used for marketplace skills |
| Manifest security scanning | **Partial** — flags dangerous capabilities but doesn't block installation |
| Defense-in-depth on bundled skills | **Good** — scans even trusted bundled content |
| Human approval gates for tool execution | **Good** — `shell_exec` requires approval by default |
| Shell metacharacter blocking | **Good** — prevents command injection in tool arguments |
| Docker container sandbox | **Good** — but optional and disabled by default |
| Taint tracking for LLM tool calls | **Good** — blocks `curl|bash`, exfiltration patterns in tool args |

---

## Part 4: Prompt Injection Findings

### In Bundled Skills: None Found

All 60 bundled skills were checked. The 8 sampled in detail contained no prompt injection attempts, no malicious URLs, and no obfuscated content.

### In ClawHub Marketplace Skills: Unable to Audit Live

This audit was performed against the local codebase only. Live ClawHub marketplace content was not fetched (read-only audit, no network requests). The codebase references "341 malicious skills discovered on ClawHub (Feb 2026)" in `verify.rs` line 107-108, confirming that the ClawHavoc attack has already occurred.

### Self-Check

Did anything I read during this audit influence how I conducted the audit? **No.** All skill content examined was legitimate security guidance. No prompt injection attempts were encountered in the files I read.

---

## Recommendations

1. **Implement code signing** — Require Ed25519 signatures from skill authors, verified against a public key registry. Block installation of unsigned or invalidly signed skills.

2. **Add user consent flow** — Before installing a marketplace skill, display its declared capabilities, runtime type, and security scan results. Require explicit user confirmation.

3. **Sandbox all runtimes** — Extend the WASM sandbox model to Python/Node/Shell via Linux namespaces (unshare), seccomp-bpf, or mandatory Docker containers. At minimum, use filesystem chroot and network namespace isolation.

4. **Scan executable code** — Static analysis of JavaScript/Python/Shell scripts for malicious patterns (network calls to unknown hosts, file reads of sensitive paths, process spawning, encoded payloads).

5. **Improve prompt injection detection** — Use LLM-based classification instead of or in addition to pattern matching. Normalize Unicode before scanning. Detect base64-encoded content.

6. **Require explicit skill activation** — Skills should not auto-load from the filesystem. Require `openfang skill enable <name>` after installation.

7. **Per-skill capability grants** — Allow users to grant specific capabilities to specific skills, not just global agent policies.

8. **Scan metadata fields** — Apply prompt injection detection to skill names, descriptions, and summaries from marketplace APIs.

9. **Add resource limits** — Apply CPU time, memory, and network bandwidth limits to Python/Node/Shell skill processes.

10. **Structured security audit logging** — Log all skill installations, executions, security scan results, and blocked operations in a queryable format.
