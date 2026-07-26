# Ghidra BizHawk MCP

A unified MCP (Model Context Protocol) server bridging Ghidra's headless static analysis with BizHawk's live emulation — switch between decompiling a ROM and running it on real hardware in the same session.

> **GBA ROMs**: If analyzing Game Boy Advance ROMs, install [pudii/gba-ghidra-loader](https://github.com/pudii/gba-ghidra-loader) in your Ghidra installation for proper ROM header parsing, mirrored memory regions, and I/O register maps. The loader repository has pre-built `.gpa` files for Ghidra 11.x.

## Prerequisites

| Dependency | Version | Required | Notes |
|---|---|---|---|
| Python | >= 3.10 | Yes | Runtime for the MCP server |
| Ghidra | 11.x or 12.x | Yes | Headless or GUI install; `GHIDRA_INSTALL_DIR` must point here |
| Java (JDK) | >= 17 | Yes | Bundled with Ghidra; needed for JVM bridge |
| pyghidra | >= 3.0 | Yes | Python-to-Ghidra bridge; installed automatically |
| BizHawk (EmuHawk) | Latest stable | No | Only needed for live emulation tools; `BIZHAWK_EXE_PATH` optional |
| Docker | Latest | No | Only needed for containerized deployment |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        MCP Client (Claude / Cursor)              │
│  sends JSON-RPC over stdin/stdout                                │
└──────────────┬──────────────────────────────────────┬───────────┘
               │                                      │
               ▼                                      ▼
┌──────────────────────────────┐    ┌──────────────────────────────┐
│     ghidra-bizhawk-mcp       │    │     BizHawk Lua Bridge       │
│  ┌─────────────────────────┐ │    │  ┌────────────────────────┐ │
│  │   MCP Server (server.py)│ │    │  │  bridge.lua            │ │
│  │   tool registry, stdio  │─┼────┼─>│  memory read/write     │ │
│  │   dispatch              │ │    │  │  joypad, savestate     │ │
│  └───────────┬─────────────┘ │    │  │  frame advance         │ │
│              │               │    │  └────────────────────────┘ │
│  ┌───────────▼─────────────┐ │    └──────────────────────────────┘
│  │   GhidraSession         │ │
│  │   pyghidra JVM bridge   │ │
│  │   decompile, search,    │ │
│  │   emulate, fingerprint  │ │
│  │   ┌───────────────────┐ │ │
│  │   │ Ghidra JVM (Java) │ │ │
│  │   │ EmulatorHelper    │ │ │
│  │   │ SLEIGH / P-code   │ │ │
│  │   └───────────────────┘ │ │
│  └─────────────────────────┘ │
└──────────────────────────────┘
```

All communication is **local stdio only** — there is no HTTP listener, no TCP socket, and no network exposure.

## Security Model

This server communicates **exclusively over standard process stdio** — there is no HTTP socket, no TCP listener, and no network interface exposed. It is inherently immune to LAN/WAN exposure, SSRF, and unauthenticated API attacks. The only way to interact with it is for an MCP client to launch it as a subprocess and communicate via stdin/stdout.

## Hardware & Retro Ecosystem Integration

`ghidra-bizhawk-mcp` includes native out-of-the-box support for retro-reversing automation pipelines via Ghidra's static analysis, plus live emulation via BizHawk's multi-system emulator. The server bundles:

- **Nintendo Entertainment System (NES)** via `GhidraNes`
- **Super Nintendo Entertainment System (SNES)** via native 65816 memory maps
- **Game Boy Advance (GBA)** via `gba-ghidra-loader`
- **Nintendo DS (NDS)** via `NTRGhidra`
- **Nintendo Switch** via `ghidra-switch-loader`
- **PlayStation 1 (PSX)** via `ghidra_psx_ldr`
- **Sega Genesis / Mega Drive** via native 68000 memory maps
- **Sega Master System / Game Gear** via `Ghidra-SegaMasterSystem-Loader`
- **Sega Dreamcast** via native SuperH4 memory maps

### Zero-Input Triage — Worked Example (GBA)

The primary entry point is `triage_and_load_retro_rom`. Call it with any ROM path and the server handles the rest:

```python
# Auto-detect platform, map language, provision session
triage_and_load_retro_rom(rom_path="/data/game.gba")
# → platform: "Game Boy Advance (GBA)"
# → loader:   "GBA ROM Loader"
# → arch:     "ARM:LE:32:v4t"

# Decompile the main entry point on the same session
decompile_function(address="0x00001c2c")
# → decompiled C code for the GBA ROM entry routine

# Search for a known pattern (e.g. 32-bit ARM store-multiple)
search_bytes(pattern="09 08 00 01")
# → matching addresses labelled "gba_ram_start"
```

### Execution Chaining Flow

Instead of forcing your AI agent to spend cycles manually identifying architecture maps, register layouts, or memory segments, chain the automated ingestion pipeline:

1. Invoke `triage_and_load_retro_rom` with a target file path.
2. The server headlessly parses the binary file structure (`NES\x1a`, `NTR`, `NSO0`, `GBA`, SNES title vectors, `PS-X EXE`, `SEGA`, `TMR SEGA`, `SEGA ENTERPRISES`), binds the matching Ghidra language module (`6502:LE:16`, `ARM:LE:32:v4t`, `AARCH64:LE:64`, `65816:LE:24`, `MIPS:LE:32`, `68000:BE:32`, `Z80:16`, `SuperH4:LE:32`), loads standard address memory blocks, and links automated signature cache arrays.
3. Use the integrated `emulate_slice` or `emulate_slice_with_taint` tools to analyze localized console loops — no physical console hardware or open GDB networking ports needed.

### Triage Tool

| Tool | Description |
|---|---|
| `triage_and_load_retro_rom` | Reads raw file magic bytes to detect NES, SNES, GBA, NDS, Switch, PSX, Genesis, SMS, or Dreamcast ROMs. Provisions a correctly-language-mapped Ghidra session and auto-restores cached function signatures. Returns platform, loader, architecture tag, and mapped memory blocks. |

## Quick Start

### 1. Install

```bash
pip install ghidra-bizhawk-mcp
```

Or from source:

```bash
git clone https://github.com/getanirao/ghidra-bizhawk-mcp.git
cd ghidra-bizhawk-mcp
pip install -e .
```

### 2. Set environment

```bash
# Required: point to your Ghidra installation
export GHIDRA_INSTALL_DIR=/opt/ghidra_11.2    # Linux / macOS
set GHIDRA_INSTALL_DIR=C:\Program Files\ghidra_11.2   # Windows

# Optional: enable live BizHawk emulation
export BIZHAWK_EXE_PATH=/path/to/EmuHawk.exe

# Optional: run in mock mode (no Ghidra/BizHawk needed)
export MOCK_MODE=1
```

### 3. Run

```bash
ghidra-bizhawk-mcp
```

The server listens on **stdin/stdout** — pipe it to any MCP-compatible client.

### Docker

```bash
docker build -t ghidra-bizhawk-mcp .
docker run -i --rm -v /path/to/binaries:/data ghidra-bizhawk-mcp
```

The container bundles JDK 17, Ghidra 11.2, and the server — no host dependencies beyond Docker.

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GHIDRA_INSTALL_DIR` | Yes | — | Path to Ghidra installation (e.g. `/opt/ghidra_11.2`) |
| `BIZHAWK_EXE_PATH` | No | — | Path to EmuHawk.exe for live emulation features |
| `MOCK_MODE` | No | `0` | Set to `1` to run without Ghidra/BizHawk (for testing/CI) |

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ghidra-bizhawk": {
      "command": "ghidra-bizhawk-mcp",
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra_11.2"
      }
    }
  }
}
```

### Cursor

Add to your Cursor MCP configuration:

```json
{
  "mcpServers": {
    "ghidra-bizhawk": {
      "command": "ghidra-bizhawk-mcp",
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra_11.2"
      }
    }
  }
}
```

## Tools

### Session management

| Tool | Description |
|---|---|
| `analyze_binary` | Import + analyze a binary, returns a `session_id`. Reuses the ID if provided, otherwise auto-generates. |
| `list_sessions` | List all active workspaces with their session IDs, binary paths, and load times. |
| `close_session` | Close a session and free its Ghidra project resources. |

Most tools accept an optional `session_id` parameter — omit it to use the most recently loaded session.

### Read / Analysis

| Tool | Description |
|---|---|
| `decompile_function` | Decompile a function by name or address. |
| `decompile_function_paginated` | Decompile with `line_start`, `line_end`, `max_tokens` (token-budget truncation), and `summarize` (strips boilerplate locals + collapsing blank lines). Prevents context-window exhaustion. |
| `get_data_types` | List all data types defined in the program. |
| `get_cross_references` | Cross-references to/from an address. |
| `get_call_graph` | Recursive call graph + callers for a function. |
| `analyze_and_decompile_entrypoints` | Composite — bulk decompile all entry points (program entry, exports, `main`, `_start`, etc.) in one call. |
| `generate_workspace_report` | Produce a Markdown summary of the active workspace — entry points, function count, custom symbols, recovered structures, renamed functions, comments. Replaces a GUI CodeBrowser window. |

### Write / Mutation

| Tool | Description |
|---|---|
| `rename_symbol` | Rename a function or label. Stored in the Ghidra project DB. |
| `add_comment` | Attach a comment (`plate`, `pre`, `post`, `eol`, `repeatable`). |
| `create_struct` | Create a custom structured data type from a JSON member layout `[{offset, name, type}, ...]`. Offsets are optional. |
| `retype_variable` | Re-type a local variable or function parameter (e.g. `undefined4*` → `MyStruct*`). |

### Assembly-level

| Tool | Description |
|---|---|
| `disassemble_range` | Disassemble N raw instructions at an address — returns mnemonic, operands, hex bytes, and length for precise lower-level inspection. |
| `get_listing_range` | Raw hex + ASCII dump for a byte range, equivalent to Ghidra's Listing panel. Complements `disassemble_range` for data regions. |

### Byte-sequence search

| Tool | Description |
|---|---|
| `search_bytes` | Search the entire binary for a hex byte pattern (e.g. `09 08 00 01` or `F86D0003`). Returns matching addresses with context bytes and any string label at the hit. |

### Binary diffing

| Tool | Description |
|---|---|
| `diff_binaries` | Compare two loaded sessions by function name and body size. Returns functions unique to each side and changed functions. |

## Workspace Sessions

Each `analyze_binary` call creates a named session. Sessions keep their Ghidra project open independently, so multiple binaries can be loaded concurrently:

```python
# Load two binaries into separate sessions
s1 = analyze_binary(binary_path="/bin/a.out")        # auto session_id
s2 = analyze_binary(binary_path="/bin/b.out", session_id="my_session")

# Operate on a specific session
decompile_function(function_name="main", session_id=s1.session_id)

# Diff them
diff_binaries(session_a=s1.session_id, session_b="my_session")
```

## Deployment

### Docker (multi-user / CI)

```bash
docker build -t ghidra-bizhawk-mcp .

# Run as an MCP subprocess
docker run -i --rm \
  -v /data/binaries:/data \
  ghidra-bizhawk-mcp \
  --ghidra-dir /opt/ghidra
```

The `Dockerfile` bundles Ghidra 11.2 and JDK 17 in a slim Python 3.11 image. Bind-mount your binaries directory at runtime.

### MCP Bundle (MCPB — Claude Desktop / Smithery)

Package as a portable `.mcpb` bundle for one-click install in Claude Desktop or publishing on [Smithery](https://smithery.ai).

**Prerequisites:** Install the MCPB CLI:

```bash
npm install -g @anthropic-ai/mcpb
```

**Build the bundle:**

```bash
# From the repo root
scripts/build-mcpb.ps1
```

Or manually with `mcpb`:

```bash
mcpb pack
```

The output `ghidra-bizhawk-mcp.mcpb` wraps the server with a `manifest.json` that prompts for `GHIDRA_INSTALL_DIR` (required) and optionally `BIZHAWK_EXE_PATH` at install time — no manual JSON editing.

**Publishing to Smithery:**

```bash
smithery mcp publish ./dist/ghidra-bizhawk-mcp.mcpb -n getanirao/ghidra-bizhawk-mcp
```

### P-code micro-emulation

| Tool | Description |
|---|---|
| `emulate_slice` | Headlessly execute N instructions. Seed register state and get a step-by-step trace of register mutations. |
| `emulate_slice_with_taint` | Same as `emulate_slice` but with automated taint tracking — specify a taint register (e.g. `r0`) and the tool flags exactly when its value is modified or propagates to other registers. |
| `emulate_slice_with_breakpoints` | Execute until a condition is met or the count expires. Condition syntax: `R0==0`, `R1>0xFF`, `R2!=R3`, `PC==0x1234`. Stops before or after the matching instruction. |

All run inside the pyhidra process via Ghidra's `EmulatorHelper` — no GDB/LLDB, no network ports, no debugger stubs. Works on ARM, x86, MIPS, and any Ghidra-supported architecture.

#### Worked example — breaking on a register condition

Suppose you're reversing a GBA ROM and want to find the first time `r0` becomes zero inside a loop at `0x08000100`:

```python
# Step until r0 == 0, stop before the matching instruction
result = emulate_slice_with_breakpoints(
    session_id="gba_v1",
    start_address="0x08000100",
    max_instructions=5000,
    stop_condition="R0==0",
    stop_mode="before"
)
# result.exit_reason → "R0==0"
# result.instructions_executed → 312
# result.trace → [step 311: r0 goes 4→2, step 312: r0 goes 2→0]

# Check if a specific address was reached after a branch
result = emulate_slice_with_breakpoints(
    session_id="gba_v1",
    start_address="0x08000100",
    max_instructions=5000,
    stop_condition="PC==0x08001234"
)
# result.exit_reason → "PC==0x08001234"

# Use inequalities to catch bounds checks
result = emulate_slice_with_breakpoints(
    session_id="gba_v1",
    start_address="0x08000100",
    max_instructions=5000,
    stop_condition="R1>0xFF"
)
# result.exit_reason → "R1>0xFF"
# result.last_step["r1"] → 0x100
```

This is especially powerful for identifying copy-loop bounds (`R3 >= R4`), null-pointer paths (`R0==0`), or switch-table targets (`PC==0x`).

### Function fingerprinting / signature transfer

| Tool | Description |
|---|---|
| `calculate_function_fingerprint` | Generate a structural hash for a function (vars, params, body size, branches, called funcs, embedded strings, numeric constants). Survives compiler reordering. |
| `export_signature_map` | Build a complete `{hash → name}` map for every function in the current binary. Save this JSON to reuse across versions. |
| `apply_signature_map` | Pass a previously exported signature map; the server sweeps the binary and renames every matching function automatically. |

### Persistent signature stash (server-side cache)

| Tool | Description |
|---|---|
| `save_active_binary_signature` | Fingerprint all functions and stash the map under a `lineage_group_id` (e.g. `"my_firmware_v1"`). Stored in `~/.ghidra_bizhawk_mcp/signatures/` — no JSON files to manage. |
| `auto_restore_signatures_from_stash` | Load a stashed map by `lineage_group_id` and auto-rename every matching function. |
| `auto_stash_current_binary` | **Zero-input auto-stash** — hashes the binary's first 4 KB, saves a map under that hash. Just analyze and call. |
| `auto_restore_current_binary` | **Zero-input auto-restore** — hashes the binary, looks up a previous stash, renames matches. No group ID needed. |
| `list_stashed_signature_groups` | List all stashed groups currently in the local cache. |

**Workflow — fully automated persistence:**

```python
# Analyze v1 — stashes automatically under binary content hash
s1 = analyze_binary(binary_path="/bin/v1.bin")
auto_stash_current_binary(session_id=s1.session_id)

# Later, analyze v2 — restores automatically
s2 = analyze_binary(binary_path="/bin/v2.bin")
auto_restore_current_binary(session_id=s2.session_id)
# → 142 functions renamed, zero manual JSON handling
```

## Demo

![Claude Desktop requesting a GBA ROM triage and getting a decompiled function back](assets/demo-claude-triage.png)

*Claude Desktop: "Decompile the entry point of this GBA ROM and trace r0 propagation" — the server auto-detects the ARMv4t language, provisions a session, and returns decompiled C + taint trace.*

![Terminal output showing triage_and_load_retro_rom detecting a PSX EXE](assets/demo-terminal-triage.png)

*Console output from `triage_and_load_retro_rom` detecting a PlayStation 1 executable (`PS-X EXE` magic), mapping MIPS:LE:32, and auto-restoring cached signatures.*

### Try these prompts

After configuring your MCP client (see [Configuration](#configuration)), ask your AI agent:
- *"Load this GBA ROM and decompile the entry point."*
- *"What functions call 0x8001234 in this NDS binary?"*
- *"Triage this PSX EXE and trace r0 through the first 20 instructions."*
- *"Diff the two sessions I have open and show me changed functions."*

## Project Structure

```
ghidra-bizhawk-mcp/
├── Dockerfile
├── pyproject.toml
├── README.md
└── src/ghidra_bizhawk_mcp/
    ├── __init__.py
    ├── server.py          # MCP server, tool registry, stdio transport
    ├── ghidra_bridge.py   # GhidraSession — pyghidra wrapper, all Ghidra logic
    ├── lua/
    │   └── bridge.lua     # BizHawk-side Lua bridge for live emulation
    └── tools/
        ├── __init__.py
        ├── bizhawk_bridge.py  # TCP server bridging MCP ↔ BizHawk
        └── ...
```

## How it works

1. `pyhidra.start()` boots Ghidra's JVM once at server startup
2. Each `analyze_binary` call opens a new Ghidra project in its own named session
3. Read/write tools route to the requested session via `session_id` (or the active default)
4. Write tools apply changes directly to the Ghidra program database
5. Sessions persist until explicitly closed — enabling multi-binary workflows and diffing

<!-- mcp-name: io.github.getanirao/ghidra-bizhawk-mcp -->
