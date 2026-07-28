import argparse
import asyncio
import logging
import os
import sys

from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

from .tools.bizhawk_bridge import get_bridge

logger = logging.getLogger(__name__)


# ── Annotation constants ────────────────────────────────────────────
ANNOTATION_READONLY = types.ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

ANNOTATION_READONLY_EXTERNAL = types.ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

ANNOTATION_WRITE = types.ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

OUTPUT_SCHEMA_RESULT = {
    "type": "object",
    "description": "Tool execution result as a JSON-formatted string",
}

ANNOTATION_DESTRUCTIVE = types.ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)


def _sid(arguments: dict) -> str | None:
    return arguments.get("session_id")


def _structured_content(result):
    if isinstance(result, dict):
        return result
    return {"result": result}


def _tool_success(result) -> types.CallToolResult:
    structured = _structured_content(result)
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=_format_result(structured))],
        structuredContent=structured,
        isError=False,
    )


def _tool_error(tool_name: str, exc: Exception) -> types.CallToolResult:
    message = str(exc)
    structured = {
        "ok": False,
        "tool": tool_name,
        "error": {
            "type": exc.__class__.__name__,
            "message": message,
        },
    }
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=f"Error: {message}")],
        structuredContent=structured,
        isError=True,
    )


# ── Prompts ─────────────────────────────────────────────────────────
PROMPTS = [
    types.Prompt(
        name="analyze_rom",
        description="Guided ROM analysis workflow: triage a retro ROM, decompile entry points, and run initial analysis in one session.",
        arguments=[
            types.PromptArgument(
                name="rom_path",
                description="Absolute path to the ROM file to analyze",
                required=True,
            ),
        ],
    ),
    types.Prompt(
        name="session_workflow",
        description="Demonstrates a full reverse-engineering session: load binary, explore functions, analyze call graphs, and generate a report.",
        arguments=[
            types.PromptArgument(
                name="binary_path",
                description="Optional path to a binary to analyze. If omitted, demonstrates the general workflow.",
                required=False,
            ),
        ],
    ),
    types.Prompt(
        name="debug_emulation",
        description="P-code emulation debugging workflow: set up emulation context, step through instructions, and analyze register/memory state.",
        arguments=[
            types.PromptArgument(
                name="address",
                description="Starting address for emulation (e.g. '0x08000100')",
                required=True,
            ),
            types.PromptArgument(
                name="session_id",
                description="Session ID for the loaded binary context",
                required=False,
            ),
        ],
    ),
    types.Prompt(
        name="live_debug",
        description="Combined Ghidra + BizHawk workflow: analyze a ROM in Ghidra, connect to BizHawk emulation, and correlate static decompilation with live memory state.",
        arguments=[
            types.PromptArgument(
                name="rom_path",
                description="Path to the ROM file for analysis",
                required=True,
            ),
        ],
    ),
    types.Prompt(
        name="binary_diff",
        description="Compare two binary versions: load both, diff functions, and identify changed or new functions between versions.",
        arguments=[
            types.PromptArgument(
                name="binary_a",
                description="Path to the first binary (e.g. original firmware)",
                required=True,
            ),
            types.PromptArgument(
                name="binary_b",
                description="Path to the second binary (e.g. patched firmware)",
                required=True,
            ),
        ],
    ),
]


TOOLS = [
    # ── Session management ──────────────────────────────────────────
    types.Tool(
        name="ghidra_analyze",
        description="Import and analyze a binary into a named Ghidra session. Creates or replaces a session. Returns session_id, platform info, and function count. Call this first before any other Ghidra analysis tool.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Absolute path to the binary file to analyze. Supports ELF, PE, Mach-O, and raw binaries."},
                "session_id": {"type": "string", "description": "Optional session tracking ID. Auto-generated if omitted. Use to reuse a session across multiple tool calls."},
            },
            "required": ["binary_path"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_sessions",
        description="List all active Ghidra session workspaces with their session IDs, binary paths, and load timestamps. Useful before calling ghidra.session_close or ghidra.diff.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Optional session ID to filter by. Returns only the matching session if provided."},
            },
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_session_close",
        description="Close and remove a Ghidra session workspace, freeing project resources. Cannot be undone. Use ghidra.sessions first to find active session IDs.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID to close. Get active sessions from ghidra.sessions."},
            },
            "required": ["session_id"],
        },
        annotations=ANNOTATION_DESTRUCTIVE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    # ── Ghidra read / analysis ──────────────────────────────────────
    types.Tool(
        name="ghidra_decompile",
        description="Decompile a function by name or hex address. Returns decompiled C code. Use after session.analyze has loaded a binary.",
        inputSchema={
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "Function name (e.g. 'main', 'FUN_08000100') or hex address (e.g. '0x08000100')"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["function_name"],
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_decompile_paginated",
        description="Decompile a function with line range, token budget, and optional summarization to prevent context-window exhaustion on large functions. Use for functions over 50 lines.",
        inputSchema={
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "Function name or hex address to decompile"},
                "line_start": {"type": "integer", "description": "1-indexed start line for paginated output"},
                "line_end": {"type": "integer", "description": "1-indexed end line (exclusive) for paginated output"},
                "max_tokens": {"type": "integer", "description": "Truncate output to approximately N tokens to stay within context budget"},
                "summarize": {"type": "boolean", "description": "Set to true to strip boilerplate local variable declarations and collapse blank lines"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["function_name"],
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_data_types",
        description="List all data types defined in the loaded program, including structures, enums, and typedefs. Useful for understanding the program's type landscape before creating new types.",
        inputSchema={
            "type": "object",
            "properties": {"session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"}},
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_cross_references",
        description="Get cross-references to and from a given address. Shows what references the address and what the address references. Useful for understanding how data or code is used across the binary.",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Target address (e.g. '0x401000') to find cross-references for"},
                "max_results": {"type": "integer", "default": 100, "description": "Maximum number of reference results to return (default 100)"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["address"],
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_call_graph",
        description="Get the call graph for a function — shows which functions it calls (callees) and which functions call it (callers). Use after ghidra.decompile to understand function relationships.",
        inputSchema={
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "Function name or hex address to get the call graph for"},
                "max_depth": {"type": "integer", "default": 3, "description": "Recursion depth for the call graph (default 3, max 10)"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["function_name"],
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_decompile_entrypoints",
        description="Composite tool that bulk-decompiles all entry points in one call — program entry, exports, main, _start, etc. Use early in analysis to get an overview of the binary's surface area.",
        inputSchema={
            "type": "object",
            "properties": {"session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"}},
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_report",
        description="Produce a Markdown summary of the active workspace — functions, entry points, custom symbols, recovered structures, renamed functions, and comment count. Replaces a GUI CodeBrowser window. Call at the end of a session to get a human-readable overview.",
        inputSchema={
            "type": "object",
            "properties": {"session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"}},
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    # ── Ghidra write / mutation ─────────────────────────────────────
    types.Tool(
        name="ghidra_rename",
        description="Rename a function or label at a given address. Changes are stored in the Ghidra project database. Use to replace auto-generated names like FUN_* with meaningful identifiers.",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address of the symbol to rename (e.g. '0x08000100')"},
                "new_name": {"type": "string", "description": "New name for the symbol (alphanumeric + underscores only)"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["address", "new_name"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_comment",
        description="Attach a comment to a code unit at a given address. Supports comment types: plate, pre, post, eol, repeatable. Use to document reverse-engineering findings inline.",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address to attach the comment to (e.g. '0x08000100')"},
                "text": {"type": "string", "description": "Comment text content"},
                "comment_type": {"type": "string", "default": "plate", "description": "Type of comment: 'plate' (boxed header), 'pre' (before code), 'post' (after code), 'eol' (end of line), 'repeatable' (appears at all references)"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["address", "text"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_create_struct",
        description="Create a custom structured data type from a JSON member layout. Each member specifies offset (optional), field name, and type string. Use to model protocol headers, packet formats, and data structures.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Name for the new struct type (e.g. 'PacketHeader')"},
                "members": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "offset": {"type": "integer", "description": "Byte offset within struct (optional — appended sequentially if omitted)"},
                            "name": {"type": "string", "description": "Field name (e.g. 'length', 'checksum')"},
                            "type": {"type": "string", "description": "Type string: primitive (int, char, byte) or reference (MyStruct*, MyStruct)"},
                        },
                        "required": ["name", "type"],
                    },
                    "description": "Array of member field definitions forming the struct layout",
                },
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["name", "members"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_retype",
        description="Change a local variable or function parameter's type annotation in the decompiled view. Use to replace generic types like undefined4* with meaningful types like MyStruct* for cleaner decompilation.",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address inside the function containing the variable to retype"},
                "variable_name": {"type": "string", "description": "Name of the local variable or parameter to retype"},
                "new_type": {"type": "string", "description": "New type string (e.g. 'MyStruct*', 'int', 'char[256]')"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["address", "variable_name", "new_type"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    # ── Ghidra assembly / instruction ───────────────────────────────
    types.Tool(
        name="ghidra_disassemble",
        description="Disassemble N raw instructions at an address. Returns mnemonic, operands, hex bytes, and length for each instruction. Use for precise lower-level inspection when decompiled C is insufficient.",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Starting address for disassembly (e.g. '0x08000100')"},
                "instruction_count": {"type": "integer", "default": 10, "description": "Number of instructions to disassemble (default 10, max 100)"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["address"],
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    # ── Ghidra byte search / listing ────────────────────────────────
    types.Tool(
        name="ghidra_search",
        description="Search the entire loaded binary for a hex byte pattern. Returns matching addresses with context bytes and any string labels at the hit. Use to locate known constants, magic bytes, or patch locations.",
        inputSchema={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Hex byte pattern to search for (e.g. '09 08 00 01' with spaces, or 'F86D0003' without)"},
                "max_results": {"type": "integer", "default": 50, "description": "Maximum number of matches to return (default 50)"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["pattern"],
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_listing",
        description="Return a raw hex + ASCII dump for a byte range, equivalent to Ghidra's Listing panel. Complements ghidra.disassemble for inspecting data regions, strings, and padding.",
        inputSchema={
            "type": "object",
            "properties": {
                "start_address": {"type": "string", "description": "Starting address for the hex dump (e.g. '0x08000100')"},
                "byte_count": {"type": "integer", "default": 64, "description": "Total number of bytes to dump (default 64, max 4096)"},
                "columns": {"type": "integer", "default": 16, "description": "Bytes per row in the hex dump (default 16)"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["start_address"],
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    # ── Ghidra binary diffing ───────────────────────────────────────
    types.Tool(
        name="ghidra_diff",
        description="Compare two loaded sessions by function name and body size. Returns functions unique to each side and functions that changed between versions. Use for patch diffing and version comparison.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_a": {"type": "string", "description": "First session ID (the 'old' binary)"},
                "session_b": {"type": "string", "description": "Second session ID (the 'new' binary)"},
            },
            "required": ["session_a", "session_b"],
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    # ── Ghidra P-code emulation ─────────────────────────────────────
    types.Tool(
        name="ghidra_emulate",
        description="Headlessly execute a slice of instructions using Ghidra's P-code emulator. Seed initial register values and track value propagation across execution steps. No debugger, GDB stub, or network needed. Works on any Ghidra-supported architecture (ARM, x86, MIPS, etc.)",
        inputSchema={
            "type": "object",
            "properties": {
                "start_address": {"type": "string", "description": "Starting address for emulation (e.g. '0x1000')"},
                "instruction_count": {"type": "integer", "default": 10, "description": "Number of instructions to step through (default 10)"},
                "initial_registers": {
                    "type": "object",
                    "description": "Register seed values as a JSON object, e.g. {\"r0\": 5, \"r1\": 1095216660}. Omit to use Ghidra's default initial state.",
                    "additionalProperties": {"type": "integer"},
                },
                "track_registers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Subset of register names to log at each step (default: all seeded registers + PC). Example: [\"r0\", \"r1\", \"pc\"]",
                },
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["start_address"],
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_emulate_taint",
        description="Execute an instruction slice with automatic taint tracking. Specify a taint register; the tool reports every step where its value is modified or propagates to other registers. Use to trace data flows through cryptographic routines or input processing.",
        inputSchema={
            "type": "object",
            "properties": {
                "start_address": {"type": "string", "description": "Starting address for emulation (e.g. '0x1000')"},
                "instruction_count": {"type": "integer", "default": 10, "description": "Number of instructions to step through (default 10)"},
                "initial_registers": {
                    "type": "object",
                    "description": "Register seed values, e.g. {\"r0\": 5, \"r1\": 0x41424344}",
                    "additionalProperties": {"type": "integer"},
                },
                "taint_register": {"type": "string", "default": "r0", "description": "Register name to track for data lineage and propagation (default 'r0')"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["start_address"],
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_emulate_breakpoints",
        description="Execute instructions until a break condition is met or the instruction count expires. Supports equality (R0==0), inequality (R1>0xFF), not-equal (R2!=R3), and PC address (PC==0x1234). Stops before or after the matching instruction. Ideal for finding copy-loop bounds, null-pointer paths, or switch-table targets.",
        inputSchema={
            "type": "object",
            "properties": {
                "start_address": {"type": "string", "description": "Starting address for emulation (e.g. '0x1000')"},
                "instruction_count": {"type": "integer", "default": 50, "description": "Maximum instructions to execute before timeout (default 50)"},
                "initial_registers": {
                    "type": "object",
                    "additionalProperties": {"type": "integer"},
                    "description": "Register seed values for initial emulator state",
                },
                "break_condition": {"type": "string", "description": "Break condition string. Supported: R0==0, R1>0xFF, R2!=R3, PC==0x1234. Example: 'R0==0' stops when register r0 becomes zero."},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["start_address"],
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    # ── Ghidra function fingerprinting / signatures ─────────────────
    types.Tool(
        name="ghidra_fingerprint",
        description="Generate a behavior-based structural hash for a function that survives compiler shuffling and optimization changes across binary versions. Use with ghidra.apply_signatures for cross-version function matching.",
        inputSchema={
            "type": "object",
            "properties": {
                "func_name": {"type": "string", "description": "Function name or address to fingerprint (e.g. 'main' or '0x08000100')"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["func_name"],
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_export_signatures",
        description="Export a complete {structural_hash -> function_name} signature map for every function in the current binary. Save the output JSON to reuse across binary versions. Call before closing a session to preserve naming for future diffing.",
        inputSchema={
            "type": "object",
            "properties": {"session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"}},
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_apply_signatures",
        description="Scan the current binary, match every function by structural fingerprint against a previously exported signature map, and rename matches automatically. Use after loading a new binary version to restore meaningful names.",
        inputSchema={
            "type": "object",
            "properties": {
                "signature_json_map": {
                    "type": "object",
                    "description": "Signature map JSON object from a previous ghidra.export_signatures call. Format: {hash: function_name}",
                },
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["signature_json_map"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    # ── Ghidra persistent signature stash ───────────────────────────
    types.Tool(
        name="ghidra_stash_save",
        description="Fingerprint all functions and stash the signature map server-side under a lineage_group_id label (e.g. 'my_firmware_v1'). No JSON file management needed — stored in ~/.ghidra_bizhawk_mcp/signatures/.",
        inputSchema={
            "type": "object",
            "properties": {
                "lineage_group_id": {"type": "string", "description": "Arbitrary group name for this binary family (e.g. 'my_firmware_v1', 'router_fw_3.x')"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["lineage_group_id"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_stash_restore",
        description="Load a previously stashed signature map by lineage_group_id and auto-rename every matching function in the current session. Use with ghidra.stash_save for persistent cross-version function name recovery.",
        inputSchema={
            "type": "object",
            "properties": {
                "lineage_group_id": {"type": "string", "description": "Group name that was used during ghidra.stash_save (e.g. 'my_firmware_v1')"},
                "session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"},
            },
            "required": ["lineage_group_id"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_stash_auto_save",
        description="Zero-input auto-stash: hashes the loaded binary's first 4 KB and saves a signature map under that hash. No group ID or user input needed. Just analyze and call.",
        inputSchema={
            "type": "object",
            "properties": {"session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"}},
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_stash_auto_restore",
        description="Zero-input auto-restore: hashes the loaded binary, looks up a previously stashed map by content hash, and renames matching functions automatically. Pair with ghidra.stash_auto_save for fully automatic cross-version name recovery.",
        inputSchema={
            "type": "object",
            "properties": {"session_id": {"type": "string", "description": "Session ID (defaults to most recently active session)"}},
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="ghidra_stash_list",
        description="List all stashed signature groups currently in the local server cache (~/.ghidra_bizhawk_mcp/signatures/). Use before ghidra.stash_restore to see available lineage_group_ids.",
        inputSchema={
            "type": "object",
            "properties": {
                "lineage_group_id": {"type": "string", "description": "Optional lineage group ID to filter by. Returns details for a specific group if provided."},
            },
        },
        annotations=ANNOTATION_READONLY,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    # ── Retro platform triage ───────────────────────────────────────────
    types.Tool(
        name="ghidra_triage",
        description="Examines raw file magic header signatures to detect retro console architectures (NES, SNES, GBA, NDS, Switch, PSX, Genesis, SMS, Dreamcast), headlessly maps correct Ghidra language loaders, hooks multi-session project bindings, and applies automated signature caching overlays. Single-call entry point for ROM analysis.",
        inputSchema={
            "type": "object",
            "properties": {
                "rom_path": {"type": "string", "description": "Absolute system path to the targeted emulator ROM image or raw memory partition block dump"},
                "session_id": {"type": "string", "description": "Optional session tracking token for parallel multi-binary session context"},
            },
            "required": ["rom_path"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    # ── BizHawk live emulation ──────────────────────────────────────────
    types.Tool(
        name="bizhawk_connect",
        description="Check connectivity to BizHawk by pinging the bridge.lua script running inside EmuHawk. Use first before any other bizhawk.* tool to verify the emulator is responsive.",
        inputSchema={
            "type": "object",
            "properties": {
                "timeout": {"type": "integer", "default": 5, "description": "Connection timeout in seconds (default 5). Increase for slow or remote emulator instances."},
            },
        },
        annotations=ANNOTATION_READONLY_EXTERNAL,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_info",
        description="Get ROM name, ROM hash, current framecount, available memory domains, and capabilities from the connected BizHawk instance.",
        inputSchema={
            "type": "object",
            "properties": {
                "detail": {"type": "string", "enum": ["summary", "full"], "default": "summary", "description": "Detail level: 'summary' for key info, 'full' for all available metadata including memory domains."},
            },
        },
        annotations=ANNOTATION_READONLY_EXTERNAL,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_memory_domains",
        description="List available memory domains for the currently loaded emulation core (e.g. WRAM, RAM, EWRAM, VRAM, System Bus). Use before bizhawk.read to determine valid domain names.",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Optional domain name to get details for a specific memory domain (e.g. 'WRAM', 'VRAM'). Returns all domains if omitted."},
            },
        },
        annotations=ANNOTATION_READONLY_EXTERNAL,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_read",
        description="Read bytes from BizHawk emulated memory at a given address. Returns an array of byte values. Use bizhawk.memory_domains first to discover valid domain names for the loaded game.",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "integer", "description": "Starting memory address (decimal or hex format, e.g. 0x02000000)"},
                "size": {"type": "integer", "default": 4, "description": "Number of bytes to read (default 4, max 4096)"},
                "domain": {"type": "string", "description": "Memory domain name (e.g. WRAM, RAM, EWRAM, VRAM, System Bus). Use bizhawk.memory_domains to discover available names."},
            },
            "required": ["address"],
        },
        annotations=ANNOTATION_READONLY_EXTERNAL,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_write",
        description="Write bytes to BizHawk emulated memory at a given address. Use to patch game state, inject values, or modify emulated hardware registers in real time.",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "integer", "description": "Starting memory address to write to (decimal or hex)"},
                "data": {"type": "array", "items": {"type": "integer"}, "description": "Array of byte values to write (max 4096 bytes). Example: [0x00, 0xFF, 0xAB]"},
                "domain": {"type": "string", "description": "Optional memory domain (e.g. WRAM, RAM). Defaults to system bus."},
            },
            "required": ["address", "data"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_buttons",
        description="Set joypad button state for a player. Accepts an object like {A: true, B: true, Up: true, Start: true, Select: true}. State persists until changed or cleared. Use bizhawk_tap_buttons for a single atomic press/hold/release sequence.",
        inputSchema={
            "type": "object",
            "properties": {
                "buttons": {
                    "type": "object",
                    "description": "Button states as {ButtonName: true/false}. Valid names: A, B, Up, Down, Left, Right, Start, Select, L, R, X, Y (console-dependent). Example: {A: true, Start: true}",
                    "additionalProperties": {"type": "boolean"},
                },
                "player": {"type": "integer", "default": 1, "description": "Player number (1-based). Player 1 is the default."},
            },
            "required": ["buttons"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_input_state",
        description="Read the current joypad state for a player. Returns the active button table as reported by BizHawk, which is useful for verifying that input was applied correctly.",
        inputSchema={
            "type": "object",
            "properties": {
                "player": {"type": "integer", "default": 1, "description": "Player number (1-based). Player 1 is the default."},
            },
        },
        annotations=ANNOTATION_READONLY_EXTERNAL,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_frame",
        description="Advance the emulator by N frames. Use to step through execution frame by frame. If you need to apply input and release it atomically, prefer bizhawk_tap_buttons.",
        inputSchema={
            "type": "object",
            "properties": {
                "count": {"type": "integer", "default": 1, "description": "Number of frames to advance (default 1). Use higher values to fast-forward through known sequences."},
            },
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_tap_buttons",
        description="Atomically press a set of buttons for a fixed number of frames, then release them. Use for timed inputs such as a one-frame tap or a short hold.",
        inputSchema={
            "type": "object",
            "properties": {
                "buttons": {
                    "type": "object",
                    "description": "Button states as {ButtonName: true/false}. Valid names: A, B, Up, Down, Left, Right, Start, Select, L, R, X, Y (console-dependent). Example: {A: true, Start: true}",
                    "additionalProperties": {"type": "boolean"},
                },
                "frames": {"type": "integer", "default": 1, "description": "Number of frames to hold the buttons before releasing them."},
                "player": {"type": "integer", "default": 1, "description": "Player number (1-based). Player 1 is the default."},
            },
            "required": ["buttons"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_pause",
        description="Pause BizHawk emulation. Use before reading memory or inspecting state to prevent the emulated system from changing values between operations.",
        inputSchema={
            "type": "object",
            "properties": {
                "reason": {"type": "string", "description": "Optional reason for pausing (e.g. 'reading memory', 'inspecting state'). Logged for debugging."},
            },
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_unpause",
        description="Unpause BizHawk emulation after a previous pause call. The emulated system resumes normal execution.",
        inputSchema={
            "type": "object",
            "properties": {
                "reason": {"type": "string", "description": "Optional reason for unpausing (e.g. 'resuming after memory read'). Logged for debugging."},
            },
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_reset",
        description="Reset the loaded emulation core (reboot the emulated console). All emulated memory and CPU state is lost. Use to restart a game or boot a different ROM path.",
        inputSchema={
            "type": "object",
            "properties": {
                "hard": {"type": "boolean", "default": False, "description": "If true, perform a hard reset (reload ROM). If false (default), perform a soft reset."},
            },
        },
        annotations=ANNOTATION_DESTRUCTIVE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_screenshot",
        description="Save a PNG screenshot of the current emulator display to a file path. Useful for capturing in-game state, error screens, or UI elements during automated testing.",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute file path to save the PNG screenshot (e.g. 'C:/temp/shot.png' or '/tmp/shot.png')"},
            },
            "required": ["path"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_save_state",
        description="Save the current emulator state to a file. The savestate captures all CPU registers, memory, and hardware state for later reload. Use with bizhawk.load_state for checkpoint-based testing workflows.",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute file path for the savestate (e.g. 'C:/temp/state.bin')"},
            },
            "required": ["path"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_load_state",
        description="Load emulator state from a previously saved savestate file. Restores all CPU registers, memory, and hardware state exactly. Use with bizhawk.save_state for reproducible testing.",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute file path of the savestate to load (e.g. 'C:/temp/state.bin')"},
            },
            "required": ["path"],
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
    types.Tool(
        name="bizhawk_launch",
        description="Launch the BizHawk emulator process and establish the Lua bridge connection. Optionally specify a ROM path to load. Call this first before any other bizhawk.* tool if the emulator is not already running.",
        inputSchema={
            "type": "object",
            "properties": {
                "rom_path": {"type": "string", "description": "Optional absolute path to a ROM file to load on startup"},
            },
        },
        annotations=ANNOTATION_WRITE,
        outputSchema=OUTPUT_SCHEMA_RESULT,
    ),
]


async def serve(ghidra_dir: str | None = None):
    mock_mode = os.environ.get("MOCK_MODE") == "1"

    if not mock_mode:
        from .ghidra_bridge import GhidraSession
        session = GhidraSession(ghidra_dir=ghidra_dir or os.environ.get("GHIDRA_INSTALL_DIR"))
        await get_bridge().start()
        asyncio.create_task(_boot_jvm(session))
    else:
        logger.info("MOCK_MODE=1 — skipping GhidraSession import, bridge, and JVM boot")
        session = None
    server = Server("ghidra-bizhawk-mcp")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return TOOLS

    @server.list_prompts()
    async def list_prompts() -> list[types.Prompt]:
        return PROMPTS

    @server.get_prompt()
    async def get_prompt(name: str, arguments: dict | None = None) -> types.GetPromptResult:
        if name == "analyze_rom":
            rom_path = arguments.get("rom_path", "") if arguments else ""
            return types.GetPromptResult(
                description="Guided ROM analysis workflow",
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"Load the ROM at {rom_path} using ghidra_triage, then decompile its entry points with ghidra_decompile_entrypoints, and generate a report with ghidra_report.",
                        ),
                    ),
                ],
            )
        if name == "session_workflow":
            binary_path = arguments.get("binary_path", "") if arguments else ""
            path_hint = f"Load {binary_path}, then " if binary_path else ""
            return types.GetPromptResult(
                description="Full reverse-engineering session workflow",
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"{path_hint}Start a RE session: 1) ghidra_analyze a binary, 2) ghidra_decompile key functions, 3) ghidra_call_graph to understand relationships, 4) ghidra_rename and ghidra_comment to document findings, 5) ghidra_report to summarize.",
                        ),
                    ),
                ],
            )
        if name == "debug_emulation":
            address = arguments.get("address", "") if arguments else ""
            sid = arguments.get("session_id", "") if arguments else ""
            return types.GetPromptResult(
                description="P-code emulation debugging workflow",
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"Set up P-code emulation at {address} using ghidra_emulate. Step through instructions, inspect register changes, and use ghidra_emulate_breakpoints to find where a specific condition occurs.{' Session: ' + sid if sid else ''}",
                        ),
                    ),
                ],
            )
        if name == "live_debug":
            rom_path = arguments.get("rom_path", "") if arguments else ""
            return types.GetPromptResult(
                description="Combined Ghidra + BizHawk live debugging workflow",
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"Analyze {rom_path} with ghidra_triage, then decompile key functions. Connect BizHawk with bizhawk_connect, read live memory with bizhawk_read at addresses from Ghidra's analysis, and correlate static decompilation with runtime values.",
                        ),
                    ),
                ],
            )
        if name == "binary_diff":
            binary_a = arguments.get("binary_a", "") if arguments else ""
            binary_b = arguments.get("binary_b", "") if arguments else ""
            return types.GetPromptResult(
                description="Binary diffing workflow between two firmware versions",
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"Load both binaries into separate Ghidra sessions with ghidra_analyze (paths: {binary_a}, {binary_b}). Then use ghidra_diff to compare function changes between session_a and session_b. Investigate changed functions with ghidra_decompile.",
                        ),
                    ),
                ],
            )
        raise ValueError(f"Unknown prompt: {name}")

    @server.list_resources()
    async def list_resources() -> list[types.Resource]:
        return []

    @server.read_resource()
    async def read_resource(uri: str) -> str:
        raise ValueError(f"Unknown resource: {uri}")

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> types.CallToolResult:
        try:
            result = await _dispatch(name, arguments, session)
            return _tool_success(result)
        except Exception as e:
            logger.exception("Tool call failed")
            return _tool_error(name, e)

    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="ghidra-bizhawk-mcp",
                    server_version="0.1.0",
                    instructions="This MCP server bridges Ghidra static analysis with BizHawk live emulation for retro-reversing. Ghidra tools (ghidra_*) handle session management, decompilation, disassembly, search, emulation, function fingerprinting, signature stashing, and ROM triage. BizHawk tools (bizhawk_*) control live emulation — connect, read/write memory, press buttons, frame-advance, save/load states. Start with ghidra_analyze or ghidra_triage, then use ghidra_decompile and ghidra_emulate for analysis.",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        await get_bridge().stop()


async def _dispatch(name: str, args: dict, session):
    sid = args.get("session_id")

    # Ghidra session management
    if name == "ghidra_analyze":
        return session.analyze_binary(
            binary_path=args["binary_path"],
            session_id=args.get("session_id"),
        )
    if name == "ghidra_sessions":
        return session.list_sessions()
    if name == "ghidra_session_close":
        session.close_session(args["session_id"])
        return {"status": "closed", "session_id": args["session_id"]}

    # Ghidra read / analysis
    if name == "ghidra_decompile":
        return session.decompile_function(args["function_name"], session_id=sid)
    if name == "ghidra_decompile_paginated":
        return session.decompile_function_paginated(
            function_name=args["function_name"],
            line_start=args.get("line_start"),
            line_end=args.get("line_end"),
            max_tokens=args.get("max_tokens"),
            summarize=args.get("summarize", False),
            session_id=sid,
        )
    if name == "ghidra_data_types":
        return session.get_data_types(session_id=sid)
    if name == "ghidra_cross_references":
        return session.get_cross_references(
            address=args["address"],
            max_results=args.get("max_results", 100),
            session_id=sid,
        )
    if name == "ghidra_call_graph":
        return session.get_call_graph(
            function_name=args["function_name"],
            max_depth=args.get("max_depth", 3),
            session_id=sid,
        )
    if name == "ghidra_decompile_entrypoints":
        return session.analyze_and_decompile_entrypoints(session_id=sid)
    if name == "ghidra_report":
        return session.generate_workspace_report(session_id=sid)

    # Ghidra write / mutation
    if name == "ghidra_rename":
        return session.rename_symbol(args["address"], args["new_name"], session_id=sid)
    if name == "ghidra_comment":
        return session.add_comment(
            address=args["address"],
            text=args["text"],
            comment_type=args.get("comment_type", "plate"),
            session_id=sid,
        )
    if name == "ghidra_create_struct":
        return session.create_struct(args["name"], args["members"], session_id=sid)
    if name == "ghidra_retype":
        return session.retype_variable(
            address=args["address"],
            variable_name=args["variable_name"],
            new_type=args["new_type"],
            session_id=sid,
        )

    # Ghidra assembly
    if name == "ghidra_disassemble":
        return session.disassemble_range(
            address=args["address"],
            instruction_count=args.get("instruction_count", 10),
            session_id=sid,
        )

    # Ghidra byte search / listing
    if name == "ghidra_search":
        return session.search_bytes(
            pattern=args["pattern"],
            max_results=args.get("max_results", 50),
            session_id=sid,
        )
    if name == "ghidra_listing":
        return session.get_listing_range(
            start_address=args["start_address"],
            byte_count=args.get("byte_count", 64),
            columns=args.get("columns", 16),
            session_id=sid,
        )

    # Ghidra binary diffing
    if name == "ghidra_diff":
        return session.diff_binaries(
            session_a=args["session_a"],
            session_b=args["session_b"],
        )

    # Ghidra P-code emulation
    if name == "ghidra_emulate":
        return session.emulate_slice(
            start_address=args["start_address"],
            instruction_count=args.get("instruction_count", 10),
            initial_registers=args.get("initial_registers"),
            track_registers=args.get("track_registers"),
            session_id=sid,
        )
    if name == "ghidra_emulate_taint":
        return session.emulate_slice_with_taint(
            start_address=args["start_address"],
            instruction_count=args.get("instruction_count", 10),
            initial_registers=args.get("initial_registers"),
            taint_register=args.get("taint_register", "r0"),
            session_id=sid,
        )
    if name == "ghidra_emulate_breakpoints":
        return session.emulate_slice_with_breakpoints(
            start_address=args["start_address"],
            instruction_count=args.get("instruction_count", 50),
            initial_registers=args.get("initial_registers"),
            break_condition=args.get("break_condition", ""),
            session_id=sid,
        )

    # Ghidra function fingerprinting / signatures
    if name == "ghidra_fingerprint":
        return session.calculate_function_fingerprint(args["func_name"], session_id=sid)
    if name == "ghidra_export_signatures":
        return session.export_signature_map(session_id=sid)
    if name == "ghidra_apply_signatures":
        return session.apply_signature_map(args["signature_json_map"], session_id=sid)

    # Ghidra persistent signature stash
    if name == "ghidra_stash_save":
        return session.save_active_binary_signature(args["lineage_group_id"], session_id=sid)
    if name == "ghidra_stash_restore":
        return session.auto_restore_signatures_from_stash(args["lineage_group_id"], session_id=sid)
    if name == "ghidra_stash_auto_save":
        return session.auto_stash_current_binary(session_id=sid)
    if name == "ghidra_stash_auto_restore":
        return session.auto_restore_current_binary(session_id=sid)
    if name == "ghidra_stash_list":
        return session.list_stashed_signature_groups()

    # Retro platform triage
    if name == "ghidra_triage":
        return session.triage_and_load_retro_rom(
            rom_path=args["rom_path"],
            session_id=args.get("session_id"),
        )

    # ── BizHawk live emulation ──────────────────────────────────────────
    bridge = get_bridge()
    mock_mode = os.environ.get("MOCK_MODE") == "1"

    if mock_mode:
        if name.startswith("bizhawk_"):
            return {"status": "mock", "note": "MOCK_MODE enabled — BizHawk not available"}
        return {"status": "mock", "note": f"MOCK_MODE enabled — {name} not available"}

    if name == "bizhawk_connect":
        result = await bridge.send_command("ping")
        return {
            "status": "connected",
            "transport": {
                "tcp_connected": True,
                "lua_responsive": True,
            },
            "result": result,
        }

    if name == "bizhawk_launch":
        rom_path = args.get("rom_path")
        if rom_path:
            rom_path = os.path.abspath(rom_path)
            if not os.path.isfile(rom_path):
                raise FileNotFoundError(f"ROM file not found: {rom_path}")
        ping_result = await bridge.ensure_responsive(rom_path)
        return {
            "status": "ready",
            "transport": {
                "tcp_connected": True,
                "lua_responsive": True,
            },
            "emu": bridge._emu_path,
            "rom": rom_path,
            "ping": ping_result,
        }

    if name == "bizhawk_info":
        return await bridge.send_command("get_info")

    if name == "bizhawk_memory_domains":
        return await bridge.send_command("list_memory_domains")

    if name == "bizhawk_read":
        address = args["address"]
        size = args.get("size", 4)
        domain = args.get("domain")
        result = await bridge.send_command("read_range", {
            "address": address,
            "length": size,
            "domain": domain,
        })
        return {"address": address, "size": size, "domain": domain, "bytes": result}

    if name == "bizhawk_write":
        address = args["address"]
        data = args["data"]
        domain = args.get("domain")
        result = await bridge.send_command("write_range", {
            "address": address,
            "bytes": data,
            "domain": domain,
        })
        return {"address": address, "written": result["written"], "domain": domain}

    if name == "bizhawk_buttons":
        buttons = args["buttons"]
        player = args.get("player", 1)
        await bridge.send_command("press_buttons", {
            "buttons": buttons,
            "player": player,
        })
        return {"buttons": buttons, "player": player}

    if name == "bizhawk_input_state":
        player = args.get("player", 1)
        result = await bridge.send_command("get_input_state", {"player": player})
        return result

    if name == "bizhawk_frame":
        count = args.get("count", 1)
        framecount = await bridge.send_command("frame_advance", {"count": count})
        return {"frames_advanced": count, "framecount": framecount}

    if name == "bizhawk_tap_buttons":
        buttons = args["buttons"]
        player = args.get("player", 1)
        frames = args.get("frames", 1)
        result = await bridge.send_command("tap_buttons", {
            "buttons": buttons,
            "player": player,
            "frames": frames,
        })
        return result

    if name == "bizhawk_pause":
        await bridge.send_command("pause")
        return {"status": "paused"}

    if name == "bizhawk_unpause":
        await bridge.send_command("unpause")
        return {"status": "unpaused"}

    if name == "bizhawk_reset":
        await bridge.send_command("reset")
        return {"status": "reset"}

    if name == "bizhawk_screenshot":
        path = args["path"]
        result = await bridge.send_command("screenshot", {"path": path})
        return {"path": result["path"]}

    if name == "bizhawk_save_state":
        path = args["path"]
        result = await bridge.send_command("save_state", {"path": path})
        return {"path": result["path"]}

    if name == "bizhawk_load_state":
        path = args["path"]
        result = await bridge.send_command("load_state", {"path": path})
        return {"path": result["path"]}

    raise ValueError(f"Unknown tool: {name}")


async def _boot_jvm(session):
    """Boot JVM in background thread so MCP initialize responds instantly."""
    logger.info("Booting JVM in background (this may take 30-60 seconds)...")
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, session.start)
    logger.info("JVM ready")


def _format_result(obj) -> str:
    import json
    return json.dumps(obj, indent=2, default=str)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )

    parser = argparse.ArgumentParser(description="Ghidra BizHawk MCP Server")
    parser.add_argument(
        "--ghidra-dir",
        default=os.environ.get("GHIDRA_INSTALL_DIR"),
        help="Path to Ghidra installation directory",
    )
    args = parser.parse_args()

    logger.info("Starting Ghidra BizHawk MCP server...")
    asyncio.run(serve(ghidra_dir=args.ghidra_dir))


if __name__ == "__main__":
    main()
