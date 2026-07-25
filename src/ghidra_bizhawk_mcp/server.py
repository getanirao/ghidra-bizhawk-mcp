import argparse
import asyncio
import logging
import os
import sys

from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

from .ghidra_bridge import GhidraSession
from .tools.bizhawk_bridge import get_bridge

logger = logging.getLogger(__name__)

session = GhidraSession(ghidra_dir=os.environ.get("GHIDRA_INSTALL_DIR"))


def _sid(arguments: dict) -> str | None:
    return arguments.get("session_id")


TOOLS = [
    # ── Session management ──────────────────────────────────────────
    types.Tool(
        name="analyze_binary",
        description="Import and analyze a binary into a named session (creates or replaces). Returns session_id.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the binary file"},
                "session_id": {"type": "string", "description": "Optional session ID (auto-generated if omitted)"},
            },
            "required": ["binary_path"],
        },
    ),
    types.Tool(
        name="list_sessions",
        description="List all active session workspaces",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="close_session",
        description="Close and remove a session workspace",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID to close"},
            },
            "required": ["session_id"],
        },
    ),
    # ── Read / analysis ─────────────────────────────────────────────
    types.Tool(
        name="decompile_function",
        description="Decompile a function by name or address",
        inputSchema={
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "Function name or hex address"},
                "session_id": {"type": "string", "description": "Session ID (defaults to active)"},
            },
            "required": ["function_name"],
        },
    ),
    types.Tool(
        name="decompile_function_paginated",
        description="Decompile with line range, token budget, and optional summarization. Prevents context-window exhaustion on large functions.",
        inputSchema={
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "Function name or address"},
                "line_start": {"type": "integer", "description": "1-indexed start line"},
                "line_end": {"type": "integer", "description": "1-indexed end line (exclusive)"},
                "max_tokens": {"type": "integer", "description": "Truncate output to ~N tokens"},
                "summarize": {"type": "boolean", "description": "Strip boilerplate locals and blank lines"},
                "session_id": {"type": "string"},
            },
            "required": ["function_name"],
        },
    ),
    types.Tool(
        name="get_data_types",
        description="List all data types in the loaded program",
        inputSchema={
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
        },
    ),
    types.Tool(
        name="get_cross_references",
        description="Get cross-references to and from an address",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address (e.g. 0x401000)"},
                "max_results": {"type": "integer", "default": 100},
                "session_id": {"type": "string"},
            },
            "required": ["address"],
        },
    ),
    types.Tool(
        name="get_call_graph",
        description="Get call graph for a function — who it calls and who calls it",
        inputSchema={
            "type": "object",
            "properties": {
                "function_name": {"type": "string"},
                "max_depth": {"type": "integer", "default": 3},
                "session_id": {"type": "string"},
            },
            "required": ["function_name"],
        },
    ),
    types.Tool(
        name="analyze_and_decompile_entrypoints",
        description="Composite: bulk decompile all entry points in one call",
        inputSchema={
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
        },
    ),
    # ── Write / mutation ────────────────────────────────────────────
    types.Tool(
        name="rename_symbol",
        description="Rename a function or label at a given address",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address of the symbol"},
                "new_name": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "required": ["address", "new_name"],
        },
    ),
    types.Tool(
        name="add_comment",
        description="Attach a comment to a code unit",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "string"},
                "text": {"type": "string"},
                "comment_type": {"type": "string", "default": "plate", "description": "plate, pre, post, eol, repeatable"},
                "session_id": {"type": "string"},
            },
            "required": ["address", "text"],
        },
    ),
    types.Tool(
        name="create_struct",
        description="Create a custom structured data type from a JSON member layout",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Struct name"},
                "members": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "offset": {"type": "integer", "description": "Byte offset (optional, appended if omitted)"},
                            "name": {"type": "string", "description": "Field name"},
                            "type": {"type": "string", "description": "Type string (int, char, MyStruct*, etc.)"},
                        },
                        "required": ["name", "type"],
                    },
                    "description": "Array of member definitions",
                },
                "session_id": {"type": "string"},
            },
            "required": ["name", "members"],
        },
    ),
    types.Tool(
        name="retype_variable",
        description="Change a local variable or parameter's type in a function",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address inside the function"},
                "variable_name": {"type": "string"},
                "new_type": {"type": "string", "description": "New type (e.g. MyStruct*, int)"},
                "session_id": {"type": "string"},
            },
            "required": ["address", "variable_name", "new_type"],
        },
    ),
    # ── Assembly grain ──────────────────────────────────────────────
    types.Tool(
        name="disassemble_range",
        description="Disassemble raw instructions at an address (mnemonic, operands, bytes)",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Start address"},
                "instruction_count": {"type": "integer", "default": 10},
                "session_id": {"type": "string"},
            },
            "required": ["address"],
        },
    ),
    # ── Byte search / listing ───────────────────────────────────────
    types.Tool(
        name="search_bytes",
        description="Search for a hex byte pattern across the entire binary (e.g. '09 08 00 01' or 'F86D0003'). Returns matching addresses with context bytes.",
        inputSchema={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Hex pattern (e.g. '09 08 00 01' or 'F86D0003')"},
                "max_results": {"type": "integer", "default": 50},
                "session_id": {"type": "string"},
            },
            "required": ["pattern"],
        },
    ),
    types.Tool(
        name="get_listing_range",
        description="Return raw hex + ASCII dump for a byte range, equivalent to Ghidra's Listing view.",
        inputSchema={
            "type": "object",
            "properties": {
                "start_address": {"type": "string", "description": "Start address"},
                "byte_count": {"type": "integer", "default": 64, "description": "Total bytes to dump"},
                "columns": {"type": "integer", "default": 16, "description": "Bytes per row"},
                "session_id": {"type": "string"},
            },
            "required": ["start_address"],
        },
    ),
    # ── Binary diffing ──────────────────────────────────────────────
    types.Tool(
        name="diff_binaries",
        description="Compare two loaded sessions by function names and body sizes",
        inputSchema={
            "type": "object",
            "properties": {
                "session_a": {"type": "string", "description": "First session ID"},
                "session_b": {"type": "string", "description": "Second session ID"},
            },
            "required": ["session_a", "session_b"],
        },
    ),
    # ── Workspace reporting ─────────────────────────────────────────
    types.Tool(
        name="generate_workspace_report",
        description="Produce a Markdown summary of the active workspace — functions, entry points, custom symbols, recovered structures, renamed functions, and comment count. Replaces a GUI CodeBrowser window.",
        inputSchema={
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
        },
    ),
    # ── P-code micro-emulation ──────────────────────────────────────
    types.Tool(
        name="emulate_slice",
        description="Headlessly execute a slice of instructions using Ghidra's P-code emulator. Seed registers and track value propagation across steps — no debugger or network needed.",
        inputSchema={
            "type": "object",
            "properties": {
                "start_address": {"type": "string", "description": "Starting address (e.g. 0x1000)"},
                "instruction_count": {"type": "integer", "default": 10, "description": "Number of instructions to step"},
                "initial_registers": {
                    "type": "object",
                    "description": "Register seed values as JSON object, e.g. {\"r0\": 5, \"r1\": 1095216660}",
                    "additionalProperties": {"type": "integer"},
                },
                "track_registers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Subset of registers to log (default: all seeded + PC)",
                },
                "session_id": {"type": "string"},
            },
            "required": ["start_address"],
        },
    ),
    types.Tool(
        name="emulate_slice_with_taint",
        description="Execute an instruction slice with automatic taint tracking. Specify a taint register; the tool reports when its value is modified or propagated to other registers.",
        inputSchema={
            "type": "object",
            "properties": {
                "start_address": {"type": "string", "description": "Starting address"},
                "instruction_count": {"type": "integer", "default": 10},
                "initial_registers": {
                    "type": "object",
                    "description": "Register seeds, e.g. {\"r0\": 5, \"r1\": 0x41424344}",
                    "additionalProperties": {"type": "integer"},
                },
                "taint_register": {"type": "string", "default": "r0", "description": "Register to track for data lineage"},
                "session_id": {"type": "string"},
            },
            "required": ["start_address"],
        },
    ),
    types.Tool(
        name="emulate_slice_with_breakpoints",
        description="Execute instructions until a break condition is met or the count expires. Conditions: R0==0, R1>0xFF, R2!=R3, PC==0x1234. Stops before or after the matching instruction.",
        inputSchema={
            "type": "object",
            "properties": {
                "start_address": {"type": "string", "description": "Starting address"},
                "instruction_count": {"type": "integer", "default": 50, "description": "Max steps before timeout"},
                "initial_registers": {
                    "type": "object",
                    "additionalProperties": {"type": "integer"},
                    "description": "Register seeds",
                },
                "break_condition": {"type": "string", "description": "Condition string, e.g. R0==0, R1>0xFF, PC==0x1234"},
                "session_id": {"type": "string"},
            },
            "required": ["start_address"],
        },
    ),
    # ── Function fingerprinting / signature transfer ────────────────
    types.Tool(
        name="calculate_function_fingerprint",
        description="Generate a behavior-based structural hash for a function. Survives compiler shuffling across binary versions.",
        inputSchema={
            "type": "object",
            "properties": {
                "func_name": {"type": "string", "description": "Function name or address"},
                "session_id": {"type": "string"},
            },
            "required": ["func_name"],
        },
    ),
    types.Tool(
        name="export_signature_map",
        description="Export a complete signature map of every function in the current binary. Output can be saved and later applied to a new version.",
        inputSchema={
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
        },
    ),
    types.Tool(
        name="apply_signature_map",
        description="Scan the current binary, match functions by structural fingerprint against a previously exported map, and rename matches automatically.",
        inputSchema={
            "type": "object",
            "properties": {
                "signature_json_map": {
                    "type": "object",
                    "description": "Signature map from a previous export_signature_map call",
                },
                "session_id": {"type": "string"},
            },
            "required": ["signature_json_map"],
        },
    ),
    # ── Persistent signature stash (server-side cache) ──────────────
    types.Tool(
        name="save_active_binary_signature",
        description="Fingerprint all functions and stash the signature map server-side under a lineage_group_id (e.g. 'my_firmware_v1'). No JSON management needed.",
        inputSchema={
            "type": "object",
            "properties": {
                "lineage_group_id": {"type": "string", "description": "Arbitrary group name for this binary family"},
                "session_id": {"type": "string"},
            },
            "required": ["lineage_group_id"],
        },
    ),
    types.Tool(
        name="auto_restore_signatures_from_stash",
        description="Load a previously stashed signature map by lineage_group_id and auto-rename every matching function in the current session.",
        inputSchema={
            "type": "object",
            "properties": {
                "lineage_group_id": {"type": "string", "description": "Group name used during save"},
                "session_id": {"type": "string"},
            },
            "required": ["lineage_group_id"],
        },
    ),
    types.Tool(
        name="auto_stash_current_binary",
        description="Auto-stash: hash the loaded binary's first 4 KB, save a signature map under that hash. Zero user input needed.",
        inputSchema={
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
        },
    ),
    types.Tool(
        name="auto_restore_current_binary",
        description="Auto-restore: hash the loaded binary, look up a previously stashed map by hash, and rename matches automatically.",
        inputSchema={
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
        },
    ),
    types.Tool(
        name="list_stashed_signature_groups",
        description="List all stashed signature groups currently in the local server cache (~/.ghidra_bizhawk_mcp/signatures/).",
        inputSchema={"type": "object", "properties": {}},
    ),
    # ── Retro platform triage ───────────────────────────────────────────
    types.Tool(
        name="triage_and_load_retro_rom",
        description="Examines raw file magic header signatures to detect retro console architectures (NES, SNES, GBA, NDS, Switch, PSX, Genesis, SMS, Dreamcast), headlessly maps correct language loaders, hooks multi-session project bindings, and applies automated signature caching overlays.",
        inputSchema={
            "type": "object",
            "properties": {
                "rom_path": {"type": "string", "description": "Absolute system path to the targeted emulator ROM image or raw memory partition block dump."},
                "session_id": {"type": "string", "description": "Optional session tracking token for parallel multi-binary session context."},
            },
            "required": ["rom_path"],
        },
    ),
    # ── BizHawk live emulation ──────────────────────────────────────────
    types.Tool(
        name="bizhawk_connect",
        description="Check connectivity to BizHawk (ping bridge.lua running inside EmuHawk).",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="bizhawk_get_info",
        description="Get ROM name, ROM hash, framecount, memory domains, and capabilities from BizHawk.",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="bizhawk_list_memory_domains",
        description="List available memory domains for the loaded core.",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="bizhawk_read_memory",
        description="Read bytes from BizHawk emulated memory. Returns an array of byte values.",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "integer", "description": "Starting memory address (decimal or hex)"},
                "size": {"type": "integer", "default": 4, "description": "Number of bytes to read (max 4096)"},
                "domain": {"type": "string", "description": "Optional memory domain (e.g. WRAM, RAM, EWRAM, VRAM). Use bizhawk_list_memory_domains to discover names."},
            },
            "required": ["address"],
        },
    ),
    types.Tool(
        name="bizhawk_write_memory",
        description="Write bytes to BizHawk emulated memory.",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "integer", "description": "Starting memory address"},
                "data": {"type": "array", "items": {"type": "integer"}, "description": "Array of byte values to write (max 4096)"},
                "domain": {"type": "string", "description": "Optional memory domain"},
            },
            "required": ["address", "data"],
        },
    ),
    types.Tool(
        name="bizhawk_press_buttons",
        description="Set joypad button state for a player. Buttons is an object like {A: true, B: true, Up: true, Start: true, Select: true}. Runs once; hold buttons across frames by repeating.",
        inputSchema={
            "type": "object",
            "properties": {
                "buttons": {
                    "type": "object",
                    "description": "Button states as {ButtonName: true/false, ...}",
                    "additionalProperties": {"type": "boolean"},
                },
                "player": {"type": "integer", "default": 1, "description": "Player number (1-based)"},
            },
            "required": ["buttons"],
        },
    ),
    types.Tool(
        name="bizhawk_frame_advance",
        description="Advance the emulator by N frames. Use to step through execution or apply button inputs.",
        inputSchema={
            "type": "object",
            "properties": {
                "count": {"type": "integer", "default": 1, "description": "Number of frames to advance"},
            },
        },
    ),
    types.Tool(
        name="bizhawk_pause",
        description="Pause emulation.",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="bizhawk_unpause",
        description="Unpause emulation.",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="bizhawk_reset",
        description="Reset the loaded core (reboot the emulated system).",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="bizhawk_screenshot",
        description="Save a PNG screenshot of the current display to a file path.",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute file path to save the PNG screenshot (e.g. C:/temp/shot.png)"},
            },
            "required": ["path"],
        },
    ),
    types.Tool(
        name="bizhawk_save_state",
        description="Save emulator state to a file.",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path for the savestate (e.g. C:/temp/state.bin)"},
            },
            "required": ["path"],
        },
    ),
    types.Tool(
        name="bizhawk_load_state",
        description="Load emulator state from a file.",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path of the savestate to load"},
            },
            "required": ["path"],
        },
    ),
    types.Tool(
        name="bizhawk_launch",
        description="Launch BizHawk emulator and connect the bridge. Optionally specify a ROM path.",
        inputSchema={
            "type": "object",
            "properties": {
                "rom_path": {"type": "string", "description": "Optional path to a ROM file to load"},
            },
        },
    ),
]


async def serve():
    await get_bridge().start()
    # Start JVM boot in background so MCP initialize doesn't timeout
    asyncio.create_task(_boot_jvm())
    server = Server("ghidra-bizhawk-mcp")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return TOOLS

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
        try:
            result = await _dispatch(name, arguments)
            return [types.TextContent(type="text", text=_format_result(result))]
        except Exception as e:
            logger.exception("Tool call failed")
            return [types.TextContent(type="text", text=f"Error: {e}")]

    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="ghidra-bizhawk-mcp",
                    server_version="0.1.0",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        await get_bridge().stop()


async def _dispatch(name: str, args: dict):
    sid = args.get("session_id")

    # Session management
    if name == "analyze_binary":
        return session.analyze_binary(
            binary_path=args["binary_path"],
            session_id=args.get("session_id"),
        )
    if name == "list_sessions":
        return session.list_sessions()
    if name == "close_session":
        session.close_session(args["session_id"])
        return {"status": "closed", "session_id": args["session_id"]}

    # Read / analysis
    if name == "decompile_function":
        return session.decompile_function(args["function_name"], session_id=sid)
    if name == "decompile_function_paginated":
        return session.decompile_function_paginated(
            function_name=args["function_name"],
            line_start=args.get("line_start"),
            line_end=args.get("line_end"),
            max_tokens=args.get("max_tokens"),
            summarize=args.get("summarize", False),
            session_id=sid,
        )
    if name == "get_data_types":
        return session.get_data_types(session_id=sid)
    if name == "get_cross_references":
        return session.get_cross_references(
            address=args["address"],
            max_results=args.get("max_results", 100),
            session_id=sid,
        )
    if name == "get_call_graph":
        return session.get_call_graph(
            function_name=args["function_name"],
            max_depth=args.get("max_depth", 3),
            session_id=sid,
        )
    if name == "analyze_and_decompile_entrypoints":
        return session.analyze_and_decompile_entrypoints(session_id=sid)

    # Write / mutation
    if name == "rename_symbol":
        return session.rename_symbol(args["address"], args["new_name"], session_id=sid)
    if name == "add_comment":
        return session.add_comment(
            address=args["address"],
            text=args["text"],
            comment_type=args.get("comment_type", "plate"),
            session_id=sid,
        )
    if name == "create_struct":
        return session.create_struct(args["name"], args["members"], session_id=sid)
    if name == "retype_variable":
        return session.retype_variable(
            address=args["address"],
            variable_name=args["variable_name"],
            new_type=args["new_type"],
            session_id=sid,
        )

    # Assembly
    if name == "disassemble_range":
        return session.disassemble_range(
            address=args["address"],
            instruction_count=args.get("instruction_count", 10),
            session_id=sid,
        )

    # Byte search / listing
    if name == "search_bytes":
        return session.search_bytes(
            pattern=args["pattern"],
            max_results=args.get("max_results", 50),
            session_id=sid,
        )
    if name == "get_listing_range":
        return session.get_listing_range(
            start_address=args["start_address"],
            byte_count=args.get("byte_count", 64),
            columns=args.get("columns", 16),
            session_id=sid,
        )

    # Diffing
    if name == "diff_binaries":
        return session.diff_binaries(
            session_a=args["session_a"],
            session_b=args["session_b"],
        )

    # Reporting
    if name == "generate_workspace_report":
        return session.generate_workspace_report(session_id=sid)

    # Emulation
    if name == "emulate_slice":
        return session.emulate_slice(
            start_address=args["start_address"],
            instruction_count=args.get("instruction_count", 10),
            initial_registers=args.get("initial_registers"),
            track_registers=args.get("track_registers"),
            session_id=sid,
        )
    if name == "emulate_slice_with_taint":
        return session.emulate_slice_with_taint(
            start_address=args["start_address"],
            instruction_count=args.get("instruction_count", 10),
            initial_registers=args.get("initial_registers"),
            taint_register=args.get("taint_register", "r0"),
            session_id=sid,
        )
    if name == "emulate_slice_with_breakpoints":
        return session.emulate_slice_with_breakpoints(
            start_address=args["start_address"],
            instruction_count=args.get("instruction_count", 50),
            initial_registers=args.get("initial_registers"),
            break_condition=args.get("break_condition", ""),
            session_id=sid,
        )

    # Function fingerprinting / signature transfer
    if name == "calculate_function_fingerprint":
        return session.calculate_function_fingerprint(args["func_name"], session_id=sid)
    if name == "export_signature_map":
        return session.export_signature_map(session_id=sid)
    if name == "apply_signature_map":
        return session.apply_signature_map(args["signature_json_map"], session_id=sid)

    # Persistent signature stash
    if name == "save_active_binary_signature":
        return session.save_active_binary_signature(args["lineage_group_id"], session_id=sid)
    if name == "auto_restore_signatures_from_stash":
        return session.auto_restore_signatures_from_stash(args["lineage_group_id"], session_id=sid)
    if name == "auto_stash_current_binary":
        return session.auto_stash_current_binary(session_id=sid)
    if name == "auto_restore_current_binary":
        return session.auto_restore_current_binary(session_id=sid)
    if name == "list_stashed_signature_groups":
        return session.list_stashed_signature_groups()

    # Retro platform triage
    if name == "triage_and_load_retro_rom":
        return session.triage_and_load_retro_rom(
            rom_path=args["rom_path"],
            session_id=args.get("session_id"),
        )

    # ── BizHawk live emulation ──────────────────────────────────────────
    bridge = get_bridge()

    if name == "bizhawk_connect":
        result = await bridge.send_command("ping")
        return {"status": "connected", "result": result}

    if name == "bizhawk_launch":
        rom_path = args.get("rom_path")
        await bridge.ensure_connected(rom_path)
        return {"status": "connected", "emu": bridge._emu_path, "rom": rom_path}

    if name == "bizhawk_get_info":
        return await bridge.send_command("get_info")

    if name == "bizhawk_list_memory_domains":
        return await bridge.send_command("list_memory_domains")

    if name == "bizhawk_read_memory":
        address = args["address"]
        size = args.get("size", 4)
        domain = args.get("domain")
        result = await bridge.send_command("read_range", {
            "address": address,
            "length": size,
            "domain": domain,
        })
        return {"address": address, "size": size, "domain": domain, "bytes": result}

    if name == "bizhawk_write_memory":
        address = args["address"]
        data = args["data"]
        domain = args.get("domain")
        result = await bridge.send_command("write_range", {
            "address": address,
            "bytes": data,
            "domain": domain,
        })
        return {"address": address, "written": result["written"], "domain": domain}

    if name == "bizhawk_press_buttons":
        buttons = args["buttons"]
        player = args.get("player", 1)
        await bridge.send_command("press_buttons", {
            "buttons": buttons,
            "player": player,
        })
        return {"buttons": buttons, "player": player}

    if name == "bizhawk_frame_advance":
        count = args.get("count", 1)
        framecount = await bridge.send_command("frame_advance", {"count": count})
        return {"frames_advanced": count, "framecount": framecount}

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


async def _boot_jvm():
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

    if args.ghidra_dir:
        session._ghidra_dir = args.ghidra_dir

    logger.info("Starting Ghidra BizHawk MCP server...")
    asyncio.run(serve())


if __name__ == "__main__":
    main()
