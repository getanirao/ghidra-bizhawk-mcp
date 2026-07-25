import os
import sys
import time
import logging
import uuid
import re
import shutil
import tempfile
import threading
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import jpype

logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", message="open_program.*deprecated")

try:
    import pyghidra as _pyghidra
except ImportError:
    _pyghidra = None

# Ghidra Java classes — importable only after pyhidra.start() initializes the JVM
FunctionManager = CodeUnit = ReferenceManager = SourceType = None
StructureDataType = CategoryPath = ByteDataType = DecompInterface = ConsoleTaskMonitor = None
_HAS_GHIDRA = False
_HAS_PYGHIDRA = _pyghidra is not None


_SIMPLE_TYPES = {
    "void": "void",
    "bool": "bool",
    "char": "char",
    "byte": "byte",
    "short": "short",
    "int": "int",
    "long": "long",
    "longlong": "longlong",
    "float": "float",
    "double": "double",
    "uint": "uint",
    "ushort": "ushort",
    "uint8": "uint8",
    "uint16": "uint16",
    "uint32": "uint32",
    "uint64": "uint64",
    "int8": "int8",
    "int16": "int16",
    "int32": "int32",
    "int64": "int64",
}


@dataclass
class SessionInfo:
    session_id: str
    launcher: object = None
    program: object = None
    flat_api: object = None
    binary_path: str = ""
    project_name: str = ""
    project_location: str = ""
    loaded_at: float = 0.0


class GhidraSession:
    def __init__(self, ghidra_dir: Optional[str] = None):
        self._ghidra_dir = ghidra_dir
        self._sessions: dict[str, SessionInfo] = {}
        self._active_session_id: Optional[str] = None
        self._started = False
        self._start_lock = threading.Lock()

    def start(self):
        if self._started:
            return
        with self._start_lock:
            if self._started:
                return
            if not _HAS_PYGHIDRA:
                raise RuntimeError(
                    "pyghidra not found. Install with: pip install ghidra-bizhawk-mcp[ghidra]"
                )
            kwargs = {}
            if self._ghidra_dir:
                kwargs["install_dir"] = self._ghidra_dir
            # Suppress Java stdout noise that would break MCP JSON-RPC
            old_stdout = sys.stdout
            sys.stdout = sys.stderr
            try:
                _pyghidra.start(**kwargs)
            finally:
                sys.stdout = old_stdout
            logger.info("pyghidra started — importing Ghidra classes")
            global FunctionManager, CodeUnit, ReferenceManager, SourceType
            global StructureDataType, CategoryPath, ByteDataType, DecompInterface, ConsoleTaskMonitor
            global _HAS_GHIDRA
            from ghidra.program.model.listing import FunctionManager, CodeUnit
            from ghidra.program.model.symbol import ReferenceManager, SourceType
            from ghidra.program.model.data import StructureDataType, CategoryPath, ByteDataType
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor
            _HAS_GHIDRA = True
            self._started = True
            logger.info("Ghidra classes imported")

    def _make_session_id(self) -> str:
        return uuid.uuid4().hex[:12]

    def _require_session(self, session_id: Optional[str] = None) -> SessionInfo:
        self.start()
        sid = session_id or self._active_session_id
        if sid is None or sid not in self._sessions:
            raise RuntimeError(
                f"No active session. Call analyze_binary first or provide a valid session_id."
            )
        info = self._sessions[sid]
        if info.program is None:
            raise RuntimeError(f"Session {sid} has no loaded program.")
        return info

    def list_sessions(self) -> list[dict]:
        return [
            {
                "session_id": sid,
                "binary_path": info.binary_path,
                "project_name": info.project_name,
                "loaded_at": info.loaded_at,
            }
            for sid, info in self._sessions.items()
            if info.binary_path
        ]

    def close_session(self, session_id: str):
        info = self._sessions.get(session_id)
        if info is None:
            raise ValueError(f"Session {session_id} not found")
        if info.launcher is not None:
            try:
                info.launcher.__exit__(None, None, None)
            except Exception:
                pass
            info.launcher = None
        del self._sessions[session_id]
        if self._active_session_id == session_id:
            self._active_session_id = (
                next(iter(self._sessions)) if self._sessions else None
            )
        if info.project_location and os.path.isdir(info.project_location):
            try:
                shutil.rmtree(info.project_location)
            except Exception:
                pass

    def analyze_binary(
        self,
        binary_path: str,
        session_id: Optional[str] = None,
    ) -> dict:
        binary_path = Path(binary_path).resolve()
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        sid = session_id or self._make_session_id()
        if sid in self._sessions:
            self.close_session(sid)

        project_dir = tempfile.mkdtemp(prefix="ghidra_bizhawk_")
        project_name = f"_{binary_path.stem}_mcp_{int(time.time())}"

        old_stdout = sys.stdout
        sys.stdout = sys.stderr
        try:
            cm = _pyghidra.open_program(
                binary_path=str(binary_path),
                project_location=project_dir,
                project_name=project_name,
                analyze=False,
            )
            flat_api = cm.__enter__()
        finally:
            sys.stdout = old_stdout
        program = flat_api.getCurrentProgram()

        info = SessionInfo(
            session_id=sid,
            launcher=cm,
            program=program,
            flat_api=flat_api,
            binary_path=str(binary_path),
            project_name=project_name,
            project_location=project_dir,
            loaded_at=time.time(),
        )
        self._sessions[sid] = info
        self._active_session_id = sid

        listing = info.program.getListing()

        return {
            "session_id": sid,
            "binary": str(binary_path),
            "project": project_name,
            "language": info.program.getLanguageID().getIdAsString(),
            "compiler": info.program.getCompilerSpec().getCompilerSpecID().getIdAsString(),
            "image_base": str(info.program.getImageBase()),
            "min_address": str(info.program.getMinAddress()),
            "max_address": str(info.program.getMaxAddress()),
            "num_functions": len(list(listing.getFunctions(True))),
        }

    # ── Read / analysis tools ──────────────────────────────────────────

    def decompile_function(
        self, function_name: str, session_id: Optional[str] = None
    ) -> dict:
        info = self._require_session(session_id)
        program = info.program
        func = _find_function(program, function_name)
        if func is None:
            raise ValueError(f"Function '{function_name}' not found")

        result = _do_decompile(program, func)
        return {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature": func.getSignature(),
            "decompiled": result,
        }

    def decompile_function_paginated(
        self,
        function_name: str,
        line_start: Optional[int] = None,
        line_end: Optional[int] = None,
        max_tokens: Optional[int] = None,
        summarize: bool = False,
        session_id: Optional[str] = None,
    ) -> dict:
        info = self._require_session(session_id)
        program = info.program
        func = _find_function(program, function_name)
        if func is None:
            raise ValueError(f"Function '{function_name}' not found")

        c_code = _do_decompile(program, func)
        if summarize:
            c_code = _summarize_c_code(c_code)

        lines = c_code.split("\n")
        total_lines = len(lines)

        if line_start is not None:
            line_start = max(0, line_start - 1)
        else:
            line_start = 0
        if line_end is not None:
            lines = lines[line_start:line_end]
        else:
            lines = lines[line_start:]

        result = "\n".join(lines)

        if max_tokens is not None:
            estimated = len(result) // 4
            if estimated > max_tokens:
                ratio = max_tokens / estimated
                keep_lines = max(1, int(len(lines) * ratio))
                lines = lines[:keep_lines]
                result = "\n".join(lines)
                result += f"\n/*... truncated to ~{max_tokens} tokens ({len(lines)} of {total_lines} lines) ...*/"

        return {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature": func.getSignature(),
            "total_lines": total_lines,
            "line_start": line_start,
            "line_end": line_end if line_end else total_lines,
            "summarized": summarize,
            "decompiled": result,
        }

    def get_data_types(self, session_id: Optional[str] = None) -> list[dict]:
        info = self._require_session(session_id)
        program = info.program
        dtm = program.getDataTypeManager()
        types = []

        for dt in dtm.getAllDataTypes():
            try:
                types.append({
                    "name": dt.getName(),
                    "path": dt.getPathName(),
                    "category": dt.getCategory().getCategoryPath().getPath(),
                    "size": dt.getLength(),
                    "type": dt.getClass().getSimpleName(),
                })
            except Exception:
                pass

        return types

    def get_cross_references(
        self, address: str, max_results: int = 100, session_id: Optional[str] = None
    ) -> dict:
        info = self._require_session(session_id)
        program = info.program
        addr = program.getAddressFactory().getAddress(address)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")

        ref_mgr: ReferenceManager = program.getReferenceManager()
        refs_to = ref_mgr.getReferencesTo(addr)
        refs_from = ref_mgr.getReferencesFrom(addr)

        to_list = []
        from_list = []
        for r in refs_to:
            to_list.append({
                "from_address": str(r.getFromAddress()),
                "ref_type": str(r.getReferenceType().getName()),
            })
            if len(to_list) >= max_results:
                break

        for r in refs_from:
            from_list.append({
                "to_address": str(r.getToAddress()),
                "ref_type": str(r.getReferenceType().getName()),
            })
            if len(from_list) >= max_results:
                break

        return {
            "address": address,
            "references_to": to_list,
            "references_from": from_list,
        }

    def get_call_graph(
        self, function_name: str, max_depth: int = 3, session_id: Optional[str] = None
    ) -> dict:
        info = self._require_session(session_id)
        func = _find_function(program, function_name)
        if func is None:
            raise ValueError(f"Function '{function_name}' not found")

        calls_from = _resolve_calls(func, info.program, max_depth)

        calls_to = {}
        fm: FunctionManager = info.program.getFunctionManager()
        for caller in fm.getFunctions(True):
            if caller == func:
                continue
            called_set = _resolve_calls(caller, info.program, 1)
            if func.getName() in called_set or str(func.getEntryPoint()) in called_set:
                calls_to[caller.getName()] = str(caller.getEntryPoint())

        return {
            "function": function_name,
            "address": str(func.getEntryPoint()),
            "calls": calls_from,
            "called_by": calls_to,
        }

    def analyze_and_decompile_entrypoints(
        self, session_id: Optional[str] = None
    ) -> list[dict]:
        info = self._require_session(session_id)
        program = info.program
        fm = program.getFunctionManager()

        targets = set()
        entry = program.getExecutableEntrySet()
        for entry_addr in entry:
            targets.add(entry_addr)

        for func in fm.getFunctions(True):
            name = func.getName()
            if name in ("entry", "_start", "main", "WinMain", "DllMain", "DriverEntry"):
                targets.add(func.getEntryPoint())

        exports = program.getSymbolTable().getSymbolIterator()
        for sym in exports:
            if sym.getSymbolType().toString() == "Function":
                targets.add(sym.getAddress())

        decompiler = DecompInterface()
        decompiler.openProgram(program)
        monitor = ConsoleTaskMonitor()
        results = []

        seen = set()
        for addr in targets:
            key = str(addr)
            if key in seen:
                continue
            seen.add(key)
            func = fm.getFunctionAt(addr)
            if func is None:
                continue
            result = decompiler.decompileFunction(func, 0, monitor)
            results.append({
                "name": func.getName(),
                "address": key,
                "signature": func.getSignature(),
                "decompiled": result.getDecompiledFunction().getC()
                if (result and result.decompileCompleted())
                else None,
            })

        return results

    # ── Write / mutation tools ─────────────────────────────────────────

    def rename_symbol(
        self, address: str, new_name: str, session_id: Optional[str] = None
    ) -> dict:
        info = self._require_session(session_id)
        program = info.program
        addr = program.getAddressFactory().getAddress(address)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")

        fm = program.getFunctionManager()
        func = fm.getFunctionAt(addr)
        if func is not None:
            old_name = func.getName()
            func.setName(new_name, SourceType.USER_DEFINED)
            return {
                "address": address,
                "old_name": old_name,
                "new_name": new_name,
                "type": "function",
            }

        symbol_table = program.getSymbolTable()
        symbols = list(symbol_table.getSymbols(addr))
        if not symbols:
            raise ValueError(f"No symbol found at address {address}")

        sym = symbols[0]
        old_name = sym.getName()
        sym.setName(new_name, SourceType.USER_DEFINED)
        return {
            "address": address,
            "old_name": old_name,
            "new_name": new_name,
            "type": str(sym.getSymbolType()),
        }

    def add_comment(
        self,
        address: str,
        text: str,
        comment_type: str = "plate",
        session_id: Optional[str] = None,
    ) -> dict:
        info = self._require_session(session_id)
        program = info.program
        addr = program.getAddressFactory().getAddress(address)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")

        type_map = {
            "plate": CodeUnit.PLATE_COMMENT,
            "pre": CodeUnit.PRE_COMMENT,
            "post": CodeUnit.POST_COMMENT,
            "eol": CodeUnit.EOL_COMMENT,
            "repeatable": CodeUnit.REPEATABLE_COMMENT,
        }
        ghidra_type = type_map.get(comment_type.lower())
        if ghidra_type is None:
            valid = ", ".join(type_map.keys())
            raise ValueError(f"Invalid comment_type '{comment_type}'. Valid: {valid}")

        listing = program.getListing()
        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            raise ValueError(f"No code unit at address {address}")

        existing = cu.getComment(ghidra_type)
        cu.setComment(ghidra_type, text)

        return {
            "address": address,
            "comment_type": comment_type,
            "length": len(text),
            "replaced_existing": existing is not None,
        }

    def create_struct(
        self, name: str, members: list[dict], session_id: Optional[str] = None
    ) -> dict:
        info = self._require_session(session_id)
        program = info.program
        dtm = program.getDataTypeManager()

        existing = dtm.getDataType(CategoryPath.ROOT, name)
        if existing is not None:
            raise ValueError(f"Data type '{name}' already exists")

        struct = StructureDataType(CategoryPath.ROOT, name, 0)
        created = []

        for m in members:
            offset = m.get("offset")
            field_name = m.get("name", "")
            type_str = m.get("type", "byte")

            ghidra_type = _resolve_type(dtm, type_str)
            if offset is not None:
                struct.insertAtOffset(offset, ghidra_type, ghidra_type.getLength(), field_name, None)
            else:
                struct.add(ghidra_type, ghidra_type.getLength(), field_name, None)
            created.append({
                "offset": offset if offset is not None else struct.getLength(),
                "name": field_name,
                "type": type_str,
            })

        dtm.addDataType(struct, None)
        return {
            "name": name,
            "size": struct.getLength(),
            "members": created,
        }

    def retype_variable(
        self,
        address: str,
        variable_name: str,
        new_type: str,
        session_id: Optional[str] = None,
    ) -> dict:
        info = self._require_session(session_id)
        program = info.program
        addr = program.getAddressFactory().getAddress(address)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")

        fm = program.getFunctionManager()
        func = fm.getFunctionContaining(addr)
        if func is None:
            raise ValueError(f"No function found containing address {address}")

        dtm = program.getDataTypeManager()
        ghidra_type = _resolve_type(dtm, new_type)

        local_vars = func.getLocalVariables()
        for var in local_vars:
            if var.getName() == variable_name:
                old_type = var.getDataType().getName()
                var.setDataType(ghidra_type, SourceType.USER_DEFINED)
                return {
                    "function": func.getName(),
                    "variable": variable_name,
                    "old_type": old_type,
                    "new_type": new_type,
                }

        params = func.getParameters()
        for param in params:
            if param.getName() == variable_name:
                old_type = param.getDataType().getName()
                param.setDataType(ghidra_type, SourceType.USER_DEFINED)
                return {
                    "function": func.getName(),
                    "variable": variable_name,
                    "old_type": old_type,
                    "new_type": new_type,
                }

        raise ValueError(
            f"Variable '{variable_name}' not found in function '{func.getName()}'"
        )

    # ── Assembly-level tools ───────────────────────────────────────────

    def disassemble_range(
        self, address: str, instruction_count: int = 10, session_id: Optional[str] = None
    ) -> list[dict]:
        info = self._require_session(session_id)
        program = info.program
        listing = program.getListing()
        start_addr = program.getAddressFactory().getAddress(address)
        if start_addr is None:
            raise ValueError(f"Invalid address: {address}")

        instructions = []
        addr = start_addr
        count = 0
        while count < instruction_count:
            cu = listing.getCodeUnitAt(addr)
            if cu is None:
                break
            from ghidra.program.model.listing import Instruction
            if not isinstance(cu, Instruction):
                break
            mnemonic = cu.getMnemonicString()
            op_str = cu.getDefaultOperandRepresentation()
            raw_bytes = _get_bytes(program, addr, cu.getLength())
            instructions.append({
                "address": str(addr),
                "mnemonic": mnemonic,
                "operands": op_str,
                "bytes": raw_bytes,
                "length": cu.getLength(),
            })
            count += 1
            addr = addr.add(cu.getLength())

        return instructions

    def search_bytes(
        self, pattern: str, max_results: int = 50, session_id: Optional[str] = None
    ) -> list[dict]:
        info = self._require_session(session_id)
        program = info.program
        memory = program.getMemory()

        hex_str = pattern.replace(" ", "").replace("0x", "").replace("x", "")
        if not hex_str or len(hex_str) % 2 != 0:
            raise ValueError(f"Invalid hex pattern: '{pattern}'")
        raw_bytes = bytes.fromhex(hex_str)

        min_addr = program.getMinAddress()
        max_addr = program.getMaxAddress()

        from ghidra.util.task import ConsoleTaskMonitor as _CM
        results = []
        current = min_addr
        hits = 0
        while hits < max_results:
            found = memory.findBytes(current, max_addr, raw_bytes, None, True, _CM())
            if found is None:
                break
            data_at = program.getListing().getDefinedDataAt(found)
            label = ""
            if data_at is not None and data_at.isString():
                label = data_at.getDefaultValueRepresentation()
            results.append({
                "address": str(found),
                "context": _get_bytes(program, found, len(raw_bytes)),
                "label": label[:80] if label else "",
            })
            hits += 1
            current = found.add(1)
        return results

    def get_listing_range(
        self,
        start_address: str,
        byte_count: int = 64,
        columns: int = 16,
        session_id: Optional[str] = None,
    ) -> list[dict]:
        info = self._require_session(session_id)
        program = info.program
        addr = program.getAddressFactory().getAddress(start_address)
        if addr is None:
            raise ValueError(f"Invalid address: {start_address}")

        rows = []
        offset = 0
        while offset < byte_count:
            row_addr = addr.add(offset)
            chunk_len = min(columns, byte_count - offset)
            raw = _get_bytes(program, row_addr, chunk_len)
            hex_part = raw
            ascii_part = "".join(
                chr(b) if 0x20 <= b <= 0x7E else "."
                for b in _read_raw_bytes(program, row_addr, chunk_len)
            )
            rows.append({
                "address": str(row_addr),
                "hex": hex_part,
                "ascii": ascii_part,
            })
            offset += chunk_len
        return rows

    # ── Binary diffing ─────────────────────────────────────────────────

    def diff_binaries(
        self, session_a: str, session_b: str
    ) -> dict:
        info_a = self._require_session(session_a)
        info_b = self._require_session(session_b)

        fm_a = info_a.program.getFunctionManager()
        fm_b = info_b.program.getFunctionManager()

        def func_map(fm):
            out = {}
            for f in fm.getFunctions(True):
                out[f.getName()] = {
                    "address": str(f.getEntryPoint()),
                    "signature": f.getSignature(),
                    "body_bytes": f.getBody().getNumAddresses(),
                }
            return out

        map_a = func_map(fm_a)
        map_b = func_map(fm_b)

        names_a = set(map_a)
        names_b = set(map_b)

        only_a = {n: map_a[n] for n in names_a - names_b}
        only_b = {n: map_b[n] for n in names_b - names_a}

        common = names_a & names_b
        changed = {}
        for name in common:
            if map_a[name]["body_bytes"] != map_b[name]["body_bytes"]:
                changed[name] = {"a": map_a[name], "b": map_b[name]}

        return {
            "session_a": {"id": session_a, "binary": info_a.binary_path},
            "session_b": {"id": session_b, "binary": info_b.binary_path},
            "only_in_a": only_a,
            "only_in_b": only_b,
            "changed": changed,
            "common_count": len(common),
        }

    # ── Workspace reporting ────────────────────────────────────────────

    def generate_workspace_report(
        self, session_id: Optional[str] = None
    ) -> str:
        from .tools.reporter import build_workspace_report

        info = self._require_session(session_id)
        return build_workspace_report(info.program)

    # ── P-code micro-emulation ─────────────────────────────────────────

    def emulate_slice(
        self,
        start_address: str,
        instruction_count: int = 10,
        initial_registers: Optional[dict[str, int]] = None,
        track_registers: Optional[list[str]] = None,
        session_id: Optional[str] = None,
    ) -> dict:
        from .tools.emulation import emulate_instruction_slice

        info = self._require_session(session_id)
        program = info.program
        addr = program.getAddressFactory().getAddress(start_address)
        if addr is None:
            raise ValueError(f"Invalid address: {start_address}")

        return emulate_instruction_slice(
            program=program,
            start_address=addr,
            instruction_count=instruction_count,
            initial_registers=initial_registers or {},
            track_registers=track_registers,
        )

    def emulate_slice_with_taint(
        self,
        start_address: str,
        instruction_count: int = 10,
        initial_registers: Optional[dict[str, int]] = None,
        taint_register: str = "r0",
        session_id: Optional[str] = None,
    ) -> dict:
        from .tools.emulation import emulate_slice_with_taint as _taint

        info = self._require_session(session_id)
        program = info.program
        addr = program.getAddressFactory().getAddress(start_address)
        if addr is None:
            raise ValueError(f"Invalid address: {start_address}")

        return _taint(
            program=program,
            start_address=addr,
            instruction_count=instruction_count,
            initial_registers=initial_registers or {},
            taint_register=taint_register,
        )

    def emulate_slice_with_breakpoints(
        self,
        start_address: str,
        instruction_count: int = 50,
        initial_registers: Optional[dict[str, int]] = None,
        break_condition: str = "",
        session_id: Optional[str] = None,
    ) -> dict:
        from .tools.emulation import emulate_slice_with_breakpoints as _break

        info = self._require_session(session_id)
        program = info.program
        addr = program.getAddressFactory().getAddress(start_address)
        if addr is None:
            raise ValueError(f"Invalid address: {start_address}")

        return _break(
            program=program,
            start_address=addr,
            instruction_count=instruction_count,
            initial_registers=initial_registers or {},
            break_condition=break_condition,
        )

    # ── Function fingerprinting / signature transfer ──────────────────

    def calculate_function_fingerprint(
        self, func_name: str, session_id: Optional[str] = None
    ) -> dict:
        from .tools.signatures import fingerprint_function

        info = self._require_session(session_id)
        func = _find_function(program, func_name)
        if func is None:
            raise ValueError(f"Function '{func_name}' not found")
        return fingerprint_function(func, info.program)

    def export_signature_map(
        self, session_id: Optional[str] = None
    ) -> dict:
        from .tools.signatures import export_signature_map as _export

        info = self._require_session(session_id)
        return {
            "session_id": session_id or self._active_session_id,
            "binary_path": info.binary_path,
            "function_count": len(list(info.program.getFunctionManager().getFunctions(True))),
            "signature_map": _export(info.program),
        }

    def apply_signature_map(
        self, signature_json_map: dict, session_id: Optional[str] = None
    ) -> dict:
        from .tools.signatures import apply_signature_map as _apply

        info = self._require_session(session_id)
        count = _apply(info.program, signature_json_map)
        return {
            "session_id": session_id or self._active_session_id,
            "matched": count,
        }

    # ── Persistent signature cache (server-side stash) ────────────────

    def save_active_binary_signature(
        self, lineage_group_id: str, session_id: Optional[str] = None
    ) -> dict:
        from .tools.persistent_signatures import save_signature_stash

        info = self._require_session(session_id)
        return save_signature_stash(info.program, lineage_group_id)

    def auto_restore_signatures_from_stash(
        self, lineage_group_id: str, session_id: Optional[str] = None
    ) -> dict:
        from .tools.persistent_signatures import restore_signature_stash

        info = self._require_session(session_id)
        return restore_signature_stash(info.program, lineage_group_id)

    def auto_stash_current_binary(
        self, session_id: Optional[str] = None
    ) -> dict:
        from .tools.persistent_signatures import auto_stash_current_binary as _auto_stash

        info = self._require_session(session_id)
        return _auto_stash(info.program)

    def auto_restore_current_binary(
        self, session_id: Optional[str] = None
    ) -> dict:
        from .tools.persistent_signatures import auto_restore_current_binary as _auto_restore

        info = self._require_session(session_id)
        return _auto_restore(info.program)

    def list_stashed_signature_groups(self) -> list[dict]:
        from .tools.persistent_signatures import list_stashed_groups

        return list_stashed_groups()

    # ── Retro platform triage & load ─────────────────────────────────────

    def triage_and_load_retro_rom(
        self,
        rom_path: str,
        session_id: Optional[str] = None,
    ) -> dict:
        from .tools.retro_triage import detect_retro_platform

        rom_path = Path(rom_path).resolve()
        if not rom_path.exists():
            raise FileNotFoundError(f"Binary not found: {rom_path}")

        platform_name, lang_id, loader_name = detect_retro_platform(str(rom_path))

        sid = session_id or self._make_session_id()
        if sid in self._sessions:
            self.close_session(sid)

        project_dir = tempfile.mkdtemp(prefix="ghidra_bizhawk_")
        short = platform_name.split()[0].lower().replace("/", "_")
        project_name = f"_{rom_path.stem}_{short}_{int(time.time())}"

        kwargs = dict(
            binary_path=str(rom_path),
            project_location=project_dir,
            project_name=project_name,
            analyze=False,
        )
        if lang_id != "Auto-Detect":
            kwargs["language"] = lang_id

        old_stdout = sys.stdout
        sys.stdout = sys.stderr
        try:
            cm = _pyghidra.open_program(**kwargs)
            flat_api = cm.__enter__()
        finally:
            sys.stdout = old_stdout
        program = flat_api.getCurrentProgram()
        info = SessionInfo(
            session_id=sid,
            launcher=cm,
            program=program,
            flat_api=flat_api,
            binary_path=str(rom_path),
            project_name=project_name,
            project_location=project_dir,
            loaded_at=time.time(),
        )
        self._sessions[sid] = info
        self._active_session_id = sid

        from .tools.persistent_signatures import auto_restore_current_binary
        try:
            restore_result = auto_restore_current_binary(info.program)
            matched = restore_result.get("matched", 0)
            restore_status = f"Restored {matched} function names from signature cache"
        except Exception:
            restore_status = "No cached signatures found"

        return {
            "status": "Workspace successfully provisioned",
            "session_id": sid,
            "target_platform": platform_name,
            "selected_loader_engine": loader_name,
            "architecture_language_tag": info.program.getLanguageID().getIdAsString(),
            "memory_spaces_mapped": [block.getName() for block in info.program.getMemory().getBlocks()],
            "persistence_cache_status": restore_status,
        }


# ── Helpers ─────────────────────────────────────────────────────────────

def _find_function(program, name_or_addr: str):
    fm = program.getFunctionManager()
    addr = program.getAddressFactory().getAddress(name_or_addr)
    if addr is not None:
        func = fm.getFunctionAt(addr)
        if func is not None:
            return func
    for f in fm.getFunctions(True):
        if f.getName() == name_or_addr:
            return f
    return None


def _do_decompile(program, func) -> str:
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    monitor = ConsoleTaskMonitor()
    result = decompiler.decompileFunction(func, 0, monitor)
    if not result or not result.decompileCompleted():
        raise RuntimeError(f"Decompilation failed for '{func.getName()}'")
    return result.getDecompiledFunction().getC()


def _summarize_c_code(code: str) -> str:
    lines = code.split("\n")
    cleaned = []
    prev_empty = False
    for line in lines:
        stripped = line.rstrip()
        if stripped == "":
            if prev_empty:
                continue
            prev_empty = True
        else:
            prev_empty = False
        if re.match(r"^\s*(int|char|byte|uint|long|short|float|double)\s+\w+\s*;?\s*$", stripped):
            if re.search(r"local_|stack|pad|res", stripped, re.IGNORECASE):
                continue
        if re.match(r"^\s*undefined\d+\s+\w+\s*;?\s*$", stripped):
            continue
        cleaned.append(stripped)
    return "\n".join(cleaned)


def _resolve_type(dtm, type_str: str):
    from ghidra.program.model.data import PointerDataType
    type_str = type_str.strip()
    is_ptr = type_str.endswith("*")
    base = type_str.rstrip("*").strip()

    dt = dtm.getDataType(CategoryPath.ROOT, base)
    if dt is None and base in _SIMPLE_TYPES:
        from ghidra.program.model.data import (
            BooleanDataType, ByteDataType, ShortDataType, IntegerDataType,
            LongDataType, FloatDataType, DoubleDataType, UnsignedIntegerDataType,
        )
        _MAP = {
            "void": None,
            "bool": BooleanDataType(),
            "char": ByteDataType(),
            "byte": ByteDataType(),
            "short": ShortDataType(),
            "int": IntegerDataType(),
            "long": LongDataType(),
            "longlong": LongDataType(),
            "float": FloatDataType(),
            "double": DoubleDataType(),
            "uint": UnsignedIntegerDataType(),
        }
        dt = _MAP.get(base)

    if dt is None:
        for existing in dtm.getAllDataTypes():
            if existing.getName() == base:
                dt = existing
                break

    if dt is None:
        dt = ByteDataType()

    if is_ptr:
        return PointerDataType(dt)
    return dt


def _get_bytes(program, addr, length):
    try:
        mem = program.getMemory()
        jbuf = jpype.JArray(jpype.JByte, 1)(length)
        n = mem.getBytes(addr, jbuf)
        parts = []
        for i in range(n):
            parts.append(f"{(jbuf[i] + 256) % 256:02x}")
        return " ".join(parts)
    except Exception:
        return ""


def _read_raw_bytes(program, addr, length):
    try:
        mem = program.getMemory()
        jbuf = jpype.JArray(jpype.JByte, 1)(length)
        n = mem.getBytes(addr, jbuf)
        return [(jbuf[i] + 256) % 256 for i in range(n)]
    except Exception:
        return []


def _resolve_calls(func, program, depth: int) -> dict:
    if depth <= 0:
        return {}
    listing = program.getListing()
    fm = program.getFunctionManager()
    result = {}
    body = func.getBody()
    addr_iter = listing.getCodeUnits(body, True)
    seen = set()

    while addr_iter.hasNext():
        cu = addr_iter.next()
        refs = cu.getOperandReferences(0)
        for ref in refs:
            if ref.getReferenceType().toString() != "UNCONDITIONAL_CALL":
                continue
            target_addr = ref.getToAddress()
            target_key = str(target_addr)
            if target_key in seen:
                continue
            seen.add(target_key)
            target_func = fm.getFunctionAt(target_addr)
            if target_func:
                name = target_func.getName()
                if target_key not in result:
                    result[target_key] = {"name": name, "address": target_key}
                    if depth > 1:
                        nested = _resolve_calls(target_func, program, depth - 1)
                        if nested:
                            result[target_key]["calls"] = nested

    return {k: v for k, v in sorted(result.items())}
