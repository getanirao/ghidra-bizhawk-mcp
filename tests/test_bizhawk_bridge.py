"""Integration test for BizhawkBridge TCP protocol.

Simulates BizHawk's built-in socket server + bridge.lua on the server side,
while the BizhawkBridge connects as a TCP client.

Verifies the full READY/RESULT/command cycle, timeouts, and
connection-loss handling.
"""

import asyncio
import json
import logging
import os
import sys
import types as py_types

sys.path.insert(0, "src")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".venv", "Lib", "site-packages"))

for _name in ("pywintypes", "win32api", "win32con", "win32job"):
    sys.modules.setdefault(_name, py_types.ModuleType(_name))

import ghidra_bizhawk_mcp.server as server_mod
from ghidra_bizhawk_mcp.tools.bizhawk_bridge import BizhawkBridge

logging.basicConfig(level=logging.DEBUG, stream=sys.stderr,
                    format="%(levelname)s %(name)s %(message)s")


def _encode_lua_to_python(message: str) -> bytes:
    """Simulate what bridge.lua sends — plain newline-delimited text."""
    return (message + "\n").encode("utf-8")


class MockBizhawkServer:
    """Simulates BizHawk's built-in socket server + bridge.lua for testing.

    Runs a TCP server that the BizhawkBridge (Python side) connects to.
    """

    def __init__(self, host="127.0.0.1", port=8766):
        self._host = host
        self._port = port
        self._server = None
        self._reader = None
        self._writer = None
        self._last_sent = None
        self._last_received = None

    async def start(self):
        """Start the mock TCP server and wait for the bridge to connect."""
        async def _handle(reader, writer):
            self._reader = reader
            self._writer = writer
        self._server = await asyncio.start_server(_handle, self._host, self._port)
        return self

    async def wait_for_client(self, timeout=10.0):
        """Wait for the BizhawkBridge to connect."""
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            if self._reader is not None:
                return
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("Mock server: bridge did not connect in time")
            await asyncio.sleep(0.05)

    async def send(self, message: str):
        """Send a message (as bridge.lua would)."""
        data = _encode_lua_to_python(message)
        self._last_sent = message
        self._writer.write(data)
        await self._writer.drain()

    async def receive(self) -> str | None:
        """Receive the length-prefixed response from the Python bridge."""
        line = await self._reader.readline()
        if not line:
            return None
        raw = line.decode("utf-8", errors="replace").rstrip("\r\n")
        self._last_received = raw
        if " " in raw:
            _, body = raw.split(" ", 1)
            return body
        return raw

    @property
    def port(self):
        return self._server.sockets[0].getsockname()[1] if self._server else self._port

    async def close(self):
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None


async def test_ping_pong():
    """Handshake → send ping → verify pong response."""
    mock = await MockBizhawkServer(port=0).start()
    port = mock.port
    bridge = BizhawkBridge(port=port)
    await bridge._connect_to_bizhawk()  # connect as client
    await mock.wait_for_client()

    # Frame 1: Lua sends "READY" → Python should respond with "NONE"
    await mock.send("READY")
    resp = await mock.receive()
    assert resp == "NONE", f"Expected 'NONE', got {resp!r}"
    print("[PASS] Frame 1: READY -> NONE")

    # Queue ping on Python side
    send_task = asyncio.create_task(bridge.send_command("ping"))

    # Frame 2: Lua sends "READY" again → Python should send the ping command
    await mock.send("READY")
    resp = await mock.receive()
    cmd = json.loads(resp)
    assert cmd["method"] == "ping", f"Expected ping method, got {cmd}"
    assert cmd["params"] == {}, f"Expected empty params, got {cmd}"
    print(f"[PASS] Frame 2: READY -> ping command (id={cmd['id']})")

    # Python is now waiting for RESULT. Send the response.
    result_payload = {"id": cmd["id"], "result": "pong"}
    await mock.send("RESULT " + json.dumps(result_payload))

    # The send_task should resolve
    result = await asyncio.wait_for(send_task, timeout=5.0)
    assert result == "pong", f"Expected 'pong', got {result!r}"
    print("[PASS] Frame 3: RESULT -> pong received")

    await bridge.stop()
    await mock.close()


async def test_read_memory():
    """Test read_range command returns proper byte array."""
    mock = await MockBizhawkServer(port=0).start()
    port = mock.port
    bridge = BizhawkBridge(port=port)
    await bridge._connect_to_bizhawk()
    await mock.wait_for_client()

    await mock.send("READY")
    assert await mock.receive() == "NONE"

    send_task = asyncio.create_task(
        bridge.send_command("read_range", {"address": 0x3000, "length": 4})
    )

    await mock.send("READY")
    resp = await mock.receive()
    cmd = json.loads(resp)
    assert cmd["method"] == "read_range"
    assert cmd["params"]["address"] == 0x3000
    assert cmd["params"]["length"] == 4
    print(f"[PASS] read_range command received correctly")

    result_payload = {"id": cmd["id"], "result": [0x12, 0x34, 0x56, 0x78]}
    await mock.send("RESULT " + json.dumps(result_payload))

    result = await asyncio.wait_for(send_task, timeout=5.0)
    assert result == [0x12, 0x34, 0x56, 0x78], f"Unexpected result: {result}"
    print("[PASS] read_range returned correct byte array")

    await bridge.stop()
    await mock.close()


async def test_write_memory():
    """Test write_range command."""
    mock = await MockBizhawkServer(port=0).start()
    port = mock.port
    bridge = BizhawkBridge(port=port)
    await bridge._connect_to_bizhawk()
    await mock.wait_for_client()

    await mock.send("READY")
    await mock.receive()

    send_task = asyncio.create_task(
        bridge.send_command("write_range", {
            "address": 0x4000,
            "bytes": [0xAA, 0xBB],
            "domain": "WRAM",
        })
    )

    await mock.send("READY")
    resp = await mock.receive()
    cmd = json.loads(resp)
    assert cmd["method"] == "write_range"
    assert cmd["params"]["address"] == 0x4000
    assert cmd["params"]["bytes"] == [0xAA, 0xBB]
    assert cmd["params"]["domain"] == "WRAM"
    print(f"[PASS] write_range command received correctly")

    result_payload = {"id": cmd["id"], "result": {"written": 2}}
    await mock.send("RESULT " + json.dumps(result_payload))

    result = await asyncio.wait_for(send_task, timeout=5.0)
    assert result == {"written": 2}, f"Unexpected result: {result}"
    print("[PASS] write_range returned correct result")

    await bridge.stop()
    await mock.close()


async def test_consecutive_commands():
    """Test multiple commands in sequence."""
    mock = await MockBizhawkServer(port=0).start()
    port = mock.port
    bridge = BizhawkBridge(port=port)
    await bridge._connect_to_bizhawk()
    await mock.wait_for_client()

    await mock.send("READY")
    assert await mock.receive() == "NONE"

    for i in range(3):
        send_task = asyncio.create_task(bridge.send_command("ping"))

        await mock.send("READY")
        resp = await mock.receive()
        cmd = json.loads(resp)
        assert cmd["method"] == "ping"

        result_payload = {"id": cmd["id"], "result": f"pong-{i}"}
        await mock.send("RESULT " + json.dumps(result_payload))

        assert await mock.receive() == "NONE", "Expected NONE after RESULT"

        result = await asyncio.wait_for(send_task, timeout=5.0)
        assert result == f"pong-{i}", f"Expected 'pong-{i}', got {result}"
        print(f"[PASS] Consecutive command {i}: ping -> pong-{i}")

    await bridge.stop()
    await mock.close()


async def test_is_connected():
    """Test the is_connected property."""
    bridge = BizhawkBridge()
    assert not bridge.is_connected, "Should not be connected initially"

    mock = await MockBizhawkServer(port=0).start()
    port = mock.port
    bridge = BizhawkBridge(port=port)
    assert not bridge.is_connected, "Should not be connected before connect"

    await bridge._connect_to_bizhawk()
    await mock.wait_for_client()
    await mock.send("READY")
    await mock.receive()
    assert bridge.is_connected, "Should be connected after TCP handshake"
    print("[PASS] is_connected works correctly")

    await bridge.stop()
    await mock.close()


async def test_error_response():
    """Test that bridge error responses propagate as exceptions."""
    mock = await MockBizhawkServer(port=0).start()
    port = mock.port
    bridge = BizhawkBridge(port=port)
    await bridge._connect_to_bizhawk()
    await mock.wait_for_client()

    await mock.send("READY")
    await mock.receive()

    send_task = asyncio.create_task(bridge.send_command("unknown_method"))

    await mock.send("READY")
    resp = await mock.receive()
    cmd = json.loads(resp)
    assert cmd["method"] == "unknown_method"

    error_payload = {
        "id": cmd["id"],
        "error": {"code": -32601, "message": "unknown method: unknown_method"},
    }
    await mock.send("RESULT " + json.dumps(error_payload))

    with pytest_raises(RuntimeError) as exc_info:
        await asyncio.wait_for(send_task, timeout=5.0)
    assert "unknown method" in str(exc_info.value)
    print(f"[PASS] Error response correctly raised as RuntimeError")

    await bridge.stop()
    await mock.close()


async def test_connection_lost_during_command():
    """Test that disconnect raises RuntimeError in waiting command."""
    mock = await MockBizhawkServer(port=0).start()
    port = mock.port
    bridge = BizhawkBridge(port=port)
    await bridge._connect_to_bizhawk()
    await mock.wait_for_client()

    await mock.send("READY")
    await mock.receive()

    send_task = asyncio.create_task(bridge.send_command("ping"))

    await mock.send("READY")
    resp = await mock.receive()
    assert json.loads(resp)["method"] == "ping"

    await mock.close()

    with pytest_raises(RuntimeError) as exc_info:
        await asyncio.wait_for(send_task, timeout=5.0)
    assert "disconnected" in str(exc_info.value).lower()
    print(f"[PASS] Connection loss raised RuntimeError in waiting command")

    await bridge.stop()


async def test_timeout():
    """Test that send_command times out."""
    mock = await MockBizhawkServer(port=0).start()
    port = mock.port
    bridge = BizhawkBridge(port=port)
    await bridge._connect_to_bizhawk()
    await mock.wait_for_client()

    await mock.send("READY")
    await mock.receive()

    send_task = asyncio.create_task(bridge.send_command("ping"))

    await mock.send("READY")
    resp = await mock.receive()
    assert json.loads(resp)["method"] == "ping"

    with pytest_raises(asyncio.TimeoutError):
        await asyncio.wait_for(send_task, timeout=2.0)
    print(f"[PASS] Timeout correctly raised")

    await bridge.stop()
    await mock.close()


async def test_ensure_responsive():
    """Test that launch returns only after a ping response."""
    bridge = BizhawkBridge(port=18788)
    calls = []

    async def fake_ensure_connected(rom_path=None):
        calls.append(("ensure_connected", rom_path))
        bridge._connected = True

    async def fake_send_command(method, params=None, timeout=10.0):
        calls.append(("send_command", method, timeout, params or {}))
        return "pong"

    bridge.ensure_connected = fake_ensure_connected
    bridge.send_command = fake_send_command

    result = await bridge.ensure_responsive("C:/fake/rom.gba")
    assert result == "pong"
    assert calls == [
        ("ensure_connected", "C:/fake/rom.gba"),
        ("send_command", "ping", 10.0, {}),
    ]
    print("[PASS] ensure_responsive waits for ping before returning")


async def test_bizhawk_launch_rejects_missing_rom():
    """Test that launch fails immediately for missing ROM paths."""
    missing_rom = os.path.join(os.environ.get("TEMP", r"C:\Temp"), "definitely_missing_rom.gba")
    if os.path.exists(missing_rom):
        os.remove(missing_rom)

    with pytest_raises(FileNotFoundError) as exc_info:
        await server_mod._dispatch("bizhawk_launch", {"rom_path": missing_rom}, session=None)
    assert "ROM file not found" in str(exc_info.value)
    print("[PASS] bizhawk_launch rejects missing ROM paths")


async def test_tool_result_helpers():
    """Test that tool results keep structured content and errors preserve messages."""
    success = server_mod._tool_success({"status": "ok", "value": 42})
    assert success.structuredContent == {"status": "ok", "value": 42}
    assert not success.isError
    assert '"status": "ok"' in success.content[0].text

    error = server_mod._tool_error("bizhawk_launch", RuntimeError("bridge timed out"))
    assert error.isError
    assert error.structuredContent["tool"] == "bizhawk_launch"
    assert error.structuredContent["error"]["message"] == "bridge timed out"
    assert "bridge timed out" in error.content[0].text
    print("[PASS] tool result helpers preserve structured content and errors")


# ── Helpers ────────────────────────────────────────────────────────────────

class ExceptionInfo:
    """Minimal stand-in for pytest's ExceptionInfo."""
    def __init__(self, exc_val):
        self.value = exc_val

def pytest_raises(exc_type):
    """Simple context manager for testing exceptions (no pytest dependency)."""
    class _CtxMgr:
        def __init__(self, exc_type):
            self._exc_type = exc_type
            self._exc_info = None
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is None:
                raise AssertionError(f"Expected {self._exc_type.__name__} but no exception was raised")
            if not issubclass(exc_type, self._exc_type):
                raise AssertionError(f"Expected {self._exc_type.__name__} but got {exc_type.__name__}: {exc_val}")
            self._exc_info = ExceptionInfo(exc_val)
            self.value = exc_val
            return True
    return _CtxMgr(exc_type)


# ── Runner ─────────────────────────────────────────────────────────────────

async def main():
    tests = [
        ("test_ping_pong", test_ping_pong),
        ("test_read_memory", test_read_memory),
        ("test_write_memory", test_write_memory),
        ("test_consecutive_commands", test_consecutive_commands),
        ("test_is_connected", test_is_connected),
        ("test_error_response", test_error_response),
        ("test_connection_lost_during_command", test_connection_lost_during_command),
        ("test_ensure_responsive", test_ensure_responsive),
        ("test_bizhawk_launch_rejects_missing_rom", test_bizhawk_launch_rejects_missing_rom),
        ("test_tool_result_helpers", test_tool_result_helpers),
    ]

    passed = 0
    failed = 0

    for name, test_fn in tests:
        print(f"\n{'=' * 60}")
        print(f"  RUNNING: {name}")
        print(f"{'=' * 60}")
        try:
            await test_fn()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
        await asyncio.sleep(0.05)

    print(f"\n{'=' * 60}")
    print(f"  RESULTS: {passed} passed, {failed} failed")
    print(f"{'=' * 60}")
    return failed


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
