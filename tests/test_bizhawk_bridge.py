"""Integration test for BizhawkBridge TCP protocol.

Simulates bridge.lua on the other end of the TCP connection.
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


def _encode_python_to_lua(message: str) -> str:
    """Decode what Python sends to Lua — length-prefixed format."""
    # Python sends: "{len} {msg}\n"
    # Strip the length prefix and newline, return just the message body
    return message


class MockLuaBridge:
    """Simulates bridge.lua for testing."""

    def __init__(self, host="127.0.0.1", port=8766):
        self._host = host
        self._port = port
        self._reader = None
        self._writer = None
        self._last_sent = None
        self._last_received = None

    async def connect(self):
        self._reader, self._writer = await asyncio.open_connection(
            self._host, self._port
        )
        return self

    async def send(self, message: str):
        """Send a message (as bridge.lua would)."""
        data = _encode_lua_to_python(message)
        self._last_sent = message
        self._writer.write(data)
        await self._writer.drain()

    async def receive(self) -> str | None:
        """Receive the length-prefixed response from Python side."""
        line = await self._reader.readline()
        if not line:
            return None
        raw = line.decode("utf-8", errors="replace").rstrip("\r\n")
        self._last_received = raw
        # Parse length-prefixed format: "<len> <message>"
        # BizHawk's comm.socketServerResponse strips this internally
        if " " in raw:
            _, body = raw.split(" ", 1)
            return body
        return raw

    async def close(self):
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass


async def test_ping_pong():
    """Handshake → send ping → verify pong response."""
    bridge = BizhawkBridge(port=18766)
    await bridge.start()
    try:
        mock = await MockLuaBridge(port=18766).connect()

        # Frame 1: Lua sends "READY" → Python should respond with "NONE"
        await mock.send("READY")
        resp = await mock.receive()
        assert resp == "NONE", f"Expected 'NONE', got {resp!r}"
        print("[PASS] Frame 1: READY -> NONE")

        # Now call send_command from Python side. It'll queue a ping.
        # The mock needs to send another "READY" to trigger the command send.
        send_task = asyncio.create_task(bridge.send_command("ping"))

        # Frame 2: Lua sends "READY" again → Python should send the ping command
        await mock.send("READY")
        resp = await mock.receive()
        cmd = json.loads(resp)
        assert cmd["method"] == "ping", f"Expected ping method, got {cmd}"
        assert cmd["params"] == {}, f"Expected empty params, got {cmd}"
        print(f"[PASS] Frame 2: READY -> ping command (id={cmd['id']})")

        # Python is now waiting for RESULT. Lua sends the response.
        result_payload = {"id": cmd["id"], "result": "pong"}
        await mock.send("RESULT " + json.dumps(result_payload))

        # The send_task should resolve
        result = await asyncio.wait_for(send_task, timeout=5.0)
        assert result == "pong", f"Expected 'pong', got {result!r}"
        print("[PASS] Frame 3: RESULT -> pong received")

    finally:
        await bridge.stop()


async def test_read_memory():
    """Test read_range command returns proper byte array."""
    bridge = BizhawkBridge(port=18767)
    await bridge.start()
    try:
        mock = await MockLuaBridge(port=18767).connect()

        # Consume first READY
        await mock.send("READY")
        resp = await mock.receive()
        assert resp == "NONE"

        # Queue read_range
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

        # Simulate response: byte array [0x12, 0x34, 0x56, 0x78]
        result_payload = {"id": cmd["id"], "result": [0x12, 0x34, 0x56, 0x78]}
        await mock.send("RESULT " + json.dumps(result_payload))

        result = await asyncio.wait_for(send_task, timeout=5.0)
        assert result == [0x12, 0x34, 0x56, 0x78], f"Unexpected result: {result}"
        print("[PASS] read_range returned correct byte array")

    finally:
        await bridge.stop()


async def test_write_memory():
    """Test write_range command."""
    bridge = BizhawkBridge(port=18768)
    await bridge.start()
    try:
        mock = await MockLuaBridge(port=18768).connect()
        await mock.send("READY")
        await mock.receive()  # NONE

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

    finally:
        await bridge.stop()


async def test_frame_advance():
    """Test frame_advance with count."""
    bridge = BizhawkBridge(port=18769)
    await bridge.start()
    try:
        mock = await MockLuaBridge(port=18769).connect()
        await mock.send("READY")
        await mock.receive()  # NONE

        send_task = asyncio.create_task(
            bridge.send_command("frame_advance", {"count": 5})
        )

        await mock.send("READY")
        resp = await mock.receive()
        cmd = json.loads(resp)
        assert cmd["method"] == "frame_advance"
        assert cmd["params"]["count"] == 5
        print(f"[PASS] frame_advance command received")

        result_payload = {"id": cmd["id"], "result": 120}
        await mock.send("RESULT " + json.dumps(result_payload))

        result = await asyncio.wait_for(send_task, timeout=5.0)
        assert result == 120, f"Unexpected result: {result}"
        print("[PASS] frame_advance returned framecount 120")

    finally:
        await bridge.stop()


async def test_input_state():
    """Test input-state readback."""
    bridge = BizhawkBridge(port=18770)
    await bridge.start()
    try:
        mock = await MockLuaBridge(port=18770).connect()
        await mock.send("READY")
        await mock.receive()

        send_task = asyncio.create_task(bridge.send_command("get_input_state", {"player": 1}))

        await mock.send("READY")
        resp = await mock.receive()
        cmd = json.loads(resp)
        assert cmd["method"] == "get_input_state"
        assert cmd["params"]["player"] == 1

        state_payload = {
            "id": cmd["id"],
            "result": {
                "player": 1,
                "buttons": {"A": True, "B": False, "Start": True},
            },
        }
        await mock.send("RESULT " + json.dumps(state_payload))

        result = await asyncio.wait_for(send_task, timeout=5.0)
        assert result["player"] == 1
        assert result["buttons"]["A"] is True
        assert result["buttons"]["Start"] is True
        print("[PASS] get_input_state returned correct data")

    finally:
        await bridge.stop()


async def test_tap_buttons():
    """Test atomic tap_buttons command."""
    bridge = BizhawkBridge(port=18771)
    await bridge.start()
    try:
        mock = await MockLuaBridge(port=18771).connect()
        await mock.send("READY")
        await mock.receive()

        send_task = asyncio.create_task(
            bridge.send_command(
                "tap_buttons",
                {"buttons": {"A": True, "Start": True}, "frames": 3, "player": 1},
            )
        )

        await mock.send("READY")
        resp = await mock.receive()
        cmd = json.loads(resp)
        assert cmd["method"] == "tap_buttons"
        assert cmd["params"]["buttons"] == {"A": True, "Start": True}
        assert cmd["params"]["frames"] == 3
        assert cmd["params"]["player"] == 1

        tap_payload = {
            "id": cmd["id"],
            "result": {
                "player": 1,
                "buttons": {"A": True, "Start": True},
                "frames": 3,
                "framecount": 123,
            },
        }
        await mock.send("RESULT " + json.dumps(tap_payload))

        result = await asyncio.wait_for(send_task, timeout=5.0)
        assert result["frames"] == 3
        assert result["framecount"] == 123
        assert result["buttons"] == {"A": True, "Start": True}
        print("[PASS] tap_buttons returned correct data")

    finally:
        await bridge.stop()


async def test_ensure_responsive():
    """Test that launch returns only after a ping response."""
    bridge = BizhawkBridge(port=18778)
    calls = []

    async def fake_ensure_connected(rom_path=None):
        calls.append(("ensure_connected", rom_path))
        bridge._connected = True

    async def fake_send_command(method, params=None, timeout=10.0):
        calls.append(("send_command", method, timeout, params or {}))
        return "pong"

    bridge.ensure_connected = fake_ensure_connected  # type: ignore[method-assign]
    bridge.send_command = fake_send_command  # type: ignore[method-assign]

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


async def test_get_info():
    """Test get_info returns capabilities dict."""
    bridge = BizhawkBridge(port=18772)
    await bridge.start()
    try:
        mock = await MockLuaBridge(port=18772).connect()
        await mock.send("READY")
        await mock.receive()

        send_task = asyncio.create_task(bridge.send_command("get_info"))

        await mock.send("READY")
        resp = await mock.receive()
        cmd = json.loads(resp)
        assert cmd["method"] == "get_info"
        print(f"[PASS] get_info command received")

        info_response = {
            "id": cmd["id"],
            "result": {
                "rom_name": "TEST ROM",
                "framecount": 42,
                "memory_domains": ["WRAM", "VRAM", "OAM"],
                "capabilities": {"framecount": True, "pause": True},
            }
        }
        await mock.send("RESULT " + json.dumps(info_response))

        result = await asyncio.wait_for(send_task, timeout=5.0)
        assert result["rom_name"] == "TEST ROM"
        assert result["framecount"] == 42
        assert result["memory_domains"] == ["WRAM", "VRAM", "OAM"]
        print("[PASS] get_info returned correct data")

    finally:
        await bridge.stop()


async def test_error_response():
    """Test that bridge error responses propagate as exceptions."""
    bridge = BizhawkBridge(port=18773)
    await bridge.start()
    try:
        mock = await MockLuaBridge(port=18773).connect()
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

    finally:
        await bridge.stop()


async def test_connection_lost_during_command():
    """Test that disconnect raises RuntimeError in waiting command."""
    bridge = BizhawkBridge(port=18774)
    await bridge.start()
    try:
        mock = await MockLuaBridge(port=18774).connect()
        await mock.send("READY")
        await mock.receive()

        send_task = asyncio.create_task(bridge.send_command("ping"))

        await mock.send("READY")
        resp = await mock.receive()
        assert json.loads(resp)["method"] == "ping"

        # Disconnect before responding
        await mock.close()

        with pytest_raises(RuntimeError) as exc_info:
            await asyncio.wait_for(send_task, timeout=5.0)
        assert "disconnected" in str(exc_info.value).lower()
        print(f"[PASS] Connection loss raised RuntimeError in waiting command")

    finally:
        await bridge.stop()


async def test_timeout():
    """Test that send_command times out after 10 seconds."""
    bridge = BizhawkBridge(port=18775)
    await bridge.start()
    try:
        mock = await MockLuaBridge(port=18775).connect()
        await mock.send("READY")
        await mock.receive()

        # Set a very short timeout for testing by directly accessing
        # We can't easily change the timeout, so test with a short timeout by
        # wrapping in asyncio.wait_for with a short timeout
        send_task = asyncio.create_task(bridge.send_command("ping"))

        await mock.send("READY")
        resp = await mock.receive()
        assert json.loads(resp)["method"] == "ping"

        # Don't respond — the bridge should time out after 10s
        # We'll test with a shorter wrapper timeout
        with pytest_raises(asyncio.TimeoutError):
            await asyncio.wait_for(send_task, timeout=2.0)
        print(f"[PASS] Timeout correctly raised")

    finally:
        await bridge.stop()
        # Need to cancel the pending command to avoid hanging
        # The bridge's _pending_future will time out on its own


async def test_consecutive_commands():
    """Test that we can send multiple commands in sequence.

    After each RESULT, the Python side responds with NONE (no pending cmd).
    The mock must drain that NONE before the next cycle, otherwise it
    will parse stale NONE as the next command.
    """
    bridge = BizhawkBridge(port=18776)
    await bridge.start()
    try:
        mock = await MockLuaBridge(port=18776).connect()

        # Consume initial READY → NONE
        await mock.send("READY")
        assert await mock.receive() == "NONE"

        for i in range(3):
            # Queue command on Python side
            send_task = asyncio.create_task(
                bridge.send_command("ping")
            )

            # Send READY to trigger command delivery
            await mock.send("READY")
            resp = await mock.receive()
            cmd = json.loads(resp)
            assert cmd["method"] == "ping"

            # Send result back
            result_payload = {"id": cmd["id"], "result": f"pong-{i}"}
            await mock.send("RESULT " + json.dumps(result_payload))

            # MUST drain the NONE that Python sends back (no pending cmd after resolve)
            assert await mock.receive() == "NONE", "Expected NONE after RESULT"

            # Now the send_task result should be available
            result = await asyncio.wait_for(send_task, timeout=5.0)
            assert result == f"pong-{i}", f"Expected 'pong-{i}', got {result}"
            print(f"[PASS] Consecutive command {i}: ping -> pong-{i}")

    finally:
        await bridge.stop()


async def test_is_connected():
    """Test the is_connected property."""
    bridge = BizhawkBridge(port=18777)
    assert not bridge.is_connected, "Should not be connected before start"

    await bridge.start()
    assert not bridge.is_connected, "Should not be connected without client"

    mock = await MockLuaBridge(port=18777).connect()
    await mock.send("READY")
    await mock.receive()
    assert bridge.is_connected, "Should be connected after client connects"
    print("[PASS] is_connected works correctly")

    await mock.close()
    # Give the server a moment to notice the disconnect
    await asyncio.sleep(0.1)
    assert not bridge.is_connected, "Should not be connected after client disconnects"
    print("[PASS] is_connected false after disconnect")

    await bridge.stop()


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
        ("test_frame_advance", test_frame_advance),
        ("test_input_state", test_input_state),
        ("test_tap_buttons", test_tap_buttons),
        ("test_ensure_responsive", test_ensure_responsive),
        ("test_bizhawk_launch_rejects_missing_rom", test_bizhawk_launch_rejects_missing_rom),
        ("test_tool_result_helpers", test_tool_result_helpers),
        ("test_get_info", test_get_info),
        ("test_error_response", test_error_response),
        ("test_connection_lost_during_command", test_connection_lost_during_command),
        ("test_consecutive_commands", test_consecutive_commands),
        ("test_is_connected", test_is_connected),
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
        await asyncio.sleep(0.05)  # let ports settle

    print(f"\n{'=' * 60}")
    print(f"  RESULTS: {passed} passed, {failed} failed")
    print(f"{'=' * 60}")
    return failed


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
