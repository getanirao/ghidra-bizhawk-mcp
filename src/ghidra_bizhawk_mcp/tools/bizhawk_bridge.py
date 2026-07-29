import asyncio
import json
import logging
import os
import subprocess
import sys

logger = logging.getLogger(__name__)

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = int(os.environ.get("BIZHAWK_PORT", "8766"))
_EMU_EXE = "EmuHawk.exe"


class BizhawkBridge:
    """TCP client that connects to BizHawk's built-in Lua socket server
    and mediates between MCP tool calls and bridge.lua running inside EmuHawk.

    Architecture:
      ghidra-bizhawk-mcp (this client, connects to BizHawk)
          │
          │  TCP — newline-delimited JSON
          ▼
      BizHawk (runs socket server via --socket_ip / --socket_port)
          ▲
          │  comm.socketServer* API
          │
      bridge.lua (BizHawk Lua, polls once per frame)

    Wire format:
      Lua → Python: "READY\\n" | "RESULT <json>\\n"
      Python → Lua: "NONE\\n" | "<len> <json>\\n"  (length-prefixed INCOMING)
    """

    def __init__(self, host: str = _DEFAULT_HOST, port: int = _DEFAULT_PORT):
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._cmd_id = 0
        self._pending_future: asyncio.Future | None = None
        self._pending_cmd: dict | None = None
        self._emu_path: str | None = None
        self._process: subprocess.Popen | None = None
        self._lua_responsive = False
        self._pump_task: asyncio.Task | None = None

    @staticmethod
    def find_emu_path() -> str | None:
        """Locate EmuHawk.exe on this system."""
        env_path = os.environ.get("BIZHAWK_EXE_PATH")
        if env_path and os.path.isfile(env_path):
            return env_path
        candidates = [
            os.path.expandvars(r"%ProgramFiles%\BizHawk\EmuHawk.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\BizHawk\EmuHawk.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\BizHawk\EmuHawk.exe"),
            os.path.expandvars(r"%USERPROFILE%\Downloads\BizHawk-2.11.1-win-x64\EmuHawk.exe"),
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
        for dir_ in os.environ.get("PATH", "").split(os.pathsep):
            p = os.path.join(dir_, _EMU_EXE)
            if os.path.isfile(p):
                return p
        return None

    def _bridge_lua_path(self) -> str | None:
        """Return path to the bundled bridge.lua."""
        pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        lua = os.path.join(pkg_dir, "lua", "bridge.lua")
        return lua if os.path.isfile(lua) else None

    # ── Connection management ─────────────────────────────────────────────

    async def _connect_to_bizhawk(self, timeout: float = 30.0):
        """Connect to BizHawk's built-in Lua socket server (TCP client).

        BizHawk must already be running with --socket_ip / --socket_port.
        Retries until the server accepts the connection or timeout expires.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        last_error = None
        while True:
            try:
                self._reader, self._writer = await asyncio.open_connection(
                    self._host, self._port
                )
                self._connected = True
                self._pump_task = asyncio.create_task(self._message_pump())
                logger.info(
                    "Connected to BizHawk socket server at %s:%s",
                    self._host, self._port,
                )
                return
            except (ConnectionRefusedError, OSError) as exc:
                last_error = exc
                if loop.time() >= deadline:
                    raise TimeoutError(
                        f"BizHawk socket server did not accept connection "
                        f"within {timeout:.0f}s on {self._host}:{self._port}"
                    ) from exc
                await asyncio.sleep(0.5)

    async def _message_pump(self):
        """Read inbound messages from bridge.lua and dispatch.

        Runs as a background task for the lifetime of the connection.
        """
        try:
            while True:
                line = await self._reader.readline()
                if not line:
                    logger.info("BizHawk bridge disconnected: EOF")
                    break

                line = line.decode("utf-8", errors="replace").rstrip("\r\n")
                logger.debug("BizHawk raw line received: %s", line)

                if line == "READY":
                    await self._send_next()
                elif line.startswith("RESULT "):
                    self._handle_result(line[7:])
                    await self._send_next()
                else:
                    logger.warning("BizHawk bridge unexpected line: %s", line)
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError):
            logger.info("BizHawk bridge disconnected: transport error")
        except Exception:
            logger.exception("BizHawk message pump crashed")
        finally:
            self._connected = False
            self._reader = None
            if self._pending_future and not self._pending_future.done():
                self._pending_future.set_exception(RuntimeError("BizHawk disconnected"))
                self._pending_future = None
                self._pending_cmd = None
            logger.info("BizHawk bridge disconnected")

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def start(self):
        """No-op kept for backward compatibility; connection happens on demand."""
        pass

    async def stop(self):
        """Close the TCP connection and terminate BizHawk if we launched it."""
        self._connected = False
        self._lua_responsive = False
        # Cancel message pump
        if self._pump_task and not self._pump_task.done():
            self._pump_task.cancel()
            try:
                await asyncio.wait_for(self._pump_task, timeout=2.0)
            except (asyncio.CancelledError, Exception):
                pass
            self._pump_task = None
        # Cancel pending command
        if self._pending_future and not self._pending_future.done():
            self._pending_future.cancel()
            self._pending_future = None
            self._pending_cmd = None
        # Close TCP writer
        if self._writer:
            self._writer.close()
            try:
                await asyncio.wait_for(self._writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
            self._writer = None
        self._reader = None
        # Terminate BizHawk subprocess
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                    self._process.wait(timeout=3)
                except Exception:
                    pass
            self._process = None

    async def ensure_connected(self, rom_path: str | None = None):
        """Auto-launch BizHawk if not connected. Blocks until bridge connects."""
        if self._connected:
            return
        emu = self._emu_path or self.find_emu_path()
        if not emu:
            raise RuntimeError(
                "BizHawk not found. Set BIZHAWK_EXE_PATH env var or install BizHawk."
            )
        self._emu_path = emu
        await self.launch(emu, rom_path)

    async def ensure_responsive(self, rom_path: str | None = None):
        """Auto-launch BizHawk if needed and verify the Lua bridge answers ping."""
        await self.ensure_connected(rom_path)
        logger.info("Verifying BizHawk Lua bridge responsiveness with ping")
        try:
            pong = await self.send_command("ping", timeout=10.0)
        except Exception:
            logger.exception("BizHawk TCP connection exists but Lua bridge did not respond to ping")
            await self.stop()
            raise
        if pong != "pong":
            await self.stop()
            raise RuntimeError(f"BizHawk bridge returned unexpected ping response: {pong!r}")
        self._lua_responsive = True
        logger.info("BizHawk Lua bridge responsive: %s", pong)
        return pong

    async def launch(self, emu_path: str, rom_path: str | None = None):
        """Launch EmuHawk (starts its own socket server), then connect as client."""
        if rom_path:
            rom_path = os.path.abspath(rom_path)
            if not os.path.isfile(rom_path):
                raise FileNotFoundError(f"ROM file not found: {rom_path}")
        if self._connected:
            return
        lua = self._bridge_lua_path()
        if not lua:
            raise RuntimeError("bridge.lua not found in package")
        args = [
            emu_path,
            f"--socket_ip={self._host}",
            f"--socket_port={self._port}",
            f"--lua={lua}",
        ]
        if rom_path:
            args.append(rom_path)
        logger.info("Launching BizHawk: %s", " ".join(args))
        try:
            self._process = subprocess.Popen(args, shell=False)
        except FileNotFoundError:
            raise RuntimeError(f"EmuHawk executable not found: {emu_path}")
        try:
            logger.info("Connecting to BizHawk socket server at %s:%s", self._host, self._port)
            await self._connect_to_bizhawk()
            logger.info("BizHawk bridge connected")
        except Exception:
            logger.exception("BizHawk launch failed before Lua bridge became reachable")
            await self.stop()
            raise

    @property
    def is_connected(self) -> bool:
        return self._connected

    # ── Command API ────────────────────────────────────────────────────────

    async def send_command(self, method: str, params: dict | None = None, timeout: float = 10.0) -> dict:
        """Send a command to BizHawk and wait for the result.

        Raises RuntimeError if the bridge is not connected or a command is
        already in flight.
        Raises TimeoutError after 10 seconds with no response.
        """
        if not self._connected:
            await self.ensure_connected()
        if self._pending_future is not None:
            raise RuntimeError("A command is already in flight")

        self._cmd_id += 1
        cmd = {"id": self._cmd_id, "method": method, "params": params or {}}
        future = asyncio.get_running_loop().create_future()

        self._pending_cmd = cmd
        self._pending_future = future
        logger.info("Queued BizHawk command id=%s method=%s", cmd["id"], method)

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending_future = None
            self._pending_cmd = None
            raise TimeoutError(
                f"BizHawk did not respond within {timeout:.0f} seconds — is bridge.lua still polling?"
            )

    # ── Internal: protocol handlers ────────────────────────────────────────

    def _handle_result(self, json_str: str):
        try:
            msg = json.loads(json_str)
        except json.JSONDecodeError:
            logger.warning("BizHawk RESULT parse error: %s", json_str)
            return
        if self._pending_future and not self._pending_future.done():
            logger.debug("BizHawk returned result for id=%s", msg.get("id"))
            if "error" in msg:
                err_info = msg["error"]
                self._pending_future.set_exception(
                    RuntimeError(err_info.get("message", str(err_info)))
                )
                logger.error("BizHawk command id=%s failed: %s", msg.get("id"), err_info)
            else:
                self._pending_future.set_result(msg.get("result"))
                logger.debug("BizHawk command id=%s succeeded", msg.get("id"))
            self._pending_future = None
        else:
            logger.warning("BizHawk returned RESULT with no pending command: %s", json_str)

    async def _send_next(self):
        cmd = self._pending_cmd
        if cmd:
            self._pending_cmd = None
            cmd_json = json.dumps(cmd)
            msg = f"{len(cmd_json)} {cmd_json}\n"
            logger.debug("Sending BizHawk command id=%s method=%s", cmd.get("id"), cmd.get("method"))
            self._writer.write(msg.encode("utf-8"))
            await self._writer.drain()
        else:
            logger.debug("Sending BizHawk NONE heartbeat")
            self._writer.write(b"4 NONE\n")
            await self._writer.drain()


# Module-level singleton
_BRIDGE = BizhawkBridge()


def get_bridge() -> BizhawkBridge:
    return _BRIDGE
