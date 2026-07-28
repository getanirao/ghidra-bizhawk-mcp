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
    """Asyncio TCP server that mediates between MCP tool calls and BizHawk's
    bridge.lua running inside EmuHawk.

    Architecture (inverted transport):
      ghidra-bizhawk-mcp (this server, runs TCP listener)
          ▲
          │  TCP — newline-delimited JSON
          │
      bridge.lua (BizHawk Lua, polls once per frame)

    Wire format:
      Lua → server: "READY\\n" | "RESULT <json>\\n"
      Server → Lua: "NONE\\n" | "<len> <json>\\n"  (length-prefixed INCOMING)
    """

    def __init__(self, host: str = _DEFAULT_HOST, port: int = _DEFAULT_PORT):
        self._host = host
        self._port = port
        self._server: asyncio.AbstractServer | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._cmd_id = 0
        self._pending_future: asyncio.Future | None = None
        self._pending_cmd: dict | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._emu_path: str | None = None
        self._process: subprocess.Popen | None = None
        self._lua_responsive = False

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
        # Search PATH
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

    # ── Public API ───────────────────────────────────────────────────────

    async def start(self):
        self._loop = asyncio.get_event_loop()
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._host,
            port=self._port,
        )
        logger.info("BizHawk bridge listening on %s:%s", self._host, self._port)

    async def stop(self):
        self._connected = False
        self._lua_responsive = False
        # Cancel any pending command
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
        # Close TCP server
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=1.0)
            except Exception:
                pass
            self._server = None
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
        self._reader = None

    async def _wait_for_connection(self, timeout: float = 30.0):
        """Wait for the BizHawk TCP bridge to connect."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            if self._connected:
                return
            if loop.time() >= deadline:
                raise TimeoutError(
                    f"BizHawk started but bridge did not connect within {timeout:.0f} seconds"
                )
            await asyncio.sleep(0.1)

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
        """Launch EmuHawk with the bridge Lua script and wait for connection."""
        if rom_path:
            rom_path = os.path.abspath(rom_path)
            if not os.path.isfile(rom_path):
                raise FileNotFoundError(f"ROM file not found: {rom_path}")
        if self._connected:
            return
        lua = self._bridge_lua_path()
        if not lua:
            raise RuntimeError("bridge.lua not found in package")
        args = [emu_path, f"--socket_ip={self._host}", f"--socket_port={self._port}", f"--lua={lua}"]
        if rom_path:
            args.append(rom_path)
        logger.info("Launching BizHawk: %s", " ".join(args))
        try:
            self._process = subprocess.Popen(args, shell=False)
        except FileNotFoundError:
            raise RuntimeError(f"EmuHawk executable not found: {emu_path}")
        try:
            logger.info("Waiting for BizHawk TCP bridge connection")
            await self._wait_for_connection()
            logger.info("BizHawk TCP bridge connected")
        except Exception:
            logger.exception("BizHawk launch failed before Lua bridge became reachable")
            await self.stop()
            raise

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def send_command(self, method: str, params: dict | None = None, timeout: float = 10.0) -> dict:
        """Send a command to BizHawk and wait for the result (≈2 frames ≈33ms).

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
        future = self._loop.create_future()

        self._pending_cmd = cmd
        self._pending_future = future
        logger.info("Queued BizHawk command id=%s method=%s", cmd["id"], method)

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending_future = None
            self._pending_cmd = None
            raise TimeoutError(f"BizHawk did not respond within {timeout:.0f} seconds — is bridge.lua still polling?")

    # ── Internal: TCP handler ────────────────────────────────────────────

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer
        self._connected = True
        self._lua_responsive = False
        logger.info("BizHawk client connected")

        try:
            while True:
                line = await reader.readline()
                if not line:
                    logger.info("BizHawk client disconnected: EOF from socket")
                    break

                line = line.decode("utf-8", errors="replace").rstrip("\r\n")
                logger.debug("BizHawk raw line received: %s", line)

                if line == "READY":
                    logger.debug("BizHawk bridge READY received")
                    await self._send_next()

                elif line.startswith("RESULT "):
                    logger.debug("BizHawk bridge RESULT received")
                    self._handle_result(line[7:])
                    await self._send_next()
                else:
                    logger.warning("BizHawk bridge sent unexpected line: %s", line)

        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError):
            logger.info("BizHawk client disconnected: transport error")
            pass
        finally:
            self._connected = False
            self._reader = None
            self._writer = None
            logger.info("BizHawk client disconnected")
            if self._pending_future and not self._pending_future.done():
                self._pending_future.set_exception(RuntimeError("BizHawk disconnected"))
                self._pending_future = None
                self._pending_cmd = None

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
            logger.debug("Sending BizHawk READY/NONE heartbeat")
            self._writer.write(b"4 NONE\n")
            await self._writer.drain()


# Module-level singleton
_BRIDGE = BizhawkBridge()


def get_bridge() -> BizhawkBridge:
    return _BRIDGE
