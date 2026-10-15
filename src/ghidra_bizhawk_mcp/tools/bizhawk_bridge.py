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
    """TCP server that accepts BizHawk's built-in Lua socket client
    and mediates between MCP tool calls and bridge.lua running inside EmuHawk.

    Architecture:
      ghidra-bizhawk-mcp (TCP listener on localhost)
          │
          │  TCP — newline-delimited messages
          ▼
      BizHawk (socket client via --socket_ip / --socket_port)
          │  comm.socketServer* API
          │
      bridge.lua (BizHawk Lua, polls once per frame)

    Wire format:
      Lua → Python: "<len> READY\\n" | "<len> RESULT <json>\\n"
      Python → Lua: "NONE\\n" | "<len> <json>\\n"  (length-prefixed INCOMING)
    """

    def __init__(self, host: str = _DEFAULT_HOST, port: int = _DEFAULT_PORT):
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._server: asyncio.Server | None = None
        self._client_connected = asyncio.Event()
        self._connected = False
        self._cmd_id = 0
        self._pending_future: asyncio.Future | None = None
        self._pending_cmd: dict | None = None
        self._in_flight_cmd_id: int | None = None
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

    async def _wait_for_bizhawk(self, timeout: float = 30.0):
        """Wait for EmuHawk to connect to the local listener."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while not self._client_connected.is_set():
            if self._process and self._process.poll() is not None:
                raise RuntimeError(
                    f"EmuHawk exited with code {self._process.returncode} "
                    "before connecting to the MCP listener"
                )
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError(
                    f"BizHawk did not connect within {timeout:.0f}s "
                    f"to MCP listener {self._host}:{self._port}"
                )
            try:
                await asyncio.wait_for(self._client_connected.wait(), min(remaining, 0.1))
            except asyncio.TimeoutError:
                continue

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if self._connected:
            logger.warning("Rejecting duplicate BizHawk socket connection")
            writer.close()
            await writer.wait_closed()
            return

        self._reader = reader
        self._writer = writer
        self._connected = True
        self._client_connected.set()
        logger.info("BizHawk TCP client connected from %s", writer.get_extra_info("peername"))
        try:
            while True:
                line = await reader.readline()
                if not line:
                    logger.info("BizHawk bridge disconnected: EOF")
                    break

                line = line.decode("utf-8", errors="replace").rstrip("\r\n")
                logger.debug("BizHawk raw line received: %s", line)
                line = self._strip_length_prefix(line)

                if line == "READY":
                    await self._send_next()
                elif line.startswith("RESULT "):
                    self._handle_result(line[7:])
                    await self._send_next()
                else:
                    logger.warning("BizHawk bridge unexpected line: %s", line)
                    await self._send_message("4 NONE\n")
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError):
            logger.info("BizHawk bridge disconnected: transport error")
        except Exception:
            logger.exception("BizHawk socket handler crashed")
        finally:
            self._connected = False
            if self._pending_future and not self._pending_future.done():
                self._pending_future.set_exception(RuntimeError("BizHawk disconnected"))
                self._pending_future = None
                self._pending_cmd = None
                self._in_flight_cmd_id = None
            if self._writer is writer:
                self._reader = None
                self._writer = None
            self._client_connected.clear()
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, OSError):
                pass
            logger.info("BizHawk TCP client disconnected")

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def start(self):
        """Start the local TCP listener that EmuHawk connects to."""
        if self._server:
            return
        try:
            self._server = await asyncio.start_server(
                self._handle_client, self._host, self._port
            )
        except OSError as exc:
            raise RuntimeError(
                f"Cannot start BizHawk MCP listener on {self._host}:{self._port}: {exc}"
            ) from exc
        if self._port == 0:
            self._port = self._server.sockets[0].getsockname()[1]
        logger.info("BizHawk MCP listener started on %s:%s", self._host, self._port)

    async def stop(self):
        """Close the TCP connection and terminate BizHawk if we launched it."""
        self._connected = False
        self._lua_responsive = False
        # Cancel pending command
        if self._pending_future and not self._pending_future.done():
            self._pending_future.cancel()
            self._pending_future = None
            self._pending_cmd = None
            self._in_flight_cmd_id = None
        # Close TCP writer
        if self._writer:
            self._writer.close()
            try:
                await asyncio.wait_for(self._writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
            self._writer = None
        self._reader = None
        self._client_connected.clear()
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
        """Start the listener, then launch EmuHawk as its socket client."""
        if rom_path:
            rom_path = os.path.abspath(rom_path)
            if not os.path.isfile(rom_path):
                raise FileNotFoundError(f"ROM file not found: {rom_path}")
        if self._connected:
            return
        lua = self._bridge_lua_path()
        if not lua:
            raise RuntimeError("bridge.lua not found in package")
        await self.start()
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
            await self.stop()
            raise RuntimeError(f"EmuHawk executable not found: {emu_path}")
        try:
            logger.info("Waiting for BizHawk to connect to %s:%s", self._host, self._port)
            await self._wait_for_bizhawk()
            logger.info("BizHawk TCP client connected")
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
            self._in_flight_cmd_id = None
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
            if msg.get("id") != self._in_flight_cmd_id:
                error = RuntimeError(
                    f"BizHawk returned result id {msg.get('id')!r}; "
                    f"expected {self._in_flight_cmd_id!r}"
                )
                self._pending_future.set_exception(error)
                logger.error("BizHawk result id mismatch: %s", error)
                self._pending_future = None
                self._in_flight_cmd_id = None
                return
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
            self._in_flight_cmd_id = None
        else:
            logger.warning("BizHawk returned RESULT with no pending command: %s", json_str)

    @staticmethod
    def _strip_length_prefix(message: str) -> str:
        length, separator, payload = message.partition(" ")
        if separator and length.isdigit():
            return payload
        return message

    async def _send_message(self, message: str):
        if not self._writer:
            raise RuntimeError("BizHawk socket client is not connected")
        self._writer.write(message.encode("utf-8"))
        await self._writer.drain()

    async def _send_next(self):
        cmd = self._pending_cmd
        if cmd:
            self._pending_cmd = None
            self._in_flight_cmd_id = cmd["id"]
            cmd_json = json.dumps(cmd)
            msg = f"{len(cmd_json)} {cmd_json}\n"
            logger.debug("Sending BizHawk command id=%s method=%s", cmd.get("id"), cmd.get("method"))
            await self._send_message(msg)
        else:
            logger.debug("Sending BizHawk NONE heartbeat")
            await self._send_message("4 NONE\n")


# Module-level singleton
_BRIDGE = BizhawkBridge()


def get_bridge() -> BizhawkBridge:
    return _BRIDGE
