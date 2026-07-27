-- bridge.lua: BizHawk-side polling client for ghidra-bizhawk-mcp
--
-- Architecture (inverted — the MCP server runs the TCP listener):
--
--   ghidra-bizhawk-mcp (Python, runs TCP server :8766)
--          ▲
--          │  TCP — newline-delimited JSON
--          │
--   bridge.lua (BizHawk Lua, polls every frame)
--
-- Each frame, one round-trip:
--   1. Lua sends "READY\n" or "RESULT <json>\n"
--   2. Server responds with "NONE\n" or length-prefixed JSON command
--   3. If a command arrived, execute it and stash result for next frame
--
-- Wire format (bidirectional, newline-terminated):
--   Lua → server: "READY\n" | "RESULT <json>\n"
--   Server → Lua: "NONE\n" | "<len> <json>\n"  (length-prefixed INCOMING)
--
-- Setup:
--   EmuHawk.exe --socket_ip=127.0.0.1 --socket_port=8766 --lua=bridge.lua <rom>
--   Alternatively, load manually: Tools → Lua Console → Open Script

-- Pure Lua JSON (no external deps — BizHawk/NLua doesn't bundle a json module)
local json = {}
function json.encode(t)
    if t == nil then return "null" end
    local tpe = type(t)
    if tpe == "string"  then return '"' .. t:gsub('["\\]', {['"'] = '\\"', ['\\'] = '\\\\'}):gsub('\n', '\\n'):gsub('\r', '\\r'):gsub('\t', '\\t') .. '"' end
    if tpe == "number"  then return tostring(t) end
    if tpe == "boolean" then return tostring(t) end
    if tpe == "table" then
        local is_arr, max_n = true, 0
        for k, _ in pairs(t) do
            if type(k) ~= "number" or k < 1 then is_arr = false; break end
            if k > max_n then max_n = k end
        end
        if is_arr then
            local parts = {}
            for i = 1, max_n do parts[i] = json.encode(t[i]) end
            return "[" .. table.concat(parts, ",") .. "]"
        else
            local parts = {}
            local i = 1
            for k, v in pairs(t) do
                parts[i] = json.encode(tostring(k)) .. ":" .. json.encode(v)
                i = i + 1
            end
            return "{" .. table.concat(parts, ",") .. "}"
        end
    end
    return "null"
end
function json.decode(s)
    if not s or #s == 0 then return nil end
    local pos, ok = 1, true
    local function skip() while pos <= #s do local c = s:sub(pos,pos); if c == ' ' or c == '\t' or c == '\n' or c == '\r' then pos = pos + 1 else break end end end
    local function expect(ch)
        skip(); if s:sub(pos,pos) ~= ch then ok = false end; pos = pos + 1
    end
    local function parse_val()
        skip(); if not ok then return nil end
        if pos > #s then return nil end
        local c = s:sub(pos,pos)
        if c == '"' then
            pos = pos + 1
            local out = {}
            while pos <= #s do
                local cc = s:sub(pos,pos)
                if cc == '"' then pos = pos + 1; break end
                if cc == '\\' then
                    pos = pos + 1; local esc = s:sub(pos,pos)
                    if esc == '"' or esc == '\\' then out[#out+1] = esc
                    elseif esc == 'n' then out[#out+1] = '\n'
                    elseif esc == 'r' then out[#out+1] = '\r'
                    elseif esc == 't' then out[#out+1] = '\t'
                    elseif esc == 'u' then
                        local hex = s:sub(pos+1,pos+4)
                        out[#out+1] = utf8 and utf8.char(tonumber(hex, 16)) or '?'
                        pos = pos + 4
                    end
                    pos = pos + 1
                else out[#out+1] = cc; pos = pos + 1 end
            end
            return table.concat(out)
        elseif c == '{' then
            pos = pos + 1; local obj = {}
            skip()
            if s:sub(pos,pos) == '}' then pos = pos + 1; return obj end
            while ok do
                skip(); local k = parse_val(); skip(); expect(':'); skip(); local v = parse_val()
                if ok then obj[tostring(k)] = v end
                skip()
                local cc = s:sub(pos,pos)
                if cc == ',' then pos = pos + 1
                elseif cc == '}' then pos = pos + 1; break
                else ok = false end
            end
            return obj
        elseif c == '[' then
            pos = pos + 1; local arr = {}
            skip()
            if s:sub(pos,pos) == ']' then pos = pos + 1; return arr end
            while ok do
                table.insert(arr, parse_val()); skip()
                local cc = s:sub(pos,pos)
                if cc == ',' then pos = pos + 1
                elseif cc == ']' then pos = pos + 1; break
                else ok = false end
            end
            return arr
        elseif c == 't' then pos = pos + 4; return true
        elseif c == 'f' then pos = pos + 5; return false
        elseif c == 'n' then pos = pos + 4; return nil
        else
            local _, e = s:find('^[-]?[0-9]+%.?[0-9]*([eE][+-]?[0-9]+)?', pos)
            if e then local n = tonumber(s:sub(pos,e)); pos = e + 1; return n end
            ok = false; return nil
        end
    end
    local r = parse_val()
    return r
end

local pending_result = nil
local skip_outer_frameadvance = false

-- Capability detection
local function has(t, name)
    if not t then return false end
    local v = rawget(t, name)
    if v == nil then v = t[name] end
    if v == nil then return false end
    local tv = type(v)
    return tv == "function" or tv == "userdata"
end

local CAPS = {
    framecount             = emu and has(emu, "framecount"),
    pause                  = emu and has(emu, "pause"),
    unpause                = emu and has(emu, "unpause"),
    frameadvance           = emu and has(emu, "frameadvance"),
    reboot_core            = client and has(client, "reboot_core"),
    screenshot             = client and has(client, "screenshot"),
    savestate_save         = savestate and has(savestate, "save"),
    savestate_load         = savestate and has(savestate, "load"),
    joypad_set             = joypad and has(joypad, "set"),
    joypad_get             = joypad and has(joypad, "get"),
    memory_read_u8         = memory and has(memory, "read_u8"),
    memory_read_u16_le     = memory and has(memory, "read_u16_le"),
    memory_read_u32_le     = memory and has(memory, "read_u32_le"),
    memory_write_u8        = memory and has(memory, "write_u8"),
    memory_write_u16_le    = memory and has(memory, "write_u16_le"),
    memory_write_u32_le    = memory and has(memory, "write_u32_le"),
    memory_get_domain_list = memory and has(memory, "getmemorydomainlist"),
    memory_get_current_domain = memory and has(memory, "getcurrentmemorydomain"),
    memory_use_domain      = memory and has(memory, "usememorydomain"),
    memory_get_domain_size = memory and has(memory, "getmemorydomainsize"),
    gameinfo_getromname    = gameinfo and has(gameinfo, "getromname"),
    gameinfo_getromhash    = gameinfo and has(gameinfo, "getromhash"),
}

function memory_domain_list()
    if not CAPS.memory_get_domain_list then return nil end
    local raw = memory.getmemorydomainlist()
    local out = {}
    local i = (raw[0] ~= nil) and 0 or 1
    while raw[i] ~= nil do
        out[#out + 1] = raw[i]
        i = i + 1
    end
    return out
end

local function in_domain(domain, fn)
    if not domain then return fn() end
    if not CAPS.memory_use_domain then
        error("memory.usememorydomain not available")
    end
    local prev = memory.getcurrentmemorydomain and memory.getcurrentmemorydomain() or nil
    local ok = memory.usememorydomain(domain)
    if not ok then error("unknown memory domain: " .. tostring(domain)) end
    local r = fn()
    if prev then memory.usememorydomain(prev) end
    return r
end

local function strip_length_prefix(message)
    if type(message) ~= "string" then return message end
    local body = message:match("^%d+%s+(.*)$")
    if body then return body end
    return message
end

local function advance_frames(count)
    if not CAPS.frameadvance then error("emu.frameadvance not available") end
    local n = math.max(1, math.floor(tonumber(count or 1) or 1))
    for _ = 1, n do emu.frameadvance() end
    skip_outer_frameadvance = true
    return CAPS.framecount and emu.framecount() or nil
end

-- Command handlers
local function cmd_ping(p) return "pong" end

local function cmd_get_info(p)
    return {
        rom_name             = CAPS.gameinfo_getromname and gameinfo.getromname() or nil,
        rom_hash             = CAPS.gameinfo_getromhash and gameinfo.getromhash() or nil,
        framecount           = CAPS.framecount and emu.framecount() or nil,
        memory_domains       = memory_domain_list(),
        current_memory_domain = CAPS.memory_get_current_domain and memory.getcurrentmemorydomain() or nil,
        capabilities = CAPS,
    }
end

local function cmd_list_memory_domains(p)
    if not CAPS.memory_get_domain_list then error("memory.getmemorydomainlist not available") end
    return memory_domain_list()
end

local function cmd_read8(p)
    local addr = assert(p.address, "address required")
    return in_domain(p.domain, function() return memory.read_u8(addr) end)
end

local function cmd_read16(p)
    local addr = assert(p.address, "address required")
    return in_domain(p.domain, function() return memory.read_u16_le(addr) end)
end

local function cmd_read32(p)
    local addr = assert(p.address, "address required")
    return in_domain(p.domain, function() return memory.read_u32_le(addr) end)
end

local function cmd_write8(p)
    local addr = assert(p.address, "address required")
    local val  = assert(p.value,  "value required")
    in_domain(p.domain, function() memory.write_u8(addr, val) end)
    return true
end

local function cmd_write16(p)
    local addr = assert(p.address, "address required")
    local val  = assert(p.value,  "value required")
    in_domain(p.domain, function() memory.write_u16_le(addr, val) end)
    return true
end

local function cmd_write32(p)
    local addr = assert(p.address, "address required")
    local val  = assert(p.value,  "value required")
    in_domain(p.domain, function() memory.write_u32_le(addr, val) end)
    return true
end

local function cmd_read_range(p)
    local addr = assert(p.address, "address required")
    local len  = assert(p.length, "length required")
    if len > 4096 then error("length exceeds 4096 byte limit") end
    return in_domain(p.domain, function()
        local bytes = {}
        for i = 0, len - 1 do bytes[i + 1] = memory.read_u8(addr + i) end
        return bytes
    end)
end

local function cmd_write_range(p)
    local addr  = assert(p.address, "address required")
    local bytes = assert(p.bytes,  "bytes required (array of integers)")
    if #bytes > 4096 then error("byte count exceeds 4096 limit") end
    return in_domain(p.domain, function()
        for i, b in ipairs(bytes) do memory.write_u8(addr + i - 1, b) end
        return { written = #bytes }
    end)
end

local function cmd_press_buttons(p)
    if not CAPS.joypad_set then error("joypad.set not available") end
    local buttons = assert(p.buttons, "buttons required (table like {A=true, Up=true})")
    joypad.set(buttons, p.player or 1)
    return true
end

local function cmd_get_input_state(p)
    if not CAPS.joypad_get then error("joypad.get not available") end
    local player = p.player or 1
    local state = joypad.get(player) or {}
    return { player = player, buttons = state }
end

local function cmd_tap_buttons(p)
    if not CAPS.joypad_set then error("joypad.set not available") end
    local buttons = assert(p.buttons, "buttons required (table like {A=true, Up=true})")
    local player = p.player or 1
    local frames = math.max(1, math.floor(tonumber(p.frames or 1) or 1))

    joypad.set(buttons, player)
    local framecount = advance_frames(frames)
    joypad.set({}, player)

    return { player = player, buttons = buttons, frames = frames, framecount = framecount }
end

local function cmd_pause(p)
    if not CAPS.pause then error("emu.pause not available") end
    emu.pause()
    return true
end

local function cmd_unpause(p)
    if not CAPS.unpause then error("emu.unpause not available") end
    emu.unpause()
    return true
end

local function cmd_frame_advance(p)
    local n = math.max(1, math.floor(tonumber(p.count or 1) or 1))
    return advance_frames(n)
end

local function cmd_reset(p)
    if not CAPS.reboot_core then error("client.reboot_core not available") end
    client.reboot_core()
    return true
end

local function cmd_screenshot(p)
    if not CAPS.screenshot then error("client.screenshot not available") end
    local path = assert(p.path, "path required")
    client.screenshot(path)
    return { path = path }
end

local function cmd_save_state(p)
    if not CAPS.savestate_save then error("savestate.save not available") end
    local path = assert(p.path, "path required")
    savestate.save(path)
    return { path = path }
end

local function cmd_load_state(p)
    if not CAPS.savestate_load then error("savestate.load not available") end
    local path = assert(p.path, "path required")
    savestate.load(path)
    return { path = path }
end

-- Dispatch table
local HANDLERS = {
    ping                = cmd_ping,
    get_info            = cmd_get_info,
    list_memory_domains = cmd_list_memory_domains,
    read8               = cmd_read8,
    read16              = cmd_read16,
    read32              = cmd_read32,
    write8              = cmd_write8,
    write16             = cmd_write16,
    write32             = cmd_write32,
    read_range          = cmd_read_range,
    write_range         = cmd_write_range,
    press_buttons       = cmd_press_buttons,
    get_input_state     = cmd_get_input_state,
    tap_buttons         = cmd_tap_buttons,
    pause               = cmd_pause,
    unpause             = cmd_unpause,
    frame_advance       = cmd_frame_advance,
    reset               = cmd_reset,
    screenshot          = cmd_screenshot,
    save_state          = cmd_save_state,
    load_state          = cmd_load_state,
}

local function dispatch(cmd)
    if not cmd.method then
        return nil, { code = -32600, message = "missing method field" }
    end
    local handler = HANDLERS[cmd.method]
    if not handler then
        return nil, { code = -32601, message = "unknown method: " .. cmd.method }
    end
    local ok, result = pcall(handler, cmd.params or {})
    if not ok then
        return nil, { code = -32603, message = tostring(result) }
    end
    return result, nil
end

-- Per-frame round trip
local function tick()
    local outgoing
    if pending_result then
        outgoing = "RESULT " .. json.encode(pending_result)
        pending_result = nil
    else
        outgoing = "READY"
    end

    comm.socketServerSend(outgoing .. "\n")

    local incoming = comm.socketServerResponse()
    if incoming and type(incoming) == "string" and #incoming > 0 then
        incoming = strip_length_prefix(incoming):gsub("[\r\n]+$", "")
        if incoming ~= "NONE" and #incoming > 0 then
            local parse_ok, cmd = pcall(json.decode, incoming)
            if parse_ok and type(cmd) == "table" then
                local result, rpc_err = dispatch(cmd)
                if rpc_err then
                    pending_result = { id = cmd.id, error = rpc_err }
                else
                    pending_result = { id = cmd.id, result = result }
                end
            else
                pending_result = { id = nil, error = { code = -32700, message = "parse error" } }
            end
        end
    end
end

-- Startup
console.log("[ghidra-bizhawk-mcp] bridge starting")

if not (comm and comm.socketServerSend and comm.socketServerResponse) then
    console.log("[ghidra-bizhawk-mcp] FATAL: comm.socketServer* not available")
    return
end

local ip   = comm.socketServerGetIp   and comm.socketServerGetIp()   or "(unknown)"
local port = comm.socketServerGetPort and comm.socketServerGetPort() or "(unknown)"
console.log(string.format("[ghidra-bizhawk-mcp] socket server target: %s:%s", tostring(ip), tostring(port)))

if comm.socketServerSetTimeout then
    comm.socketServerSetTimeout(50)
    console.log("[ghidra-bizhawk-mcp] socket receive timeout set to 50ms")
end

console.log("[ghidra-bizhawk-mcp] frame loop active — polling once per frame")

local tick_count = 0
local disconnect_count = 0
while true do
    tick_count = tick_count + 1

    if tick_count % 60 == 0 and comm.socketServerIsConnected then
        local connected = comm.socketServerIsConnected()
        if not connected then
            disconnect_count = disconnect_count + 1
            console.log("[ghidra-bizhawk-mcp] socket disconnected (" .. disconnect_count .. "), waiting for reconnection...")
            if disconnect_count >= 10 then
                console.log("[ghidra-bizhawk-mcp] socket disconnected for ~10 seconds, exiting bridge loop")
                break
            end
        else
            disconnect_count = 0
        end
    end

    tick()
    if skip_outer_frameadvance then
        skip_outer_frameadvance = false
    else
        emu.frameadvance()
    end
end
