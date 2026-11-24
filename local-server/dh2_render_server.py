#!/usr/bin/env python3
"""Render-ready single-port HTTP + WebSocket server for Dungeon Hunter 2.

Routes on 0.0.0.0:$PORT:
  - GET  /                          Health check
  - GET/POST /ope/ServerConfig.php  Gameloft Live config
  - GET/POST /ope/GenericXPlayer_v1.php  Auth, Lobby lookup, Friends, Leaderboards (SQLite)
  - WS   /ws/lobby                  Binary Lobby frames (2B BE len + DataPacketLobby)
  - WS   /ws/relay                  Binary Relay frames (e5be00b0 ...)
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import struct
import time
import urllib.parse

import aiohttp
from aiohttp import WSMsgType, web

DB_PATH = os.environ.get(
    "DH2_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "dh2_online.db"),
)
PUBLIC_HOST = os.environ.get("DH2_PUBLIC_HOST", "dh2net.onrender.com")
TURSO_URL = os.environ.get("TURSO_DATABASE_URL", "").strip()
TURSO_TOKEN = os.environ.get("TURSO_AUTH_TOKEN", "").strip()
if TURSO_URL.startswith("libsql://"):
    TURSO_URL = "https://" + TURSO_URL[len("libsql://"):]

LOBBIES: dict[int, dict] = {}
NEXT_LOBBY_ID = 1
ONLINE_USERS: dict[str, float] = {}
TURSO_SESSION: aiohttp.ClientSession | None = None

RELAY_SEQ = 0
RELAY_NEXT_MEMBER_ID = 2
RELAY_CLIENTS_BY_NONCE: dict[bytes, int] = {}
RELAY_SOCKETS: dict[int, web.WebSocketResponse] = {}


# ---------------------------------------------------------------------------
# SSEncDec 6-bit codec
# ---------------------------------------------------------------------------

def _char_to_key(ch: str) -> int:
    v = ord(ch)
    if v >= 128:
        v -= 256
    if v == 45:
        return 63
    if v == 95:
        return 62
    if v > 57:
        if v > 90:
            return v - 97
        return v - 39
    return v + 4


def decode_blob(blob: str) -> str:
    n = len(blob)
    out_len = (6 * n) >> 3
    out = bytearray(out_len)
    idx = 0
    bit_pos = 8
    for ch in blob:
        key = _char_to_key(ch)
        out[idx] = (out[idx] | ((key & 0xFFFFFFFF) << (8 - bit_pos))) & 0xFF
        if bit_pos <= 6:
            if idx < out_len - 1:
                idx += 1
                out[idx] = (out[idx] | (key >> bit_pos)) & 0xFF
                bit_pos += 2
        else:
            bit_pos -= 6
    return out.rstrip(b"\x00").decode("utf-8", errors="replace")


def parse_pipe_kv(tokens: list[str]) -> dict[str, str]:
    result = {}
    i = 0
    while i + 1 < len(tokens):
        k, v = tokens[i], tokens[i + 1]
        if k:
            result[k] = v
        i += 2
    return result


# ---------------------------------------------------------------------------
# Database (Turso HTTP /v2/pipeline when configured, else local SQLite)
# ---------------------------------------------------------------------------

def _use_turso() -> bool:
    return bool(TURSO_URL and TURSO_TOKEN)


def _turso_arg(val) -> dict:
    if val is None:
        return {"type": "null"}
    if isinstance(val, int):
        return {"type": "integer", "value": str(val)}
    if isinstance(val, float):
        return {"type": "float", "value": val}
    return {"type": "text", "value": str(val)}


def _turso_val(cell: dict):
    t = cell.get("type")
    if t == "null":
        return None
    if t == "integer":
        return int(cell.get("value", 0))
    if t == "float":
        return float(cell.get("value", 0.0))
    return cell.get("value", "")


async def _turso_pipeline(statements: list[tuple[str, tuple]]) -> list[dict]:
    global TURSO_SESSION
    if TURSO_SESSION is None or TURSO_SESSION.closed:
        TURSO_SESSION = aiohttp.ClientSession()
    reqs = []
    for sql, args in statements:
        reqs.append({
            "type": "execute",
            "stmt": {"sql": sql, "args": [_turso_arg(a) for a in args]},
        })
    reqs.append({"type": "close"})
    headers = {"Authorization": f"Bearer {TURSO_TOKEN}", "Content-Type": "application/json"}
    async with TURSO_SESSION.post(f"{TURSO_URL}/v2/pipeline", json={"requests": reqs}, headers=headers, timeout=15) as resp:
        data = await resp.json()
        return data.get("results", [])


async def db_query(sql: str, args: tuple = ()) -> list[tuple]:
    if _use_turso():
        res = await _turso_pipeline([(sql, args)])
        if not res or res[0].get("type") != "ok":
            return []
        rows = res[0]["response"]["result"].get("rows", [])
        return [tuple(_turso_val(c) for c in r) for r in rows]
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(sql, args)
    rows = cur.fetchall()
    conn.close()
    return rows


async def db_exec(sql: str, args: tuple = ()) -> int | None:
    if _use_turso():
        res = await _turso_pipeline([(sql, args)])
        if not res or res[0].get("type") != "ok":
            return None
        lid = res[0]["response"]["result"].get("last_insert_rowid")
        return int(lid) if lid is not None else None
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(sql, args)
    lid = cur.lastrowid
    conn.commit()
    conn.close()
    return lid


async def init_db_async() -> None:
    stmts = [
        ("""CREATE TABLE IF NOT EXISTS accounts (
            uid INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT DEFAULT '',
            country TEXT DEFAULT 'US',
            nickname TEXT DEFAULT '',
            created_at INTEGER NOT NULL
        )""", ()),
        ("""CREATE TABLE IF NOT EXISTS friends (
            uid INTEGER NOT NULL,
            friend_uid INTEGER NOT NULL,
            status INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (uid, friend_uid)
        )""", ()),
        ("""CREATE TABLE IF NOT EXISTS leaderboards (
            uid INTEGER NOT NULL,
            board_id INTEGER NOT NULL DEFAULT 0,
            score INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (uid, board_id)
        )""", ()),
        ("""CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_uid INTEGER NOT NULL,
            sender_name TEXT NOT NULL,
            target_name TEXT NOT NULL,
            msg_type INTEGER NOT NULL DEFAULT 8,
            title TEXT DEFAULT '',
            body TEXT DEFAULT '',
            created_at INTEGER NOT NULL
        )""", ()),
    ]
    if _use_turso():
        await _turso_pipeline(stmts)
        print(f"[DB] Connected to Turso: {TURSO_URL}", flush=True)
        return
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    for sql, _ in stmts:
        cur.execute(sql)
    conn.commit()
    conn.close()


def init_db() -> None:
    if _use_turso():
        return
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            uid INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT DEFAULT '',
            country TEXT DEFAULT 'US',
            nickname TEXT DEFAULT '',
            created_at INTEGER NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS friends (
            uid INTEGER NOT NULL,
            friend_uid INTEGER NOT NULL,
            status INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (uid, friend_uid)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS leaderboards (
            uid INTEGER NOT NULL,
            board_id INTEGER NOT NULL DEFAULT 0,
            score INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (uid, board_id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_uid INTEGER NOT NULL,
            sender_name TEXT NOT NULL,
            target_name TEXT NOT NULL,
            msg_type INTEGER NOT NULL DEFAULT 8,
            title TEXT DEFAULT '',
            body TEXT DEFAULT '',
            created_at INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _prune_online() -> list[str]:
    now = time.monotonic()
    stale = [u for u, ts in ONLINE_USERS.items() if now - ts > 180.0]
    for u in stale:
        ONLINE_USERS.pop(u, None)
    return list(ONLINE_USERS.keys())


async def handle_xplayer_command(raw: str, host: str) -> str:
    tokens = raw.split("|")
    if len(tokens) < 2:
        return "f|0|r|e|40|"
    kind = tokens[0]
    try:
        func_id = int(tokens[1])
    except ValueError:
        return "f|0|r|e|40|"
    kv = parse_pipe_kv(tokens[2:])
    now = int(time.time())

    if func_id == 11:  # Register
        username = kv.get("u", "").strip()
        password = kv.get("p", "")
        if not username or not password:
            return "f|11|r|e|-100|"
        rows = await db_query("SELECT uid FROM accounts WHERE username = ?", (username,))
        if rows:
            return f"f|11|r|e|48|u|{username}|"
        uid = await db_exec(
            "INSERT INTO accounts (username, password, email, country, nickname, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (username, password, kv.get("e", ""), kv.get("c", "US"), username, now),
        )
        return f"f|11|r|s|u|{uid}|"

    if func_id == 15:  # Login (auto-registers if new)
        username = kv.get("u", "").strip()
        password = kv.get("p", "")
        if not username:
            return "f|15|r|e|42|"
        rows = await db_query("SELECT uid, password, nickname FROM accounts WHERE username = ?", (username,))
        if not rows:
            uid = await db_exec(
                "INSERT INTO accounts (username, password, email, country, nickname, created_at) VALUES (?, ?, '', 'US', ?, ?)",
                (username, password, username, now),
            )
            ONLINE_USERS[username] = time.monotonic()
            return f"f|15|r|s|u|{uid}|t|{now}|un|{username}|n|{username}|"
        uid, db_pass, nickname = rows[0]
        if db_pass != password:
            return "f|15|r|e|43|"
        ONLINE_USERS[nickname or username] = time.monotonic()
        return f"f|15|r|s|u|{uid}|t|{now}|un|{username}|n|{nickname or username}|"

    if func_id == 16:
        return f"f|16|r|s|x|{now}|"
    if func_id == 17:
        uid = kv.get("u", "")
        if uid:
            rows = await db_query("SELECT username, nickname FROM accounts WHERE uid = ? OR username = ?", (uid, uid))
            if rows:
                ONLINE_USERS.pop(rows[0][1] or rows[0][0], None)
        return "f|17|r|s|"
    if func_id in (107, 108):
        addr = host if ":" in host else f"{host}:443"
        return f"f|{func_id}|r|s|{addr}|"
    if func_id == 81:
        uid = kv.get("u", "1")
        rows = await db_query("SELECT username, nickname, country FROM accounts WHERE uid = ? OR username = ?", (uid, uid))
        if rows:
            return f"f|81|r|s|u|{uid}|un|{rows[0][0]}|n|{rows[0][1] or rows[0][0]}|c|{rows[0][2]}|"
        return f"f|81|r|s|u|{uid}|"
    if func_id == 61:  # GetUserFriends (friends + all currently online players)
        uid_str = kv.get("u", "0")
        online_names = _prune_online()
        entries: dict[str, tuple[str, int]] = {}
        try:
            uid_int = int(uid_str)
        except ValueError:
            uid_int = 0
        self_rows = await db_query("SELECT username, nickname FROM accounts WHERE uid = ?", (uid_int,))
        self_name = (self_rows[0][1] or self_rows[0][0]) if self_rows else ""
        friend_rows = await db_query(
            "SELECT a.uid, a.username, a.nickname FROM friends f JOIN accounts a ON a.uid = f.friend_uid WHERE f.uid = ?",
            (uid_int,),
        )
        for fuid, funame, fnick in friend_rows:
            dname = fnick or funame
            if dname and dname != self_name:
                entries[dname] = (str(fuid), 1 if dname in online_names else 0)
        for oname in online_names:
            if oname and oname != self_name and oname not in entries:
                entries[oname] = ("0", 1)
        parts = [f"f|61|r|s|c|{len(entries)}|"]
        for idx, (dname, (fuid, st)) in enumerate(entries.items()):
            parts.append(f"u{idx}|{fuid}|n{idx}|{dname}|s{idx}|{st}|")
        return "".join(parts)
    if func_id == 63:  # AddUserFriend
        uid_str = kv.get("u", "0")
        target = kv.get("n", kv.get("t", "")).strip()
        if target:
            trows = await db_query("SELECT uid FROM accounts WHERE username = ? OR nickname = ?", (target, target))
            if trows:
                try:
                    await db_exec("INSERT OR IGNORE INTO friends (uid, friend_uid, status) VALUES (?, ?, 1)", (int(uid_str), int(trows[0][0])))
                except ValueError:
                    pass
        return "f|63|r|s|"
    if func_id == 65:  # RemoveUserFriend
        uid_str = kv.get("u", "0")
        target = kv.get("n", kv.get("t", "")).strip()
        if target:
            trows = await db_query("SELECT uid FROM accounts WHERE username = ? OR nickname = ?", (target, target))
            if trows:
                try:
                    await db_exec("DELETE FROM friends WHERE uid = ? AND friend_uid = ?", (int(uid_str), int(trows[0][0])))
                except ValueError:
                    pass
        return "f|65|r|s|"
    if func_id == 91:  # SendOnlineMessage (game invite)
        uid_str = kv.get("u", "0")
        target = kv.get("d", kv.get("n", "")).strip()
        title = kv.get("t", "title")
        body = kv.get("m", "")
        if target:
            srows = await db_query("SELECT username, nickname FROM accounts WHERE uid = ?", (uid_str,))
            sname = (srows[0][1] or srows[0][0]) if srows else uid_str
            try:
                await db_exec(
                    "INSERT INTO messages (sender_uid, sender_name, target_name, msg_type, title, body, created_at) VALUES (?, ?, ?, 8, ?, ?, ?)",
                    (int(uid_str) if uid_str.isdigit() else 0, sname, target, title, body, now),
                )
            except Exception:
                pass
        return "f|91|r|s|"
    if func_id in (73, 74, 75, 110, 111, 112):
        return f"f|{func_id}|r|s|c|0|"
    return f"{kind}|{func_id}|r|s|"


# ---------------------------------------------------------------------------
# HTTP handlers
# ---------------------------------------------------------------------------

async def handle_health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "service": "dh2net", "host": PUBLIC_HOST})


async def handle_server_config(request: web.Request) -> web.Response:
    host = request.headers.get("Host") or PUBLIC_HOST
    plain = os.environ.get("DH2_LOCAL_PLAIN") == "1"
    http_scheme = "http" if plain else "https"
    ws_scheme = "ws" if plain else "wss"
    base = f"{http_scheme}://{host}"
    reply = (
        "f|1|r|s|"
        f"XplayerURL|{base}/ope/GenericXPlayer_v1.php|"
        "type|1|XPPHPVerNo|4|"
        f"XPlayMPURL|{ws_scheme}://{host}/ws/lobby|"
        f"XplayDWURL|{base}/|"
        f"ChatServer|{host}|ChatDomain|{host}|ChatRoomDomain|conference.{host}|"
        "min|1.0.0|latest|1.1.0|configured|1|"
    )
    return web.Response(text=reply)


async def handle_xplayer(request: web.Request) -> web.Response:
    host = request.headers.get("Host") or PUBLIC_HOST
    query = request.query_string
    if request.method == "POST":
        body = await request.text()
        if body:
            query = body
    params = urllib.parse.parse_qs(query, keep_blank_values=True)
    blob = params.get("b", [""])[0]
    if blob:
        raw = decode_blob(blob)
        resp = await handle_xplayer_command(raw, host)
        print(f"[XPLAYER] req={raw!r} -> resp={resp!r}", flush=True)
        return web.Response(text=resp)
    return web.Response(text="f|0|r|s|")


# ---------------------------------------------------------------------------
# WebSocket Lobby (/ws/lobby)
# ---------------------------------------------------------------------------

def pack_lobby(msg_type: int, payload: bytes = b"") -> bytes:
    body = bytes([1, 2]) + struct.pack(">i", msg_type) + payload
    return struct.pack(">H", len(body)) + body


def _pack_str(text: str) -> bytes:
    raw = text.encode("utf-8", errors="replace")
    return struct.pack(">h", len(raw)) + raw


def _read_str(buf: bytes, off: int) -> tuple[str, int]:
    if off + 2 > len(buf):
        return "", off
    n = struct.unpack(">h", buf[off : off + 2])[0]
    off += 2
    if n <= 0 or off + n > len(buf):
        return "", min(len(buf), off + max(0, n))
    return buf[off : off + n].rstrip(b"\x00").decode("utf-8", errors="replace"), off + n


def _read_blob(buf: bytes, off: int) -> tuple[bytes, int]:
    if off + 2 > len(buf):
        return b"", off
    n = struct.unpack(">h", buf[off : off + 2])[0]
    off += 2
    if n <= 0 or off + n > len(buf):
        return b"", min(len(buf), off + max(0, n))
    return buf[off : off + n], off + n


async def ws_lobby(request: web.Request) -> web.WebSocketResponse:
    global NEXT_LOBBY_ID
    print(f"[WS-LOBBY] connect from {request.remote}", flush=True)
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    user_name = "player"
    lobby_id: int | None = None
    host_hdr = request.headers.get("Host") or PUBLIC_HOST

    async def send_msg(mt: int, pl: bytes = b""):
        await ws.send_bytes(pack_lobby(mt, pl))

    async def leave_current_lobby():
        nonlocal lobby_id
        if lobby_id and lobby_id in LOBBIES:
            room = LOBBIES[lobby_id]
            leaving = [m for m in room["members"] if m["ws"] is ws]
            room["members"] = [m for m in room["members"] if m["ws"] is not ws]
            if not room["members"]:
                LOBBIES.pop(lobby_id, None)
            elif leaving:
                room["name"] = room["members"][0]["name"]
                room["second"] = room["members"][0]["name"]
                push21 = _pack_str(room["name"]) + _pack_str(leaving[0]["name"])
                for m in list(room["members"]):
                    try:
                        await m["ws"].send_bytes(pack_lobby(21, push21))
                    except Exception:
                        pass
        lobby_id = None

    try:
        async for msg in ws:
            if msg.type != WSMsgType.BINARY:
                continue
            buf = msg.data
            off = 0
            while off + 2 <= len(buf):
                ln = struct.unpack(">H", buf[off : off + 2])[0]
                off += 2
                body = buf[off : off + ln]
                off += ln
                if len(body) < 6 or body[0] != 1 or body[1] != 2:
                    continue
                mt = struct.unpack(">i", body[2:6])[0]
                pl = body[6:]
                print(f"[WS-LOBBY] mt={mt} len={len(pl)} user={user_name}", flush=True)
                if mt == 1:
                    await send_msg(2)
                elif mt == 3:
                    await send_msg(4)
                elif mt == 5:
                    if len(pl) >= 6:
                        uname, _ = _read_str(pl, 4)
                        if uname:
                            rows = await db_query(
                                "SELECT username, nickname FROM accounts WHERE uid = ? OR username = ?",
                                (uname, uname),
                            )
                            row = rows[0] if rows else None
                            user_name = (row[1] or row[0]) if row else uname
                    ONLINE_USERS[user_name] = time.monotonic()
                    await send_msg(6, struct.pack(">i", 0))
                elif mt == 9:
                    if user_name and user_name != "player":
                        ONLINE_USERS[user_name] = time.monotonic()
                    await send_msg(10, struct.pack(">i", 0))
                elif mt == 11:
                    p = 0
                    name, p = _read_str(pl, p)
                    _flag = pl[p] if p < len(pl) else 0
                    closed = pl[p + 1] if p + 1 < len(pl) else 0
                    p += 2
                    max_p = struct.unpack(">h", pl[p : p + 2])[0] if p + 2 <= len(pl) else 4
                    p += 2
                    attr, p = _read_blob(pl, p)
                    param, _ = _read_blob(pl, p)
                    if name:
                        user_name = name
                    lid = NEXT_LOBBY_ID
                    NEXT_LOBBY_ID += 1
                    LOBBIES[lid] = {
                        "id": lid,
                        "name": user_name,
                        "second": user_name,
                        "closed": closed,
                        "launched": False,
                        "max_players": max_p or 4,
                        "attr_blob": attr,
                        "members": [{"name": user_name, "param": param, "ws": ws}],
                    }
                    lobby_id = lid
                    await send_msg(12, struct.pack(">ii", 0, lid))
                elif mt in (13, 96):
                    rooms = list(LOBBIES.values())
                    out = bytearray(struct.pack(">ii", 0, len(rooms)))
                    for r in rooms:
                        out.extend(struct.pack(">i", r["id"]))
                        out.extend(_pack_str(r["name"]))
                        out.extend(_pack_str(r["second"]))
                        out.extend(bytes([1, r["closed"] & 0xFF, len(r["members"]) & 0xFF, r["max_players"] & 0xFF]))
                        out.extend(struct.pack(">ii", 0, 0))
                        ab = r["attr_blob"]
                        out.extend(struct.pack(">h", len(ab)) + ab)
                    await send_msg(97 if mt == 96 else 14, bytes(out))
                elif mt == 15:
                    lid = struct.unpack(">i", pl[0:4])[0] if len(pl) >= 4 else 1
                    param, _ = _read_blob(pl, 5)
                    room = LOBBIES.get(lid) or next(iter(LOBBIES.values()), None)
                    if room is None:
                        await send_msg(16, struct.pack(">i", -1))
                        continue
                    lobby_id = room["id"]
                    if not any(m["ws"] is ws for m in room["members"]):
                        room["members"].append({"name": user_name, "param": param, "ws": ws})
                    members = room["members"]
                    is_launched = bool(room.get("launched", False))
                    rep = bytearray(struct.pack(">ii", 0, len(members)))
                    for m in members:
                        rep.extend(_pack_str(m["name"]))
                        rep.extend(_pack_str(m["name"]))
                        rep.append(0)
                        rep.extend(_pack_str(m["param"].decode("utf-8", errors="replace")))
                    await send_msg(16, bytes(rep))
                    push_join = _pack_str(user_name) + _pack_str(user_name) + b"\x00" + _pack_str(param.decode("utf-8", errors="replace"))
                    push_join_mt = 47 if is_launched else 17
                    for m in members:
                        if m["ws"] is not ws:
                            await m["ws"].send_bytes(pack_lobby(push_join_mt, push_join))
                    if is_launched:
                        gs = host_hdr.split(":")[0].encode("utf-8")
                        gs_port = int(os.environ.get("PORT", "8085")) if os.environ.get("DH2_LOCAL_PLAIN") == "1" else 443
                        gs_payload = struct.pack(">h", len(gs)) + gs + struct.pack(">hhi", gs_port, gs_port, 1)
                        await send_msg(44, b"")
                        await send_msg(50, gs_payload)
                        print(f"[WS-LOBBY] -> late joiner {user_name} pushed 44+50 gs={gs.decode()}:{gs_port}", flush=True)
                elif mt == 19:
                    await leave_current_lobby()
                    try:
                        await send_msg(20, struct.pack(">i", 0))
                    except Exception:
                        pass
                elif mt == 33:
                    await send_msg(34, struct.pack(">i", 0))
                elif mt == 36:
                    await send_msg(37, struct.pack(">i", 0))
                elif mt == 39:
                    await send_msg(40, struct.pack(">i", 0))
                elif mt == 42:
                    await send_msg(43, struct.pack(">i", 0))
                    gs = host_hdr.split(":")[0].encode("utf-8")
                    gs_port = int(os.environ.get("PORT", "8085")) if os.environ.get("DH2_LOCAL_PLAIN") == "1" else 443
                    gs_payload = struct.pack(">h", len(gs)) + gs + struct.pack(">hhi", gs_port, gs_port, 1)
                    room = LOBBIES.get(lobby_id) if lobby_id else None
                    if room is not None:
                        room["launched"] = True
                    targets = [m["ws"] for m in room["members"]] if room else [ws]
                    for t in targets:
                        if t is not ws:
                            await t.send_bytes(pack_lobby(44, b""))
                        await t.send_bytes(pack_lobby(50, gs_payload))
    finally:
        await leave_current_lobby()
    return ws


# ---------------------------------------------------------------------------
# WebSocket Relay (/ws/relay)
# ---------------------------------------------------------------------------

async def ws_relay(request: web.Request) -> web.WebSocketResponse:
    global RELAY_SEQ, RELAY_NEXT_MEMBER_ID
    print(f"[WS-RELAY] connect from {request.remote}", flush=True)
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    my_mid: int | None = None

    try:
        async for msg in ws:
            if msg.type != WSMsgType.BINARY:
                continue
            req = msg.data
            if len(req) < 8 or req[0:4] != b"\xe5\xbe\x00\xb0":
                continue
            pkt_type = req[6]
            if pkt_type == 1 and len(req) >= 20:
                server_ms = int(time.monotonic() * 1000) & 0x7FFFFFFF
                await ws.send_bytes(req[0:12] + struct.pack("<i", server_ms) + req[16:20])
            elif pkt_type == 5 and len(req) >= 17 and req[8] == 0:
                nonce = req[17:25] if len(req) >= 25 else req[8:17]
                my_mid = RELAY_CLIENTS_BY_NONCE.get(nonce)
                if my_mid is None:
                    my_mid = RELAY_NEXT_MEMBER_ID
                    RELAY_NEXT_MEMBER_ID += 1
                    RELAY_CLIENTS_BY_NONCE[nonce] = my_mid
                RELAY_SOCKETS[my_mid] = ws
                if os.environ.get("DH2_LOCAL_PLAIN") == "1":
                    print(f"[WS-RELAY] handshake type=5 mid={my_mid} peers={list(RELAY_SOCKETS.keys())}", flush=True)
                await ws.send_bytes(req[0:8] + b"\x01" + struct.pack("<ii", 1, my_mid) + req[17:])
            elif pkt_type == 5:
                for tid, tws in list(RELAY_SOCKETS.items()):
                    if tid != my_mid:
                        try:
                            await tws.send_bytes(req)
                        except Exception:
                            pass
            elif pkt_type == 7:
                await ws.send_bytes(b"\xe5\xbe\x00\xb0\x08\x00\x08\x00")
            elif pkt_type == 6 and len(req) >= 22:
                seq, ack, bits, matching_id, conn_id = struct.unpack("<HHIHH", req[8:20])
                sender_mid = my_mid or matching_id
                msg_data = req[21:]
                verbose_relay = os.environ.get("DH2_LOCAL_PLAIN") == "1" and len(msg_data) > 1
                for tid, tws in list(RELAY_SOCKETS.items()):
                    if tid != sender_mid and (conn_id <= 1 or conn_id == tid):
                        if verbose_relay:
                            print(f"[WS-RELAY] fwd {sender_mid}->{tid} seq={seq} ack={ack} mask={req[20]} len={len(req)}", flush=True)
                        fwd_pl = struct.pack("<HHIHHB", seq, ack, bits, sender_mid, tid, req[20]) + msg_data
                        await tws.send_bytes(b"\xe5\xbe\x00\xb0" + struct.pack("<HBB", 8 + len(fwd_pl), 6, 0) + fwd_pl)
    finally:
        if my_mid is not None:
            RELAY_SOCKETS.pop(my_mid, None)
            if os.environ.get("DH2_LOCAL_PLAIN") == "1":
                print(f"[WS-RELAY] disconnect mid={my_mid}", flush=True)
    return ws


def create_app() -> web.Application:
    init_db()
    app = web.Application()

    async def _on_startup(_app: web.Application) -> None:
        await init_db_async()

    async def _on_cleanup(_app: web.Application) -> None:
        if TURSO_SESSION is not None and not TURSO_SESSION.closed:
            await TURSO_SESSION.close()

    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)
    app.router.add_get("/", handle_health)
    app.router.add_route("*", "/ope/ServerConfig.php", handle_server_config)
    app.router.add_route("*", "/ope/GenericXPlayer_v1.php", handle_xplayer)
    app.router.add_get("/ws/lobby", ws_lobby)
    app.router.add_get("/ws/relay", ws_relay)
    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8085"))
    host = os.environ.get("DH2_BIND_HOST", "0.0.0.0")
    web.run_app(create_app(), host=host, port=port)
