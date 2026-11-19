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
import os
import sqlite3
import struct
import time
import urllib.parse

from aiohttp import WSMsgType, web

DB_PATH = os.environ.get(
    "DH2_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "dh2_online.db"),
)
PUBLIC_HOST = os.environ.get("DH2_PUBLIC_HOST", "dh2net.onrender.com")

LOBBIES: dict[int, dict] = {}
NEXT_LOBBY_ID = 1

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
# SQLite
# ---------------------------------------------------------------------------

def init_db() -> None:
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
    conn.commit()
    conn.close()


def handle_xplayer_command(raw: str, host: str) -> str:
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
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT uid FROM accounts WHERE username = ?", (username,))
        if cur.fetchone() is not None:
            conn.close()
            return f"f|11|r|e|48|u|{username}|"
        cur.execute(
            "INSERT INTO accounts (username, password, email, country, nickname, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (username, password, kv.get("e", ""), kv.get("c", "US"), username, now),
        )
        uid = cur.lastrowid
        conn.commit()
        conn.close()
        return f"f|11|r|s|u|{uid}|"

    if func_id == 15:  # Login (auto-registers if new)
        username = kv.get("u", "").strip()
        password = kv.get("p", "")
        if not username:
            return "f|15|r|e|42|"
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT uid, password, nickname FROM accounts WHERE username = ?", (username,))
        row = cur.fetchone()
        if row is None:
            cur.execute(
                "INSERT INTO accounts (username, password, email, country, nickname, created_at) VALUES (?, ?, '', 'US', ?, ?)",
                (username, password, username, now),
            )
            uid = cur.lastrowid
            conn.commit()
            conn.close()
            return f"f|15|r|s|u|{uid}|t|{now}|un|{username}|n|{username}|"
        conn.close()
        uid, db_pass, nickname = row
        if db_pass != password:
            return "f|15|r|e|43|"
        return f"f|15|r|s|u|{uid}|t|{now}|un|{username}|n|{nickname or username}|"

    if func_id == 16:
        return f"f|16|r|s|x|{now}|"
    if func_id == 17:
        return "f|17|r|s|"
    if func_id in (107, 108):
        return f"f|{func_id}|r|s|{host}:443|"
    if func_id == 81:
        uid = kv.get("u", "1")
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT username, nickname, country FROM accounts WHERE uid = ? OR username = ?", (uid, uid))
        row = cur.fetchone()
        conn.close()
        if row:
            return f"f|81|r|s|u|{uid}|un|{row[0]}|n|{row[1] or row[0]}|c|{row[2]}|"
        return f"f|81|r|s|u|{uid}|"
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
    base = f"https://{host}"
    reply = (
        "f|1|r|s|"
        f"XplayerURL|{base}/ope/GenericXPlayer_v1.php|"
        "type|1|XPPHPVerNo|4|"
        f"XPlayMPURL|wss://{host}/ws/lobby|"
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
        return web.Response(text=handle_xplayer_command(raw, host))
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
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    user_name = "player"
    lobby_id: int | None = None
    host_hdr = request.headers.get("Host") or PUBLIC_HOST

    async def send_msg(mt: int, pl: bytes = b""):
        await ws.send_bytes(pack_lobby(mt, pl))

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
                if mt == 1:
                    await send_msg(2)
                elif mt == 3:
                    await send_msg(4)
                elif mt == 5:
                    if len(pl) >= 6:
                        uname, _ = _read_str(pl, 4)
                        if uname:
                            user_name = uname
                    await send_msg(6, struct.pack(">i", 0))
                elif mt == 9:
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
                    rep = bytearray(struct.pack(">ii", 0, len(members)))
                    for m in members:
                        rep.extend(_pack_str(m["name"]))
                        rep.extend(_pack_str(m["name"]))
                        rep.append(0)
                        rep.extend(_pack_str(m["param"].decode("utf-8", errors="replace")))
                    await send_msg(16, bytes(rep))
                    push17 = _pack_str(user_name) + _pack_str(user_name) + b"\x00" + _pack_str(param.decode("utf-8", errors="replace"))
                    for m in members:
                        if m["ws"] is not ws:
                            await m["ws"].send_bytes(pack_lobby(17, push17))
                elif mt == 19:
                    if lobby_id and lobby_id in LOBBIES:
                        LOBBIES[lobby_id]["members"] = [m for m in LOBBIES[lobby_id]["members"] if m["ws"] is not ws]
                        if not LOBBIES[lobby_id]["members"]:
                            LOBBIES.pop(lobby_id, None)
                    lobby_id = None
                    await send_msg(20, struct.pack(">i", 0))
                elif mt == 39:
                    await send_msg(40, struct.pack(">i", 0))
                elif mt == 42:
                    await send_msg(43, struct.pack(">i", 0))
                    gs = host_hdr.encode("utf-8")
                    gs_payload = struct.pack(">h", len(gs)) + gs + struct.pack(">hhi", 443, 443, 1)
                    room = LOBBIES.get(lobby_id) if lobby_id else None
                    targets = [m["ws"] for m in room["members"]] if room else [ws]
                    for t in targets:
                        if t is not ws:
                            await t.send_bytes(pack_lobby(44, b""))
                        await t.send_bytes(pack_lobby(50, gs_payload))
    finally:
        if lobby_id and lobby_id in LOBBIES:
            LOBBIES[lobby_id]["members"] = [m for m in LOBBIES[lobby_id]["members"] if m["ws"] is not ws]
            if not LOBBIES[lobby_id]["members"]:
                LOBBIES.pop(lobby_id, None)
    return ws


# ---------------------------------------------------------------------------
# WebSocket Relay (/ws/relay)
# ---------------------------------------------------------------------------

async def ws_relay(request: web.Request) -> web.WebSocketResponse:
    global RELAY_SEQ, RELAY_NEXT_MEMBER_ID
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
                await ws.send_bytes(req[0:8] + b"\x01" + struct.pack("<ii", 1, my_mid) + req[17:])
            elif pkt_type == 7:
                await ws.send_bytes(b"\xe5\xbe\x00\xb0\x08\x00\x08\x00")
            elif pkt_type == 6 and len(req) >= 22:
                seq, _ack, _bits, matching_id, _conn_id = struct.unpack("<HHIHH", req[8:20])
                sender_mid = my_mid or matching_id
                msg_data = req[21:]
                if len(msg_data) > 1 or (len(msg_data) == 1 and msg_data[0] != 0):
                    for tid, tws in list(RELAY_SOCKETS.items()):
                        if tid != sender_mid:
                            RELAY_SEQ = (RELAY_SEQ + 1) & 0xFFFF or 1
                            fwd_pl = struct.pack("<HHIHHB", RELAY_SEQ, 0, 0, sender_mid, tid, req[20]) + msg_data
                            await tws.send_bytes(b"\xe5\xbe\x00\xb0" + struct.pack("<HBB", 8 + len(fwd_pl), 6, 0) + fwd_pl)
                RELAY_SEQ = (RELAY_SEQ + 1) & 0xFFFF or 1
                ack_pl = struct.pack("<HHIHHBB", RELAY_SEQ, seq, 0xFFFFFFFF, 1, sender_mid, 0, 0)
                await ws.send_bytes(b"\xe5\xbe\x00\xb0" + struct.pack("<HBB", 8 + len(ack_pl), 6, 0) + ack_pl)
    finally:
        if my_mid is not None:
            RELAY_SOCKETS.pop(my_mid, None)
    return ws


def create_app() -> web.Application:
    init_db()
    app = web.Application()
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
