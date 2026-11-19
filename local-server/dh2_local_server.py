#!/usr/bin/env python3
"""
Local Gameloft Live + Lobby server for Dungeon Hunter 2 (dh2_win_window.exe).
- HTTP Web API on 127.0.0.1:8080 (/ope/ServerConfig.php, /ope/GenericXPlayer_v1.php)
- TCP Lobby server on 127.0.0.1:8081 (2-byte BE length + DataPacketLobby)
- SQLite database (dh2_online.db) for accounts, friends, messages, leaderboards
"""

import argparse
import os
import socket
import socketserver
import sqlite3
import struct
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dh2_online.db")
DB_LOCK = threading.Lock()

LOBBY_LOCK = threading.Lock()
LOBBIES = {}  # lobby_id -> dict(id, name, host_uid, max_players, players, ...)
NEXT_LOBBY_ID = 1


# ---------------------------------------------------------------------------
# SSEncDec 6-bit codec (matches tinyxml-and-c-libs/src/ssencdec.cpp)
# ---------------------------------------------------------------------------

def _char_to_key(ch: str) -> int:
    v = ord(ch)
    if v >= 128:
        v -= 256
    if v == 45:  # '-'
        return 63
    if v == 95:  # '_'
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
        k = tokens[i]
        v = tokens[i + 1]
        if k:
            result[k] = v
        i += 2
    return result


# ---------------------------------------------------------------------------
# SQLite Database
# ---------------------------------------------------------------------------

def init_db() -> None:
    with DB_LOCK:
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
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_uid INTEGER NOT NULL,
                to_uid INTEGER NOT NULL,
                msg_type INTEGER NOT NULL DEFAULT 0,
                label TEXT DEFAULT '',
                body TEXT DEFAULT '',
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
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


# ---------------------------------------------------------------------------
# HTTP Web API (ServerConfig.php + GenericXPlayer_v1.php)
# ---------------------------------------------------------------------------

def handle_xplayer_command(raw: str, http_host: str, lobby_host: str, lobby_port: int) -> str:
    tokens = [t for t in raw.split("|")]
    # Expected: f|<id>|i|<ggi>|...
    if len(tokens) < 2:
        return "f|0|r|e|40|"

    kind = tokens[0]
    try:
        func_id = int(tokens[1])
    except ValueError:
        return "f|0|r|e|40|"

    kv = parse_pipe_kv(tokens[2:])
    now = int(time.time())

    # 11 (0x0b): Register
    if func_id == 11:
        username = kv.get("u", "").strip()
        password = kv.get("p", "")
        email = kv.get("e", "")
        country = kv.get("c", "US")
        if not username or not password:
            return "f|11|r|e|-100|"
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT uid FROM accounts WHERE username = ?", (username,))
            if cur.fetchone() is not None:
                conn.close()
                return f"f|11|r|e|48|u|{username}|"
            cur.execute(
                "INSERT INTO accounts (username, password, email, country, nickname, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (username, password, email, country, username, now),
            )
            uid = cur.lastrowid
            conn.commit()
            conn.close()
        print(f"[HTTP] Registered account uid={uid} user={username}")
        return f"f|11|r|s|u|{uid}|"

    # 15 (0x0f): Login (auto-registers if username does not exist yet)
    if func_id == 15:
        username = kv.get("u", "").strip()
        password = kv.get("p", "")
        if not username:
            return "f|15|r|e|42|"
        with DB_LOCK:
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
                print(f"[HTTP] Auto-registered & Login ok uid={uid} user={username}")
                return f"f|15|r|s|u|{uid}|t|{now}|un|{username}|n|{username}|"
            conn.close()
        uid, db_pass, nickname = row
        if db_pass != password:
            return "f|15|r|e|43|"  # invalid password
        nick = nickname or username
        print(f"[HTTP] Login ok uid={uid} user={username}")
        return f"f|15|r|s|u|{uid}|t|{now}|un|{username}|n|{nick}|"

    # 16 (0x10): Keep-Alive
    if func_id == 16:
        return f"f|16|r|s|x|{now}|"

    # 17 (0x11): Logout
    if func_id == 17:
        return "f|17|r|s|"

    # 107 (0x6b) / 108 (0x6c): GetLobbyServer -> host:port (sem http://)
    if func_id in (107, 108):
        return f"f|{func_id}|r|s|{lobby_host}:{lobby_port}|"

    # 81 (0x51): GetUserInfo
    if func_id == 81:
        uid = kv.get("u", "1")
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT username, nickname, country FROM accounts WHERE uid = ? OR username = ?", (uid, uid))
            row = cur.fetchone()
            conn.close()
        if row:
            uname, nick, country = row
            return f"f|81|r|s|u|{uid}|un|{uname}|n|{nick or uname}|c|{country}|"
        return f"f|81|r|s|u|{uid}|"

    # 73 (0x49): GetFriendsList (empty list)
    if func_id == 73:
        return "f|73|r|s|c|0|"

    # 74 / 75: Messages
    if func_id in (74, 75):
        return f"f|{func_id}|r|s|c|0|"

    # 110 / 111 / 112: Leaderboard
    if func_id in (110, 111, 112):
        return f"f|{func_id}|r|s|c|0|"

    # Generic fallback success for other profile/EULA/product queries
    print(f"[HTTP] Unhandled func_id={func_id} raw={raw}")
    return f"{kind}|{func_id}|r|s|"


class DH2HttpHandler(BaseHTTPRequestHandler):
    server_version = "DH2Local/1.0"

    def log_message(self, format, *args):
        print(f"[HTTP] {self.address_string()} - {format % args}")

    def _send_text(self, text: str, status: int = 200):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _handle_request(self, body_bytes: bytes = b""):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        http_host = self.server.http_host
        http_port = self.server.http_port
        lobby_host = self.server.lobby_host
        lobby_port = self.server.lobby_port

        if path.endswith("ServerConfig.php"):
            cfg = (
                f"f|1|r|s|"
                f"XplayerURL|http://{http_host}:{http_port}/ope/GenericXPlayer_v1.php|"
                f"type|1|"
                f"XPPHPVerNo|4|"
                f"XPlayMPURL|http://{lobby_host}:{lobby_port}/|"
                f"XplayDWURL|http://{http_host}:{http_port}/|"
                f"ChatServer|{http_host}|"
                f"ChatDomain|{http_host}|"
                f"ChatRoomDomain|conference.{http_host}|"
                f"min|1.0.0|"
                f"latest|1.1.0|"
                f"configured|1|"
            )
            print(f"[HTTP] ServerConfig.php -> {cfg}")
            self._send_text(cfg)
            return

        query = parsed.query
        if not query and body_bytes:
            query = body_bytes.decode("utf-8", errors="replace")

        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        blob = params.get("b", [""])[0]
        if blob:
            raw = decode_blob(blob)
            print(f"[HTTP] Decoded b=: {raw}")
            resp = handle_xplayer_command(raw, f"{http_host}:{http_port}", lobby_host, lobby_port)
            print(f"[HTTP] Reply: {resp}")
            self._send_text(resp)
            return

        self._send_text("f|0|r|s|")

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        self._handle_request(body)


# ---------------------------------------------------------------------------
# TCP Lobby Server (ConnectionLobby / DataPacketLobby)
# ---------------------------------------------------------------------------

def pack_lobby_message(msg_type: int, payload: bytes = b"") -> bytes:
    body = bytes([1, 2]) + struct.pack(">i", msg_type) + payload
    return struct.pack(">H", len(body)) + body


def read_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _pack_lobby_str(text: str) -> bytes:
    raw = text.encode("utf-8", errors="replace")
    return struct.pack(">h", len(raw)) + raw


def _read_lobby_str(buf: bytes, off: int) -> tuple[str, int]:
    if off + 2 > len(buf):
        return "", off
    n = struct.unpack(">h", buf[off : off + 2])[0]
    off += 2
    if n <= 0 or off + n > len(buf):
        return "", min(len(buf), off + max(0, n))
    val = buf[off : off + n].rstrip(b"\x00").decode("utf-8", errors="replace")
    return val, off + n


def _read_lobby_blob(buf: bytes, off: int) -> tuple[bytes, int]:
    if off + 2 > len(buf):
        return b"", off
    n = struct.unpack(">h", buf[off : off + 2])[0]
    off += 2
    if n <= 0 or off + n > len(buf):
        return b"", min(len(buf), off + max(0, n))
    return buf[off : off + n], off + n


class DH2LobbyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = self.client_address
        self.user_name = f"player_{peer[1]}"
        self.lobby_id: int | None = None
        self.player_param: bytes = b""
        print(f"[LOBBY] Connected: {peer}")
        try:
            while True:
                hdr = read_exact(self.request, 2)
                if not hdr:
                    break
                length = struct.unpack(">H", hdr)[0]
                if length == 0 or length > 8192:
                    print(f"[LOBBY] Invalid packet len={length} from {peer}")
                    break
                body = read_exact(self.request, length)
                if not body:
                    break

                if len(body) >= 6 and body[0] == 1 and body[1] == 2:
                    msg_type = struct.unpack(">i", body[2:6])[0]
                    payload = body[6:]
                    self._dispatch(msg_type, payload)
                else:
                    print(f"[LOBBY] Legacy/raw packet ({len(body)}B): {body.hex()}")
        except OSError as exc:
            print(f"[LOBBY] Socket error {peer}: {exc}")
        finally:
            self._leave_current_lobby()
            print(f"[LOBBY] Disconnected: {peer}")

    def _send(self, msg_type: int, payload: bytes = b""):
        pkt = pack_lobby_message(msg_type, payload)
        self.request.sendall(pkt)

    def _leave_current_lobby(self):
        with LOBBY_LOCK:
            if self.lobby_id is None:
                return
            room = LOBBIES.get(self.lobby_id)
            if room is not None:
                room["members"] = [m for m in room["members"] if m["handler"] is not self]
                if not room["members"]:
                    LOBBIES.pop(self.lobby_id, None)
            self.lobby_id = None

    def _dispatch(self, msg_type: int, payload: bytes):
        global NEXT_LOBBY_ID
        print(f"[LOBBY] <- type={msg_type} payload={payload.hex()}")

        if msg_type == 1:  # EstablishConnection -> 2
            self._send(2)
        elif msg_type == 3:  # FinishConnection -> 4
            self._send(4)
        elif msg_type == 9:  # KeepAlive -> 10
            self._send(10, struct.pack(">i", 0))
        elif msg_type == 5:  # LobbyLogin -> 6 (result=0)
            self._send(6, struct.pack(">i", 0))
        elif msg_type == 11:  # CreateLobby -> 12 (result=0, lobby_id)
            off = 0
            name, off = _read_lobby_str(payload, off)
            flag = payload[off] if off < len(payload) else 1
            off += 1
            closed = payload[off] if off < len(payload) else 0
            off += 1
            max_players = struct.unpack(">i", payload[off : off + 4])[0] if off + 4 <= len(payload) else 4
            off += 4
            attr_blob, off = _read_lobby_blob(payload, off)
            param_blob, off = _read_lobby_blob(payload, off)
            if name:
                self.user_name = name
            self.player_param = param_blob
            with LOBBY_LOCK:
                lid = NEXT_LOBBY_ID
                NEXT_LOBBY_ID += 1
                LOBBIES[lid] = {
                    "id": lid,
                    "name": self.user_name,
                    "second": self.user_name,
                    "closed": closed,
                    "max_players": max_players or 4,
                    "attr_blob": attr_blob,
                    "host": self,
                    "members": [{"name": self.user_name, "param": param_blob, "handler": self}],
                }
                self.lobby_id = lid
            print(f"[LOBBY] Created room id={lid} host={self.user_name} max={max_players}")
            self._send(12, struct.pack(">ii", 0, lid))
        elif msg_type in (13, 96):  # GetLobbyList / WithGameParam -> 14
            with LOBBY_LOCK:
                rooms = list(LOBBIES.values())
            out = bytearray(struct.pack(">ii", 0, len(rooms)))
            for r in rooms:
                out.extend(struct.pack(">i", r["id"]))
                out.extend(_pack_lobby_str(r["name"]))
                out.extend(_pack_lobby_str(r["second"]))
                out.extend(bytes([1, r["closed"] & 0xFF, len(r["members"]) & 0xFF, r["max_players"] & 0xFF]))
                out.extend(struct.pack(">ii", 0, 0))
                ab = r["attr_blob"]
                out.extend(struct.pack(">h", len(ab)) + ab)
            self._send(14, bytes(out))
        elif msg_type in (52, 54, 97, 99):  # Other list queries
            reply_map = {52: 53, 54: 55, 97: 97, 99: 100}
            self._send(reply_map[msg_type], struct.pack(">ii", 0, 0))
        elif msg_type == 15:  # JoinLobby -> 16 + push 17 to host/members
            lid = struct.unpack(">i", payload[0:4])[0] if len(payload) >= 4 else 1
            off = 5
            param_blob, _ = _read_lobby_blob(payload, off)
            self.player_param = param_blob
            with LOBBY_LOCK:
                room = LOBBIES.get(lid) or (next(iter(LOBBIES.values()), None))
                if room is None:
                    self._send(16, struct.pack(">i", -1))
                    return
                self.lobby_id = room["id"]
                if not any(m["handler"] is self for m in room["members"]):
                    room["members"].append({"name": self.user_name, "param": param_blob, "handler": self})
                members = list(room["members"])
            # Reply 16 to joiner
            rep = bytearray(struct.pack(">ii", 0, len(members)))
            for m in members:
                rep.extend(_pack_lobby_str(m["name"]))
                rep.extend(_pack_lobby_str(m["name"]))
                rep.append(0)
                rep.extend(_pack_lobby_str(m["param"].decode("utf-8", errors="replace")))
            self._send(16, bytes(rep))
            # Push 17 (PushJoinLobbyUnlaunched) to other members
            push17 = bytearray()
            push17.extend(_pack_lobby_str(self.user_name))
            push17.extend(_pack_lobby_str(self.user_name))
            push17.append(0)
            push17.extend(_pack_lobby_str(param_blob.decode("utf-8", errors="replace")))
            for m in members:
                if m["handler"] is not self:
                    try:
                        m["handler"]._send(17, bytes(push17))
                    except OSError:
                        pass
        elif msg_type == 19:  # LeaveLobby -> 20
            self._leave_current_lobby()
            self._send(20, struct.pack(">i", 0))
        elif msg_type == 22:  # GetLobbyInfo -> 23
            self._send(23, struct.pack(">i", 0))
        elif msg_type == 24:  # KickOut -> 25
            self._send(25, struct.pack(">i", 0))
        elif msg_type == 33:  # SetGameParam -> 34
            self._send(34, struct.pack(">i", 0))
        elif msg_type == 36:  # SetUserParam -> 37
            self._send(37, struct.pack(">i", 0))
        elif msg_type == 39:  # SetPlayerStatus -> 40
            self._send(40, struct.pack(">i", 0))
        elif msg_type == 42:  # LaunchGame -> 43 + push 44 (joiners) + push 50 (GameserverAddr to all)
            self._send(43, struct.pack(">i", 0))
            pub_host = getattr(self.server, "public_host", "127.0.0.1").encode("utf-8")
            gs_payload = (
                struct.pack(">h", len(pub_host))
                + pub_host
                + struct.pack(">hhi", 8082, 8082, 1)
            )
            with LOBBY_LOCK:
                room = LOBBIES.get(self.lobby_id) if self.lobby_id is not None else None
                targets = [m["handler"] for m in room["members"]] if room else [self]
            for h in targets:
                try:
                    if h is not self:
                        h._send(44, b"")
                    h._send(50, gs_payload)
                except OSError:
                    pass
            print(f"[LOBBY] -> pushed GameserverAddr {pub_host.decode()}:8082 to {len(targets)} member(s)")
        elif msg_type == 45:  # RejoinLobby -> 46
            self._send(46, struct.pack(">i", 0))
        elif msg_type == 56:  # AutoMatch -> 57
            self._send(57, struct.pack(">i", 0))
        elif msg_type == 74:  # CancelAutoMatch -> 75
            self._send(75, struct.pack(">i", 0))
        elif msg_type == 101:  # GetPlayerCounter -> 102
            self._send(102, struct.pack(">ii", 0, len(LOBBIES)))
        elif msg_type == 103:  # JoinPredefinedLobby -> 104
            self._send(104, struct.pack(">i", 0))
        else:
            print(f"[LOBBY] Unhandled msg_type={msg_type}")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


RELAY_SEQ = 0
RELAY_NEXT_MEMBER_ID = 2
RELAY_CLIENTS_BY_NONCE: dict[bytes, int] = {}
RELAY_ENDPOINTS: dict[int, tuple[str, object]] = {}  # member_id -> ("tcp", sock) or ("udp", (sock, addr))
RELAY_PEER_TO_MEMBER: dict[tuple[str, int], int] = {}
RELAY_SEQ_LOCK = threading.Lock()


def get_or_assign_relay_member(nonce: bytes, peer: tuple[str, int], transport: str, endpoint: object) -> int:
    with RELAY_SEQ_LOCK:
        mid = RELAY_CLIENTS_BY_NONCE.get(nonce)
        if mid is None:
            global RELAY_NEXT_MEMBER_ID
            mid = RELAY_NEXT_MEMBER_ID
            RELAY_NEXT_MEMBER_ID += 1
            RELAY_CLIENTS_BY_NONCE[nonce] = mid
        RELAY_ENDPOINTS[mid] = (transport, endpoint)
        RELAY_PEER_TO_MEMBER[peer] = mid
        return mid


def _relay_send_raw(mid: int, pkt: bytes) -> None:
    ep = RELAY_ENDPOINTS.get(mid)
    if not ep:
        return
    kind, obj = ep
    try:
        if kind == "tcp":
            obj.sendall(pkt)
        else:
            sock, addr = obj
            sock.sendto(pkt, addr)
    except OSError:
        pass


def build_relay_reply(req: bytes, peer: tuple[str, int], transport: str, endpoint: object) -> bytes | None:
    global RELAY_SEQ
    if len(req) < 8 or req[0:4] != b"\xe5\xbe\x00\xb0":
        return None
    pkt_type = req[6]
    # type=1: COnline time sync (12 bytes: sendElapsed, serverElapsed, receiveElapsed)
    if pkt_type == 1 and len(req) >= 20:
        server_ms = int(time.monotonic() * 1000) & 0x7FFFFFFF
        return req[0:12] + struct.pack("<i", server_ms) + req[16:20]
    # type=5: CConnection handshake (0=Request -> 1=Response)
    if pkt_type == 5 and len(req) >= 17 and req[8] == 0:
        nonce = req[17:25] if len(req) >= 25 else req[8:17]
        member_id = get_or_assign_relay_member(nonce, peer, transport, endpoint)
        print(f"[RELAY] Assigned member_id={member_id} to {peer} ({transport})")
        return req[0:8] + b"\x01" + struct.pack("<ii", 1, member_id) + req[17:]
    # type=7: Transport KeepAlive -> type=8 KeepAlive ACK
    if pkt_type == 7:
        return b"\xe5\xbe\x00\xb0\x08\x00\x08\x00"
    # type=6: CPacketManager -> reply with ACK for seq + forward non-empty data to other clients
    if pkt_type == 6 and len(req) >= 22:
        seq, _ack, _ack_bits, matching_id, conn_id = struct.unpack("<HHIHH", req[8:20])
        msg_data = req[22:]
        sender_mid = RELAY_PEER_TO_MEMBER.get(peer, matching_id)
        with RELAY_SEQ_LOCK:
            RELAY_SEQ = (RELAY_SEQ + 1) & 0xFFFF or 1
            our_seq = RELAY_SEQ
            other_mids = [m for m in RELAY_ENDPOINTS if m != sender_mid]
        if len(msg_data) > 1 or (len(msg_data) == 1 and msg_data[0] != 0):
            print(f"[RELAY] Data from member={sender_mid} {len(msg_data)}B -> peers {other_mids}")
            for target_mid in other_mids:
                with RELAY_SEQ_LOCK:
                    RELAY_SEQ = (RELAY_SEQ + 1) & 0xFFFF or 1
                    fwd_seq = RELAY_SEQ
                fwd_payload = struct.pack("<HHIHHBB", fwd_seq, 0, 0xFFFFFFFF, 1, target_mid, req[20], 0) + msg_data
                fwd_pkt = b"\xe5\xbe\x00\xb0" + struct.pack("<HBB", 8 + len(fwd_payload), 6, 0) + fwd_payload
                _relay_send_raw(target_mid, fwd_pkt)
        # Send ACK back to sender (empty 4-bit slot terminator)
        ack_payload = struct.pack("<HHIHHBB", our_seq, seq, 0xFFFFFFFF, 1, sender_mid, 0, 0)
        return b"\xe5\xbe\x00\xb0" + struct.pack("<HBB", 8 + len(ack_payload), 6, 0) + ack_payload
    return None


class DH2RelayTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = self.client_address
        print(f"[RELAY-TCP] Connected: {peer}")
        buf = bytearray()
        try:
            while True:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                while len(buf) >= 8:
                    if buf[0:4] != b"\xe5\xbe\x00\xb0":
                        idx = buf.find(b"\xe5\xbe\x00\xb0", 1)
                        if idx < 0:
                            buf.clear()
                            break
                        del buf[:idx]
                        if len(buf) < 8:
                            break
                    total_len = struct.unpack("<H", buf[4:6])[0]
                    if total_len < 8 or total_len > 8192:
                        del buf[:4]
                        continue
                    if len(buf) < total_len:
                        break
                    data = bytes(buf[:total_len])
                    del buf[:total_len]
                    print(f"[RELAY-TCP] <- {len(data)}B from {peer}: {data.hex()}")
                    resp = build_relay_reply(data, peer, "tcp", self.request)
                    if resp:
                        self.request.sendall(resp)
                        print(f"[RELAY-TCP] -> {len(resp)}B to {peer}: {resp.hex()}")
        except OSError as exc:
            print(f"[RELAY-TCP] Error {peer}: {exc}")
        finally:
            mid = RELAY_PEER_TO_MEMBER.pop(peer, None)
            if mid is not None:
                RELAY_ENDPOINTS.pop(mid, None)
            print(f"[RELAY-TCP] Disconnected: {peer}")


class DH2RelayUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        print(f"[RELAY-UDP] <- {len(data)}B from {self.client_address}: {data.hex()}")
        resp = build_relay_reply(data, self.client_address, "udp", (sock, self.client_address))
        if resp:
            sock.sendto(resp, self.client_address)
            print(f"[RELAY-UDP] -> {len(resp)}B to {self.client_address}: {resp.hex()}")


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description="DH2 Local Online Server")
    parser.add_argument("--host", default=os.environ.get("DH2_BIND_HOST", "0.0.0.0"))
    parser.add_argument("--public-host", default=os.environ.get("DH2_PUBLIC_HOST", "127.0.0.1"))
    parser.add_argument("--http-port", type=int, default=int(os.environ.get("PORT", "8085")))
    parser.add_argument("--lobby-port", type=int, default=8081)
    args = parser.parse_args()

    init_db()

    httpd = ThreadingHTTPServer((args.host, args.http_port), DH2HttpHandler)
    httpd.http_host = args.public_host
    httpd.http_port = args.http_port
    httpd.lobby_host = args.public_host
    httpd.lobby_port = args.lobby_port

    lobbyd = ThreadingTCPServer((args.host, args.lobby_port), DH2LobbyHandler)
    lobbyd.public_host = args.public_host
    relay_tcp = ThreadingTCPServer((args.host, 8082), DH2RelayTCPHandler)
    relay_udp = ThreadingUDPServer((args.host, 8082), DH2RelayUDPHandler)

    threading.Thread(target=lobbyd.serve_forever, daemon=True).start()
    threading.Thread(target=relay_tcp.serve_forever, daemon=True).start()
    threading.Thread(target=relay_udp.serve_forever, daemon=True).start()

    print(f"DH2 Local Server running:")
    print(f"  HTTP  : http://{args.public_host}:{args.http_port}/ope/ServerConfig.php (bind {args.host})")
    print(f"  Lobby : {args.public_host}:{args.lobby_port}")
    print(f"  Relay : {args.public_host}:8082 (TCP+UDP)")
    print(f"  DB    : {DB_PATH}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        httpd.shutdown()
        lobbyd.shutdown()
        relay_tcp.shutdown()
        relay_udp.shutdown()


if __name__ == "__main__":
    main()
