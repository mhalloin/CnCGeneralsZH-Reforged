"""A private relay server for network games over the internet.

    python3 zh_relay.py --new-key                 print a fresh key to share with your players
    python3 zh_relay.py --key-file relay.key      run the server on UDP port 8090

The game's LAN screen finds games by broadcasting on the local network and then sends every packet
straight to the other machines, neither of which gets through a home router. With RelayServer and
RelayKey set in Options.ini, the game sends all of it here instead and this server passes it on. It
works like a small LAN shared by everyone who holds the key. Each player gets an address of their own
in 10.88.0.0/16 that only exists inside the relay. The game uses that address on the LAN screen, so
the lobby, the match and a map transfer all work as they do on a real LAN. Every connection is
outgoing from the player's side, so nobody forwards a port except the server.

Only someone who knows the key gets in. The key itself never crosses the wire: the server sends a
challenge and the client answers with an HMAC-SHA256 of it, and the server proves the same back.
Game traffic is not encrypted, the same as on a LAN.

Standard library only, one thread, no state on disk. README.md beside this file has the setup on a
VPS, and the protocol is described at the top of GeneralsMD/Code/GameEngine/Include/GameNetwork/Relay.h,
which is the game's half of it.
"""

import argparse
import hashlib
import hmac
import os
import secrets
import select
import socket
import struct
import sys
import time

MAGIC = b"ZR"
VERSION = 1

HELLO, CHALLENGE, AUTH, WELCOME, DENIED, SEND, DELIVER, PING, PONG, BYE, NO_SESSION = range(1, 12)

DENIED_KEY = 1      # the HMAC did not match: wrong key
DENIED_FULL = 2     # every place on the server is taken

NONCE = 16
TOKEN = 8
CLIENT_ID = 8
MAC = 32

SUBNET = 0x0A580000             # 10.88.0.0/16, the players' relay addresses
SUBNET_BROADCAST = 0x0A58FFFF
BROADCAST = 0xFFFFFFFF          # what the LAN lobby sends its announcements to
MAX_PAYLOAD = 1400              # the game sends at most 1100; anything over this is not the game's

DEFAULT_PORT = 8090
COOKIE_SECONDS = 30             # a challenge is good for this bucket and the one before it
FAILURES_BEFORE_BLOCK = 5       # wrong-key answers from one address before it is ignored ...
BLOCK_SECONDS = 60              # ... for this long


def header(kind: int) -> bytes:
    return MAGIC + bytes((VERSION, kind))


def mac(key: bytes, label: bytes, *parts: bytes) -> bytes:
    return hmac.new(key, label + b"".join(parts), hashlib.sha256).digest()


def dotted(ip: int) -> str:
    return socket.inet_ntoa(struct.pack(">I", ip))


def relay_ip_for(client_id: bytes, taken) -> int:
    """The relay address a client id asks for, the same one every time while it is free.

    A client keeps its id for as long as the game runs, so it gets its address back after a dropped
    connection or a server restart. The low byte is never 0 or 255."""
    h = int.from_bytes(hashlib.sha256(client_id).digest()[:4], "big")
    host = h % 0xFFFE
    while True:
        host = host % 0xFFFE + 1
        ip = SUBNET | host
        if (host & 0xFF) not in (0, 255) and ip not in taken:
            return ip


class Session:
    def __init__(self, token: bytes, client_id: bytes, ip: int, addr, now: float):
        self.token = token
        self.client_id = client_id
        self.ip = ip
        self.addr = addr
        self.last_heard = now
        self.welcome = b""          # resent as it was if the same AUTH comes in twice
        self.auth_nonces = b""


class RelayServer:
    """The relay's rules, with no socket: handle() takes one datagram and returns the datagrams to
    send for it, so the tests can drive it directly."""

    def __init__(self, key: bytes, max_players: int = 16, timeout: float = 60.0, log=None):
        if not key:
            raise ValueError("the relay needs a key")
        self.key = key
        self.max_players = max_players
        self.timeout = timeout
        self.secret = os.urandom(32)
        self.by_token: dict[bytes, Session] = {}
        self.by_ip: dict[int, Session] = {}
        self.by_client: dict[bytes, Session] = {}
        self.failures: dict[str, list[float]] = {}
        self.log = log or (lambda line: None)

    # --- the handshake -------------------------------------------------------------------------

    def cookie(self, addr, client_nonce: bytes, bucket: int) -> bytes:
        where = ("%s:%d" % (addr[0], addr[1])).encode()
        return mac(self.secret, b"cookie", where, client_nonce, struct.pack(">q", bucket))[:NONCE]

    def blocked(self, addr, now: float) -> bool:
        recent = [t for t in self.failures.get(addr[0], []) if now - t < BLOCK_SECONDS]
        if recent:
            self.failures[addr[0]] = recent
        else:
            self.failures.pop(addr[0], None)
        return len(recent) >= FAILURES_BEFORE_BLOCK

    def on_hello(self, data: bytes, addr, now: float):
        if len(data) != 4 + NONCE or self.blocked(addr, now):
            return []
        client_nonce = data[4:]
        server_nonce = self.cookie(addr, client_nonce, int(now // COOKIE_SECONDS))
        return [(header(CHALLENGE) + client_nonce + server_nonce, addr)]

    def on_auth(self, data: bytes, addr, now: float):
        if len(data) != 4 + NONCE + NONCE + CLIENT_ID + MAC or self.blocked(addr, now):
            return []
        client_nonce = data[4:20]
        server_nonce = data[20:36]
        client_id = data[36:44]
        answer = data[44:76]
        bucket = int(now // COOKIE_SECONDS)
        if not any(hmac.compare_digest(server_nonce, self.cookie(addr, client_nonce, b))
                   for b in (bucket, bucket - 1)):
            return []       # a stale or forged challenge: the client starts over with HELLO
        if not hmac.compare_digest(answer, mac(self.key, b"zh-relay-auth", client_nonce, server_nonce, client_id)):
            self.failures.setdefault(addr[0], []).append(now)
            self.log("refused %s:%d (wrong key)" % addr)
            return [(header(DENIED) + client_nonce + bytes((DENIED_KEY,)), addr)]

        old = self.by_client.get(client_id)
        if old is not None and old.auth_nonces == client_nonce + server_nonce:
            old.addr = addr
            old.last_heard = now
            return [(old.welcome, addr)]        # our WELCOME was lost and the client asked again
        if old is not None:
            ip = old.ip                         # the same game coming back: same address
            self.drop(old, None)
        else:
            if len(self.by_token) >= self.max_players:
                self.log("refused %s:%d (server full)" % addr)
                return [(header(DENIED) + client_nonce + bytes((DENIED_FULL,)), addr)]
            ip = relay_ip_for(client_id, self.by_ip)

        token = os.urandom(TOKEN)
        session = Session(token, client_id, ip, addr, now)
        ip_bytes = struct.pack(">I", ip)
        session.welcome = (header(WELCOME) + token + ip_bytes +
                           mac(self.key, b"zh-relay-welcome", client_nonce, server_nonce, token, ip_bytes))
        session.auth_nonces = client_nonce + server_nonce
        self.by_token[token] = session
        self.by_ip[ip] = session
        self.by_client[client_id] = session
        self.log("%s joined from %s:%d (%d on the server)" % (dotted(ip), addr[0], addr[1], len(self.by_token)))
        return [(session.welcome, addr)]

    # --- a session's traffic -------------------------------------------------------------------

    def session_for(self, data: bytes, addr, now: float):
        session = self.by_token.get(data[4:4 + TOKEN])
        if session is not None:
            if session.addr != addr:
                # The player's router gave them a new outside port. The token is what proves it
                # is them, so their packets follow the new one.
                session.addr = addr
            session.last_heard = now
        return session

    def on_send(self, data: bytes, addr, now: float):
        if len(data) < 4 + TOKEN + 8:
            return []
        session = self.session_for(data, addr, now)
        if session is None:
            return [(header(NO_SESSION) + data[4:4 + TOKEN], addr)]
        src_port, dst_ip, dst_port = struct.unpack(">HIH", data[12:20])
        payload = data[20:]
        if not payload or len(payload) > MAX_PAYLOAD:
            return []
        out = header(DELIVER) + struct.pack(">IHH", session.ip, src_port, dst_port) + payload
        if dst_ip in (BROADCAST, SUBNET_BROADCAST):
            # A LAN broadcast: everyone but the sender, whose lobby would drop its own anyway.
            return [(out, other.addr) for other in self.by_token.values() if other is not session]
        target = self.by_ip.get(dst_ip)
        return [(out, target.addr)] if target is not None else []

    def on_ping(self, data: bytes, addr, now: float):
        if len(data) != 4 + TOKEN:
            return []
        if self.session_for(data, addr, now) is None:
            return [(header(NO_SESSION) + data[4:4 + TOKEN], addr)]
        return [(header(PONG), addr)]

    def on_bye(self, data: bytes, addr, now: float):
        if len(data) != 4 + TOKEN:
            return []
        session = self.by_token.get(data[4:4 + TOKEN])
        if session is not None and session.addr == addr:
            self.drop(session, "left")
        return []

    # --- bookkeeping ---------------------------------------------------------------------------

    def drop(self, session: Session, why):
        self.by_token.pop(session.token, None)
        if self.by_ip.get(session.ip) is session:
            del self.by_ip[session.ip]
        if self.by_client.get(session.client_id) is session:
            del self.by_client[session.client_id]
        if why:
            self.log("%s %s (%d on the server)" % (dotted(session.ip), why, len(self.by_token)))

    def expire(self, now: float):
        for session in [s for s in self.by_token.values() if now - s.last_heard > self.timeout]:
            self.drop(session, "timed out")

    HANDLERS = {HELLO: on_hello, AUTH: on_auth, SEND: on_send, PING: on_ping, BYE: on_bye}

    def handle(self, data: bytes, addr, now: float):
        if len(data) < 4 or data[:2] != MAGIC or data[2] != VERSION:
            return []
        handler = self.HANDLERS.get(data[3])
        return handler(self, data, addr, now) if handler else []


def serve(server: RelayServer, sock: socket.socket, stop=lambda: False):
    """Runs until stop() says so or the process is killed."""
    last_sweep = time.monotonic()
    while not stop():
        readable, _, _ = select.select([sock], [], [], 1.0)
        now = time.monotonic()
        if readable:
            try:
                data, addr = sock.recvfrom(4096)
            except (ConnectionResetError, OSError):
                # Windows reports an ICMP "port unreachable" for an earlier send on the next receive.
                continue
            for out, to in server.handle(data, addr, now):
                try:
                    sock.sendto(out, to)
                except OSError:
                    pass
        if now - last_sweep >= 1.0:
            server.expire(now)
            last_sweep = now


def read_key(args) -> bytes:
    if args.key_file:
        with open(args.key_file, "rb") as f:
            key = f.read().strip()
    elif args.key:
        key = args.key.encode()
    else:
        key = os.environ.get("ZH_RELAY_KEY", "").encode()
    if not key:
        sys.exit("zh_relay: no key. Give --key-file, --key or ZH_RELAY_KEY; --new-key makes one.")
    if len(key) < 12:
        print("zh_relay: warning: a key under 12 characters is easy to guess", file=sys.stderr)
    return key


def main(argv=None):
    parser = argparse.ArgumentParser(description="A private relay server for Zero Hour Reforged network games.")
    parser.add_argument("--new-key", action="store_true", help="print a random key and exit")
    parser.add_argument("--key-file", help="file holding the key players put in RelayKey (recommended)")
    parser.add_argument("--key", help="the key itself (visible to other users of this machine)")
    parser.add_argument("--bind", default="0.0.0.0", help="address to listen on (default: all)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="UDP port (default: %d)" % DEFAULT_PORT)
    parser.add_argument("--max-players", type=int, default=16,
                        help="players connected at once, lobby included (default: 16, a full 12-player game and spare)")
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds of silence before a player is dropped")
    args = parser.parse_args(argv)

    if args.new_key:
        print(secrets.token_urlsafe(24))
        return

    key = read_key(args)

    def log(line):
        print(time.strftime("%Y-%m-%d %H:%M:%S ") + line, flush=True)

    server = RelayServer(key, args.max_players, args.timeout, log)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    log("relay listening on UDP %s:%d" % (args.bind, args.port))
    try:
        serve(server, sock)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
