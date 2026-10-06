"""Tests for zh_relay.py.

    python3 -m unittest discover -s Tools/Relay

Most of them drive RelayServer.handle() directly with made-up addresses; the last runs the real
socket loop on a loopback port with two clients.
"""

import os
import socket
import struct
import threading
import unittest

import zh_relay as R

KEY = b"correct horse battery staple"
A = ("203.0.113.5", 40001)
B = ("198.51.100.7", 50002)


class Client:
    """The game's side of the handshake, as Relay.cpp does it."""

    def __init__(self, server, addr, key=KEY, client_id=None):
        self.server, self.addr, self.key = server, addr, key
        self.client_id = client_id or os.urandom(R.CLIENT_ID)
        self.token = None
        self.ip = None

    def connect(self, now=1000.0):
        nonce = os.urandom(R.NONCE)
        (challenge, to), = self.server.handle(R.header(R.HELLO) + nonce, self.addr, now)
        assert to == self.addr and challenge[3] == R.CHALLENGE and challenge[4:20] == nonce
        server_nonce = challenge[20:36]
        answer = R.mac(self.key, b"zh-relay-auth", nonce, server_nonce, self.client_id)
        replies = self.server.handle(R.header(R.AUTH) + nonce + server_nonce + self.client_id + answer, self.addr, now)
        self.last_auth = (nonce, server_nonce, answer)
        if not replies:
            return None
        (reply, _), = replies
        if reply[3] == R.WELCOME:
            self.token, ip_bytes, proof = reply[4:12], reply[12:16], reply[16:48]
            assert proof == R.mac(self.key, b"zh-relay-welcome", nonce, server_nonce, self.token, ip_bytes)
            self.ip = struct.unpack(">I", ip_bytes)[0]
        return reply

    def send(self, dst_ip, payload, src_port=8086, dst_port=8086, now=1000.0, token=None):
        packet = R.header(R.SEND) + (token or self.token) + struct.pack(">HIH", src_port, dst_ip, dst_port) + payload
        return self.server.handle(packet, self.addr, now)


def delivered(out):
    """(source ip, source port, destination port, payload) of a DELIVER datagram"""
    assert out[:4] == R.header(R.DELIVER)
    ip, src_port, dst_port = struct.unpack(">IHH", out[4:12])
    return ip, src_port, dst_port, out[12:]


class Handshake(unittest.TestCase):
    def test_the_right_key_gets_an_address_in_the_relay_subnet(self):
        server = R.RelayServer(KEY)
        reply = Client(server, A).connect()
        self.assertEqual(reply[3], R.WELCOME)
        self.assertEqual(len(server.by_token), 1)
        ip = next(iter(server.by_ip))
        self.assertEqual(ip & 0xFFFF0000, R.SUBNET)
        self.assertNotIn(ip & 0xFF, (0, 255))

    def test_the_wrong_key_is_turned_away(self):
        server = R.RelayServer(KEY)
        reply = Client(server, A, key=b"not the key").connect()
        self.assertEqual(reply[3], R.DENIED)
        self.assertEqual(reply[20], R.DENIED_KEY)
        self.assertEqual(server.by_token, {})

    def test_a_challenge_for_another_address_is_ignored(self):
        server = R.RelayServer(KEY)
        nonce = os.urandom(R.NONCE)
        (challenge, _), = server.handle(R.header(R.HELLO) + nonce, A, 1000.0)
        client_id = os.urandom(8)
        answer = R.mac(KEY, b"zh-relay-auth", nonce, challenge[20:36], client_id)
        self.assertEqual(server.handle(R.header(R.AUTH) + nonce + challenge[20:36] + client_id + answer, B, 1000.0), [])

    def test_a_challenge_older_than_two_buckets_is_ignored(self):
        server = R.RelayServer(KEY)
        nonce = os.urandom(R.NONCE)
        (challenge, _), = server.handle(R.header(R.HELLO) + nonce, A, 1000.0)
        client_id = os.urandom(8)
        answer = R.mac(KEY, b"zh-relay-auth", nonce, challenge[20:36], client_id)
        auth = R.header(R.AUTH) + nonce + challenge[20:36] + client_id + answer
        self.assertEqual(server.handle(auth, A, 1000.0 + 2 * R.COOKIE_SECONDS + 1), [])
        self.assertEqual(server.handle(auth, A, 1000.0 + R.COOKIE_SECONDS)[0][0][3], R.WELCOME)

    def test_the_same_auth_twice_gets_the_same_welcome(self):
        server = R.RelayServer(KEY)
        c = Client(server, A)
        first = c.connect()
        nonce, server_nonce, answer = c.last_auth
        (again, _), = server.handle(R.header(R.AUTH) + nonce + server_nonce + c.client_id + answer, A, 1001.0)
        self.assertEqual(again, first)
        self.assertEqual(len(server.by_token), 1)

    def test_a_game_that_reconnects_keeps_its_address_and_loses_its_old_token(self):
        server = R.RelayServer(KEY)
        c = Client(server, A)
        c.connect()
        old_token, old_ip = c.token, c.ip
        c.addr = ("203.0.113.5", 40999)
        c.connect(now=1010.0)
        self.assertEqual(c.ip, old_ip)
        self.assertNotEqual(c.token, old_token)
        (reply, _), = c.send(R.BROADCAST, b"x", token=old_token)
        self.assertEqual(reply[3], R.NO_SESSION)

    def test_a_restarted_server_gives_the_same_game_the_same_address(self):
        client_id = os.urandom(8)
        first = Client(R.RelayServer(KEY), A, client_id=client_id)
        first.connect()
        second = Client(R.RelayServer(KEY), A, client_id=client_id)
        second.connect()
        self.assertEqual(first.ip, second.ip)

    def test_two_games_never_share_an_address(self):
        server = R.RelayServer(KEY, max_players=200)
        ips = set()
        for i in range(200):
            c = Client(server, ("192.0.2.%d" % (i % 250 + 1), 30000 + i))
            c.connect()
            ips.add(c.ip)
        self.assertEqual(len(ips), 200)

    def test_a_full_server_says_so(self):
        server = R.RelayServer(KEY, max_players=1)
        Client(server, A).connect()
        reply = Client(server, B).connect()
        self.assertEqual(reply[3], R.DENIED)
        self.assertEqual(reply[20], R.DENIED_FULL)

    def test_repeated_wrong_keys_get_an_address_ignored_for_a_while(self):
        server = R.RelayServer(KEY)
        for _ in range(R.FAILURES_BEFORE_BLOCK):
            Client(server, A, key=b"guess").connect()
        self.assertEqual(server.handle(R.header(R.HELLO) + os.urandom(R.NONCE), A, 1000.0), [])
        self.assertTrue(server.handle(R.header(R.HELLO) + os.urandom(R.NONCE), B, 1000.0))
        self.assertTrue(server.handle(R.header(R.HELLO) + os.urandom(R.NONCE), A, 1000.0 + R.BLOCK_SECONDS + 1))

    def test_junk_is_ignored(self):
        server = R.RelayServer(KEY)
        for junk in (b"", b"ZR", b"ZR\x02\x01" + bytes(16), b"XX\x01\x01" + bytes(16), b"ZR\x01\x63", os.urandom(200)):
            self.assertEqual(server.handle(junk, A, 1000.0), [])


class Traffic(unittest.TestCase):
    def setUp(self):
        self.server = R.RelayServer(KEY)
        self.a = Client(self.server, A)
        self.b = Client(self.server, B)
        self.c = Client(self.server, ("192.0.2.9", 9999))
        for client in (self.a, self.b, self.c):
            client.connect()

    def test_a_packet_reaches_its_address_stamped_with_the_senders(self):
        (out, to), = self.a.send(self.b.ip, b"hello", src_port=8088, dst_port=8088)
        self.assertEqual(to, B)
        self.assertEqual(delivered(out), (self.a.ip, 8088, 8088, b"hello"))

    def test_a_broadcast_reaches_everyone_but_the_sender(self):
        outs = self.a.send(R.BROADCAST, b"lobby")
        self.assertEqual(sorted(to for _, to in outs), sorted([B, self.c.addr]))
        for out, _ in outs:
            self.assertEqual(delivered(out), (self.a.ip, 8086, 8086, b"lobby"))

    def test_a_packet_to_nobody_goes_nowhere(self):
        nobody = next(R.SUBNET | host for host in range(1, 100) if R.SUBNET | host not in self.server.by_ip)
        self.assertEqual(self.a.send(nobody, b"x"), [])

    def test_an_empty_or_oversized_packet_is_dropped(self):
        self.assertEqual(self.a.send(self.b.ip, b""), [])
        self.assertEqual(self.a.send(self.b.ip, bytes(R.MAX_PAYLOAD + 1)), [])
        self.assertEqual(len(self.a.send(self.b.ip, bytes(R.MAX_PAYLOAD))), 1)

    def test_an_unknown_token_is_told_to_reconnect(self):
        (reply, to), = self.a.send(self.b.ip, b"x", token=b"\0" * 8)
        self.assertEqual((reply[3], to), (R.NO_SESSION, A))

    def test_a_player_whose_router_changes_port_keeps_receiving(self):
        self.b.addr = ("198.51.100.7", 61000)
        self.b.send(self.a.ip, b"from the new port")
        (out, to), = self.a.send(self.b.ip, b"reply")
        self.assertEqual(to, ("198.51.100.7", 61000))

    def test_ping_answers_and_keeps_the_session_alive(self):
        (reply, _), = self.server.handle(R.header(R.PING) + self.a.token, A, 1050.0)
        self.assertEqual(reply, R.header(R.PONG))
        self.server.expire(1000.0 + self.server.timeout + 10)
        self.assertIn(self.a.token, self.server.by_token)
        self.assertNotIn(self.b.token, self.server.by_token)

    def test_bye_leaves_and_only_from_the_players_own_address(self):
        self.server.handle(R.header(R.BYE) + self.a.token, B, 1000.0)
        self.assertIn(self.a.token, self.server.by_token)
        self.server.handle(R.header(R.BYE) + self.a.token, A, 1000.0)
        self.assertNotIn(self.a.token, self.server.by_token)
        self.assertNotIn(self.a.ip, self.server.by_ip)
        self.assertEqual(len(self.b.send(R.BROADCAST, b"x")), 1)


class OverRealSockets(unittest.TestCase):
    def test_two_clients_on_loopback(self):
        server = R.RelayServer(KEY)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        stop = threading.Event()
        thread = threading.Thread(target=R.serve, args=(server, sock, stop.is_set), daemon=True)
        thread.start()
        try:
            where = sock.getsockname()
            clients = []
            for _ in range(2):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2.0)
                s.bind(("127.0.0.1", 0))
                nonce, client_id = os.urandom(16), os.urandom(8)
                s.sendto(R.header(R.HELLO) + nonce, where)
                challenge, _ = s.recvfrom(4096)
                server_nonce = challenge[20:36]
                s.sendto(R.header(R.AUTH) + nonce + server_nonce + client_id +
                         R.mac(KEY, b"zh-relay-auth", nonce, server_nonce, client_id), where)
                welcome, _ = s.recvfrom(4096)
                self.assertEqual(welcome[3], R.WELCOME)
                clients.append((s, welcome[4:12], struct.unpack(">I", welcome[12:16])[0]))
            (s1, token1, ip1), (s2, token2, ip2) = clients
            s1.sendto(R.header(R.SEND) + token1 + struct.pack(">HIH", 8088, ip2, 8088) + b"over the wire", where)
            out, _ = s2.recvfrom(4096)
            self.assertEqual(delivered(out), (ip1, 8088, 8088, b"over the wire"))
            for s, _, _ in clients:
                s.close()
        finally:
            stop.set()
            thread.join(3)
            sock.close()


if __name__ == "__main__":
    unittest.main()
