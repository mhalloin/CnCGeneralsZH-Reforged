/*
**	Zero Hour Reforged
**	Copyright 2026 the Zero Hour Reforged contributors
**
**	This program is free software: you can redistribute it and/or modify
**	it under the terms of the GNU General Public License as published by
**	the Free Software Foundation, either version 3 of the License, or
**	(at your option) any later version.
**
**	This program is distributed in the hope that it will be useful,
**	but WITHOUT ANY WARRANTY; without even the implied warranty of
**	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**	GNU General Public License for more details.
**
**	You should have received a copy of the GNU General Public License
**	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// FILE: Relay.cpp ////////////////////////////////////////////////////////////////////////////////
// Desc:   The game's side of the relay server: the handshake, keeping the session alive, and the
//         packets of every Transport bound to the relay address.  The protocol is in Relay.h.
///////////////////////////////////////////////////////////////////////////////////////////////////

#include "PreRTS.h"	// This must go first in EVERY cpp file int the GameEngine
#include "Lib/Clock.h"

#include "GameNetwork/NetworkUtil.h"
#include "GameNetwork/Relay.h"
#include "GameNetwork/udp.h"

#include <chrono>
#include <random>
#include <stdlib.h>
#include <string.h>
#include <thread>

RelayClient *TheRelay = NULL;

namespace {

enum
{
	T_HELLO = 1, T_CHALLENGE, T_AUTH, T_WELCOME, T_DENIED, T_SEND, T_DELIVER, T_PING, T_PONG, T_BYE, T_NO_SESSION
};

const UnsignedByte PROTOCOL_VERSION = 1;
const UnsignedByte DENIED_FULL = 2;

const UnsignedInt RESEND_MS = 500;				///< a handshake datagram nobody answered goes again
const Int AUTH_TRIES = 4;									///< then the handshake starts over from HELLO
const UnsignedInt PING_MS = 5000;					///< often enough for a router that forgets a flow in 30 s
const UnsignedInt SERVER_SILENT_MS = 20000;	///< four pings unanswered and the session is taken as lost
const size_t MAX_INBOX = 512;							///< per port; twice Transport's own queue

const char AUTH_LABEL[] = "zh-relay-auth";
const char WELCOME_LABEL[] = "zh-relay-welcome";

inline void put16( UnsignedByte *p, UnsignedShort v ) { p[0] = (UnsignedByte)(v >> 8); p[1] = (UnsignedByte)v; }
inline void put32( UnsignedByte *p, UnsignedInt v ) { put16(p, (UnsignedShort)(v >> 16)); put16(p + 2, (UnsignedShort)v); }
inline UnsignedShort get16( const UnsignedByte *p ) { return (UnsignedShort)((p[0] << 8) | p[1]); }
inline UnsignedInt get32( const UnsignedByte *p ) { return ((UnsignedInt)get16(p) << 16) | get16(p + 2); }

inline void putHeader( UnsignedByte *p, UnsignedByte type )
{
	p[0] = 'Z';
	p[1] = 'R';
	p[2] = PROTOCOL_VERSION;
	p[3] = type;
}

/// The OS's random source (std::random_device is CryptGenRandom on Windows and /dev/urandom elsewhere)
void fillRandom( UnsignedByte *p, Int n )
{
	std::random_device source;
	for (Int i = 0; i < n; i += 4)
	{
		UnsignedInt r = source();
		for (Int j = 0; j < 4 && i + j < n; ++j)
			p[i + j] = (UnsignedByte)(r >> (8 * j));
	}
}

/// Compares every byte whatever the first difference, so the time taken says nothing about where it was
Bool sameBytes( const UnsignedByte *a, const UnsignedByte *b, Int n )
{
	UnsignedByte diff = 0;
	for (Int i = 0; i < n; ++i)
		diff |= a[i] ^ b[i];
	return diff == 0;
}

// --- SHA-256 (FIPS 180-4) ---------------------------------------------------------------------

const UnsignedInt K[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline UnsignedInt rotr( UnsignedInt x, Int n ) { return (x >> n) | (x << (32 - n)); }

struct Sha256
{
	UnsignedInt h[8];
	UnsignedByte block[64];
	Int used;
	UnsignedInt64 bytes;

	Sha256( void )
	{
		static const UnsignedInt H0[8] =
			{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
		memcpy(h, H0, sizeof(h));
		used = 0;
		bytes = 0;
	}

	void compress( void )
	{
		UnsignedInt w[64];
		for (Int i = 0; i < 16; ++i)
			w[i] = get32(block + 4 * i);
		for (Int i = 16; i < 64; ++i)
		{
			UnsignedInt s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
			UnsignedInt s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}
		UnsignedInt a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
		for (Int i = 0; i < 64; ++i)
		{
			UnsignedInt t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
			UnsignedInt t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
			hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
		}
		h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
	}

	void update( const UnsignedByte *data, Int len )
	{
		bytes += len;
		while (len > 0)
		{
			Int take = 64 - used;
			if (take > len)
				take = len;
			memcpy(block + used, data, take);
			used += take;
			data += take;
			len -= take;
			if (used == 64)
			{
				compress();
				used = 0;
			}
		}
	}

	void finish( UnsignedByte out[32] )
	{
		UnsignedInt64 bits = bytes * 8;
		UnsignedByte pad = 0x80;
		update(&pad, 1);
		pad = 0;
		while (used != 56)
			update(&pad, 1);
		UnsignedByte length[8];
		put32(length, (UnsignedInt)(bits >> 32));
		put32(length + 4, (UnsignedInt)bits);
		update(length, 8);
		for (Int i = 0; i < 8; ++i)
			put32(out + 4 * i, h[i]);
	}
};

}	// namespace

void relaySha256( const UnsignedByte *data, Int len, UnsignedByte out[32] )
{
	Sha256 s;
	s.update(data, len);
	s.finish(out);
}

void relayHmacSha256( const UnsignedByte *key, Int keyLen, const UnsignedByte *const *parts, const Int *partLens,
	Int numParts, UnsignedByte out[32] )
{
	UnsignedByte k[64];
	memset(k, 0, sizeof(k));
	if (keyLen > 64)
		relaySha256(key, keyLen, k);
	else
		memcpy(k, key, keyLen);

	UnsignedByte pad[64];
	for (Int i = 0; i < 64; ++i)
		pad[i] = k[i] ^ 0x36;
	Sha256 inner;
	inner.update(pad, 64);
	for (Int i = 0; i < numParts; ++i)
		inner.update(parts[i], partLens[i]);
	UnsignedByte innerHash[32];
	inner.finish(innerHash);

	for (Int i = 0; i < 64; ++i)
		pad[i] = k[i] ^ 0x5c;
	Sha256 outer;
	outer.update(pad, 64);
	outer.update(innerHash, 32);
	outer.finish(out);
}

// --- RelayClient ------------------------------------------------------------------------------

RelayClient::RelayClient( void )
{
	m_serverIP = 0;
	m_serverPort = DEFAULT_PORT;
	m_socket = NULL;
	m_winsockInit = FALSE;
	m_status = RELAY_IDLE;
	m_sentAuth = FALSE;
	m_authTries = 0;
	memset(m_clientNonce, 0, sizeof(m_clientNonce));
	memset(m_serverNonce, 0, sizeof(m_serverNonce));
	memset(m_token, 0, sizeof(m_token));
	fillRandom(m_clientID, sizeof(m_clientID));
	m_relayIP = 0;
	m_lastSent = 0;
	m_lastPing = 0;
	m_lastHeard = 0;
}

RelayClient::~RelayClient( void )
{
	disconnect();
	delete m_socket;
	m_socket = NULL;
#if defined(_WIN32)
	if (m_winsockInit)
		WSACleanup();
#endif
}

void RelayClient::configure( AsciiString server, AsciiString key )
{
	server.trim();
	key.trim();
	if (server == m_server && key == m_key)
		return;
	disconnect();
	m_server = server;
	m_key = key;
	m_relayIP = 0;	// another server's addresses are its own
}

Bool RelayClient::openSocket( void )
{
	if (m_socket)
		return TRUE;
#if defined(_WIN32)
	if (!m_winsockInit)
	{
		WSADATA wsadata;
		if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
			return FALSE;
		m_winsockInit = TRUE;
	}
#endif
	m_socket = NEW UDP();
	if (m_socket->Bind((UnsignedInt)INADDR_ANY, 0) != 0)	// any address, a port the system picks
	{
		DEBUG_LOG(("RelayClient: could not open a socket (error %d)\n", lastSocketError()));
		delete m_socket;
		m_socket = NULL;
		return FALSE;
	}
	return TRUE;
}

Bool RelayClient::connect( UnsignedInt timeoutMs )
{
	if (m_status == RELAY_CONNECTED)
		return TRUE;

	// "host" or "host:port"
	char host[256];
	strncpy(host, m_server.str(), sizeof(host) - 1);
	host[sizeof(host) - 1] = 0;
	UnsignedShort port = DEFAULT_PORT;
	char *colon = strrchr(host, ':');
	if (colon)
	{
		*colon = 0;
		Int p = atoi(colon + 1);
		if (p > 0 && p < 65536)
			port = (UnsignedShort)p;
	}

	if (!openSocket())
	{
		m_status = RELAY_UNREACHABLE;
		return FALSE;
	}
	UnsignedInt ip = (host[0] != 0) ? ResolveIP(AsciiString(host)) : 0;
	if (ip == 0 || ip == INADDR_NONE)
	{
		DEBUG_LOG(("RelayClient: %s does not resolve\n", host));
		m_status = RELAY_NO_SUCH_HOST;
		return FALSE;
	}
	m_serverIP = ip;
	m_serverPort = port;

	startHandshake();
	UnsignedInt start = Clock_Milliseconds();
	for (;;)
	{
		service();
		if (m_status == RELAY_CONNECTED)
			return TRUE;
		if (m_status == RELAY_WRONG_KEY || m_status == RELAY_FULL)
			return FALSE;
		if (Clock_Milliseconds() - start >= timeoutMs)
		{
			DEBUG_LOG(("RelayClient: no answer from %s:%d\n", host, port));
			m_status = RELAY_UNREACHABLE;
			return FALSE;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
}

void RelayClient::disconnect( void )
{
	if (m_status == RELAY_CONNECTED)
	{
		UnsignedByte bye[12];
		putHeader(bye, T_BYE);
		memcpy(bye + 4, m_token, 8);
		sendRaw(bye, sizeof(bye));
	}
	m_status = RELAY_IDLE;
	for (size_t i = 0; i < m_ports.size(); ++i)
		m_ports[i].inbox.clear();
}

void RelayClient::startHandshake( void )
{
	fillRandom(m_clientNonce, sizeof(m_clientNonce));
	m_sentAuth = FALSE;
	m_authTries = 0;
	m_status = RELAY_CONNECTING;
	sendHello();
}

void RelayClient::sendHello( void )
{
	UnsignedByte hello[20];
	putHeader(hello, T_HELLO);
	memcpy(hello + 4, m_clientNonce, 16);
	sendRaw(hello, sizeof(hello));
	m_lastSent = Clock_Milliseconds();
}

void RelayClient::sendAuth( void )
{
	UnsignedByte auth[76];
	putHeader(auth, T_AUTH);
	memcpy(auth + 4, m_clientNonce, 16);
	memcpy(auth + 20, m_serverNonce, 16);
	memcpy(auth + 36, m_clientID, 8);
	const UnsignedByte *parts[] = { (const UnsignedByte *)AUTH_LABEL, m_clientNonce, m_serverNonce, m_clientID };
	const Int lens[] = { (Int)strlen(AUTH_LABEL), 16, 16, 8 };
	relayHmacSha256((const UnsignedByte *)m_key.str(), m_key.getLength(), parts, lens, 4, auth + 44);
	sendRaw(auth, sizeof(auth));
	m_lastSent = Clock_Milliseconds();
}

void RelayClient::sendPing( void )
{
	UnsignedByte ping[12];
	putHeader(ping, T_PING);
	memcpy(ping + 4, m_token, 8);
	sendRaw(ping, sizeof(ping));
	m_lastPing = Clock_Milliseconds();
}

Bool RelayClient::sendRaw( const UnsignedByte *data, Int len )
{
	if (!m_socket || m_serverIP == 0)
		return FALSE;
	return m_socket->Write(data, len, m_serverIP, m_serverPort) > 0;
}

void RelayClient::service( void )
{
	if (!m_socket)
		return;

	UnsignedByte buf[2048];
	sockaddr_in from;
	Int len;
	while ((len = m_socket->Read(buf, sizeof(buf), &from)) > 0)
	{
		// Only the server speaks this protocol to us; anything else on the socket is noise.
		if (ntohl(from.sin_addr.s_addr) != m_serverIP || ntohs(from.sin_port) != m_serverPort)
			continue;
		handle(buf, len, Clock_Milliseconds());
	}

	UnsignedInt now = Clock_Milliseconds();
	switch (m_status)
	{
		case RELAY_CONNECTING:
			if (now - m_lastSent >= RESEND_MS)
			{
				if (m_sentAuth && ++m_authTries < AUTH_TRIES)
				{
					sendAuth();
				}
				else
				{
					m_sentAuth = FALSE;
					m_authTries = 0;
					sendHello();
				}
			}
			break;
		case RELAY_CONNECTED:
			if (now - m_lastHeard >= SERVER_SILENT_MS)
			{
				// The server has gone quiet: dropped, restarted, or our route to it changed.  The client
				// id stays the same, so the handshake brings back the same relay address.
				DEBUG_LOG(("RelayClient: lost the server, reconnecting\n"));
				startHandshake();
			}
			else if (now - m_lastPing >= PING_MS)
			{
				sendPing();
			}
			break;
		default:
			break;
	}
}

void RelayClient::handle( const UnsignedByte *data, Int len, UnsignedInt now )
{
	if (len < 4 || data[0] != 'Z' || data[1] != 'R' || data[2] != PROTOCOL_VERSION)
		return;

	switch (data[3])
	{
		case T_CHALLENGE:
			if (m_status == RELAY_CONNECTING && !m_sentAuth && len == 36 && sameBytes(data + 4, m_clientNonce, 16))
			{
				memcpy(m_serverNonce, data + 20, 16);
				m_sentAuth = TRUE;
				m_authTries = 0;
				sendAuth();
			}
			break;

		case T_WELCOME:
			if (m_status == RELAY_CONNECTING && m_sentAuth && len == 48)
			{
				// The server proves it holds the key too; a WELCOME that does not is not from our server.
				UnsignedByte expected[32];
				const UnsignedByte *parts[] = { (const UnsignedByte *)WELCOME_LABEL, m_clientNonce, m_serverNonce, data + 4, data + 12 };
				const Int lens[] = { (Int)strlen(WELCOME_LABEL), 16, 16, 8, 4 };
				relayHmacSha256((const UnsignedByte *)m_key.str(), m_key.getLength(), parts, lens, 5, expected);
				if (!sameBytes(expected, data + 16, 32))
					break;
				memcpy(m_token, data + 4, 8);
				UnsignedInt ip = get32(data + 12);
				DEBUG_ASSERTLOG(m_relayIP == 0 || m_relayIP == ip,
					("RelayClient: the server moved us from %X to %X\n", m_relayIP, ip));
				m_relayIP = ip;
				m_status = RELAY_CONNECTED;
				m_lastHeard = now;
				m_lastPing = now;
				DEBUG_LOG(("RelayClient: connected to %s as %d.%d.%d.%d\n", m_server.str(),
					(ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff));
			}
			break;

		case T_DENIED:
			if (m_status == RELAY_CONNECTING && len == 21 && sameBytes(data + 4, m_clientNonce, 16))
			{
				m_status = (data[20] == DENIED_FULL) ? RELAY_FULL : RELAY_WRONG_KEY;
				DEBUG_LOG(("RelayClient: %s turned us down (%s)\n", m_server.str(),
					m_status == RELAY_FULL ? "full" : "wrong key"));
			}
			break;

		case T_DELIVER:
			if (m_status == RELAY_CONNECTED && len > 12)
			{
				m_lastHeard = now;
				Port *port = findPort(get16(data + 10));
				if (port == NULL || port->opens == 0)
					break;
				if (port->inbox.size() >= MAX_INBOX)
					port->inbox.pop_front();	// nobody is reading it; the newest matter more
				port->inbox.push_back(Datagram());
				Datagram &d = port->inbox.back();
				d.fromIP = get32(data + 4);
				d.fromPort = get16(data + 8);
				d.data.assign(data + 12, data + len);
			}
			break;

		case T_PONG:
			if (m_status == RELAY_CONNECTED)
				m_lastHeard = now;
			break;

		case T_NO_SESSION:
			// The server forgot us (it restarted, or we were silent past its timeout).
			if (m_status == RELAY_CONNECTED && len == 12 && sameBytes(data + 4, m_token, 8))
				startHandshake();
			break;

		default:
			break;
	}
}

RelayClient::Port *RelayClient::findPort( UnsignedShort port )
{
	for (size_t i = 0; i < m_ports.size(); ++i)
		if (m_ports[i].port == port)
			return &m_ports[i];
	return NULL;
}

void RelayClient::openPort( UnsignedShort port )
{
	Port *p = findPort(port);
	if (p == NULL)
	{
		m_ports.push_back(Port());
		p = &m_ports.back();
		p->port = port;
		p->opens = 0;
	}
	++p->opens;
}

void RelayClient::closePort( UnsignedShort port )
{
	Port *p = findPort(port);
	if (p == NULL || p->opens == 0)
		return;
	if (--p->opens == 0)
		p->inbox.clear();
}

Bool RelayClient::send( UnsignedShort fromPort, UnsignedInt toIP, UnsignedShort toPort, const UnsignedByte *data, Int len )
{
	if (m_status != RELAY_CONNECTED || len <= 0 || len > MAX_PAYLOAD)
		return TRUE;
	UnsignedByte packet[20 + MAX_PAYLOAD];
	putHeader(packet, T_SEND);
	memcpy(packet + 4, m_token, 8);
	put16(packet + 12, fromPort);
	put32(packet + 14, toIP);
	put16(packet + 18, toPort);
	memcpy(packet + 20, data, len);
	return sendRaw(packet, 20 + len);
}

Int RelayClient::receive( UnsignedShort port, UnsignedByte *buf, Int maxLen, UnsignedInt *fromIP, UnsignedShort *fromPort )
{
	Port *p = findPort(port);
	if (p == NULL || p->inbox.empty())
		return 0;
	Datagram &d = p->inbox.front();
	Int len = (Int)d.data.size();
	if (len > maxLen)
		len = maxLen;	// what recvfrom does with a datagram too big for the buffer
	memcpy(buf, &d.data[0], len);
	*fromIP = d.fromIP;
	*fromPort = d.fromPort;
	p->inbox.pop_front();
	return len;
}
