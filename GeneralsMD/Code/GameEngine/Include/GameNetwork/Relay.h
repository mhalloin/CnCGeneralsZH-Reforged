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

// FILE: Relay.h //////////////////////////////////////////////////////////////////////////////////
//
// Network games over the internet, through a private relay server (Tools/Relay/zh_relay.py).
//
// The LAN screen finds games by broadcasting and then sends every packet straight to the other
// machines; neither gets through a home router.  With RelayServer and RelayKey in Options.ini, the
// LAN screen connects to the relay instead and is given an address of its own inside it, in
// 10.88.0.0/16.  LANAPI and the match use that address exactly as they would a LAN card's: a
// Transport bound to it sends through the relay rather than a socket of its own (Transport.cpp), a
// broadcast reaches everyone else on the relay, and a packet to another player's relay address
// reaches that player.  Nothing above Transport knows the difference.  One UDP socket carries all of
// it, and every packet goes out from the player's side, so no router needs a port forwarded.
//
// The protocol.  Every datagram starts with 'Z' 'R', the version (1) and a type; numbers are big
// endian.  Lengths are of the whole datagram.
//
//   HELLO      c->s  20  client nonce[16]
//   CHALLENGE  s->c  36  client nonce[16], server nonce[16]
//   AUTH       c->s  76  client nonce, server nonce, client id[8],
//                        HMAC-SHA256(key, "zh-relay-auth" | client nonce | server nonce | client id)
//   WELCOME    s->c  48  token[8], relay address[4],
//                        HMAC-SHA256(key, "zh-relay-welcome" | client nonce | server nonce | token | address)
//   DENIED     s->c  21  client nonce, reason (1 wrong key, 2 server full)
//   SEND       c->s  20+ token, source port[2], destination address[4], destination port[2], payload
//   DELIVER    s->c  12+ source address[4], source port[2], destination port[2], payload
//   PING       c->s  12  token                 PONG  s->c  4
//   BYE        c->s  12  token                 NO_SESSION  s->c  12  token
//
// The key never crosses the wire, and each side proves it holds it.  The client id is random and
// kept for as long as the game runs; the server hands the same id the same address, so a dropped
// connection or a restarted server leaves every player where the others expect them.  A SEND to
// 255.255.255.255 goes to everyone on the relay but the sender.  The token is what makes a SEND
// count, so a player whose router moves them to another outside port carries on.
//
///////////////////////////////////////////////////////////////////////////////////////////////////

#pragma once

#ifndef _RELAY_H_
#define _RELAY_H_

#include "Lib/BaseType.h"
#include "Common/AsciiString.h"

#include <deque>
#include <vector>

class UDP;

/// SHA-256 of `len` bytes; exposed for the test's known-answer vectors
void relaySha256( const UnsignedByte *data, Int len, UnsignedByte out[32] );
/// HMAC-SHA256 (RFC 2104) of the concatenation of `parts`, with `key`
void relayHmacSha256( const UnsignedByte *key, Int keyLen, const UnsignedByte *const *parts, const Int *partLens,
	Int numParts, UnsignedByte out[32] );

class RelayClient
{
public:
	enum Status
	{
		RELAY_IDLE,					///< never connected, or said goodbye
		RELAY_CONNECTING,		///< handshaking, the first time or after losing the server
		RELAY_CONNECTED,
		RELAY_NO_SUCH_HOST,	///< RelayServer does not resolve to an address
		RELAY_UNREACHABLE,	///< nothing answered within connect()'s time
		RELAY_WRONG_KEY,		///< the server turned RelayKey down
		RELAY_FULL					///< the server has no place left
	};

	enum { DEFAULT_PORT = 8090, MAX_PAYLOAD = 1400 };

	RelayClient( void );
	~RelayClient( void );

	/// "host" or "host:port", and the key.  A change of either drops the current session.
	void configure( AsciiString server, AsciiString key );
	/// Handshakes for up to timeoutMs, servicing the socket meanwhile.  TRUE once connected.
	Bool connect( UnsignedInt timeoutMs );
	/// Tells the server we are leaving and stops.  connect() starts again.
	void disconnect( void );
	/// Reads what has arrived and keeps the session alive.  Transport calls this on every update.
	void service( void );

	Status getStatus( void ) const { return m_status; }
	Bool isConnected( void ) const { return m_status == RELAY_CONNECTED; }
	/// Our address inside the relay, host order; 0 until the first WELCOME, then kept through reconnects
	UnsignedInt getRelayIP( void ) const { return m_relayIP; }
	AsciiString getServer( void ) const { return m_server; }

	/// A Transport bound to the relay address listens on a port of it.  Counted: two opens need two closes.
	void openPort( UnsignedShort port );
	void closePort( UnsignedShort port );
	/// FALSE only when the socket fails.  While the session is down the packet is dropped, as UDP would.
	Bool send( UnsignedShort fromPort, UnsignedInt toIP, UnsignedShort toPort, const UnsignedByte *data, Int len );
	/// The next packet for `port`: its length, or 0 when there is none.  fromIP is host order.
	Int receive( UnsignedShort port, UnsignedByte *buf, Int maxLen, UnsignedInt *fromIP, UnsignedShort *fromPort );

private:
	struct Datagram
	{
		UnsignedInt fromIP;
		UnsignedShort fromPort;
		std::vector<UnsignedByte> data;
	};
	struct Port
	{
		UnsignedShort port;
		Int opens;
		std::deque<Datagram> inbox;
	};

	Bool openSocket( void );
	void startHandshake( void );
	void sendHello( void );
	void sendAuth( void );
	void sendPing( void );
	Bool sendRaw( const UnsignedByte *data, Int len );
	void handle( const UnsignedByte *data, Int len, UnsignedInt now );
	Port *findPort( UnsignedShort port );

	AsciiString m_server;
	AsciiString m_key;
	UnsignedInt m_serverIP;				///< host order
	UnsignedShort m_serverPort;
	UDP *m_socket;
	Bool m_winsockInit;

	Status m_status;
	Bool m_sentAuth;							///< in RELAY_CONNECTING: HELLO answered, AUTH sent
	Int m_authTries;
	UnsignedByte m_clientNonce[16];
	UnsignedByte m_serverNonce[16];
	UnsignedByte m_clientID[8];
	UnsignedByte m_token[8];
	UnsignedInt m_relayIP;
	UnsignedInt m_lastSent;				///< last handshake datagram, ms
	UnsignedInt m_lastPing;
	UnsignedInt m_lastHeard;			///< last datagram from the server, ms

	std::vector<Port> m_ports;
};

/// Non-NULL while RelayServer is set and the LAN screen has used it; see LanLobbyMenu.cpp
extern RelayClient *TheRelay;

#endif // _RELAY_H_
