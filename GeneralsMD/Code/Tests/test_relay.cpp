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

/*
 * The relay (GameNetwork/Relay.h): the game's half of it, against the real server.
 *
 * Without a server this checks the SHA-256 and HMAC the handshake rests on, against FIPS 180-2's and
 * RFC 4231's own vectors.  Tests/run_relay_check.sh starts Tools/Relay/zh_relay.py on a loopback port
 * and runs this again with ZH_RELAY_TEST_SERVER and ZH_RELAY_TEST_KEY set, and then the rest runs:
 *
 *   - two games get two different addresses in 10.88.0.0/16, and one that leaves and comes back gets
 *     its own again;
 *   - a Transport bound to TheRelay's address opens no socket, and its broadcast reaches the other
 *     game stamped with its relay address and port, as the LAN lobby's announcements must;
 *   - what comes back is decoded by that Transport as a packet from the other game's relay address;
 *   - a packet reaches only the port it was sent to, and a Transport that was reset hears nothing;
 *   - the wrong key, a server that is not there and an empty server name each end in their own status,
 *     which is what the LAN screen's message is chosen by.
 *
 * What this cannot see: a router between the game and the server, and two separate machines.
 */

#include "test_harness.h"

#include "Common/GlobalData.h"
#include "Lib/Clock.h"
#include "GameNetwork/NetworkDefs.h"
#include "GameNetwork/Relay.h"
#include "GameNetwork/Transport.h"

#include <chrono>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread>

namespace {

void hex( const char *text, UnsignedByte *out )
{
	for (Int i = 0; text[2 * i] != 0; ++i)
	{
		unsigned int b;
		sscanf(text + 2 * i, "%2x", &b);
		out[i] = (UnsignedByte)b;
	}
}

Bool sha256Is( const char *message, Int len, const char *expected )
{
	UnsignedByte want[32], got[32];
	hex(expected, want);
	relaySha256((const UnsignedByte *)message, len, got);
	return memcmp(want, got, 32) == 0;
}

Bool hmacIs( const UnsignedByte *key, Int keyLen, const char *message, const char *expected )
{
	UnsignedByte want[32], got[32];
	hex(expected, want);
	// split in two to check that the parts are taken as one message
	Int half = (Int)strlen(message) / 2;
	const UnsignedByte *parts[] = { (const UnsignedByte *)message, (const UnsignedByte *)message + half };
	const Int lens[] = { half, (Int)strlen(message) - half };
	relayHmacSha256(key, keyLen, parts, lens, 2, got);
	return memcmp(want, got, 32) == 0;
}

const char *server( void ) { return getenv("ZH_RELAY_TEST_SERVER"); }
const char *key( void ) { return getenv("ZH_RELAY_TEST_KEY"); }

Bool haveServer( void )
{
	if (server() && key())
		return TRUE;
	printf("  (no relay server: run Tests/run_relay_check.sh for this one)\n");
	return FALSE;
}

/// Services both until `done` says so or a second has passed
template <class Done> Bool pumpUntil( RelayClient &a, RelayClient &b, Done done )
{
	for (Int i = 0; i < 200; ++i)
	{
		a.service();
		b.service();
		if (done())
			return TRUE;
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	return FALSE;
}

/// Transport::init reads the link simulation's settings out of TheGlobalData
struct Globals
{
	GlobalData *saved;
	Globals() : saved( TheWritableGlobalData ) { TheWritableGlobalData = NEW GlobalData; }
	~Globals() { delete TheWritableGlobalData; TheWritableGlobalData = saved; }
};

/// TheRelay for the length of one test
struct TheRelayFor
{
	TheRelayFor( RelayClient *r ) { TheRelay = r; }
	~TheRelayFor() { TheRelay = NULL; }
};

}	// namespace

TEST(relay_sha256_matches_the_fips_vectors)
{
	CHECK(sha256Is("abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
	CHECK(sha256Is("", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
	const char *twoBlocks = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	CHECK(sha256Is(twoBlocks, (Int)strlen(twoBlocks), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

TEST(relay_hmac_matches_rfc_4231)
{
	UnsignedByte key1[20];
	memset(key1, 0x0b, sizeof(key1));
	CHECK(hmacIs(key1, sizeof(key1), "Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
	CHECK(hmacIs((const UnsignedByte *)"Jefe", 4, "what do ya want for nothing?",
		"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
	UnsignedByte key6[131];	// longer than a block: hashed first
	memset(key6, 0xaa, sizeof(key6));
	CHECK(hmacIs(key6, sizeof(key6), "Test Using Larger Than Block-Size Key - Hash Key First",
		"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
}

TEST(relay_two_games_get_their_own_addresses_and_keep_them)
{
	if (!haveServer())
		return;
	RelayClient a, b;
	a.configure(server(), key());
	b.configure(server(), key());
	CHECK(a.connect(3000));
	CHECK(b.connect(3000));
	CHECK_EQ(a.getStatus(), RelayClient::RELAY_CONNECTED);
	CHECK_EQ(a.getRelayIP() & 0xFFFF0000u, 0x0A580000u);
	CHECK_EQ(b.getRelayIP() & 0xFFFF0000u, 0x0A580000u);
	CHECK_NE(a.getRelayIP(), b.getRelayIP());

	UnsignedInt first = a.getRelayIP();
	a.disconnect();
	CHECK_EQ(a.getStatus(), RelayClient::RELAY_IDLE);
	CHECK(a.connect(3000));
	CHECK_EQ(a.getRelayIP(), first);
}

TEST(relay_a_transport_on_the_relay_address_plays_like_a_lan)
{
	if (!haveServer())
		return;
	Globals globals;
	RelayClient *a = new RelayClient;
	RelayClient b;
	TheRelayFor relay(a);
	a->configure(server(), key());
	b.configure(server(), key());
	CHECK(a->connect(3000));
	CHECK(b.connect(3000));
	const UnsignedShort LOBBY = 8086, GAME = 8088;
	b.openPort(LOBBY);
	b.openPort(GAME);

	Transport lobby;
	CHECK(lobby.init(a->getRelayIP(), LOBBY));
	CHECK(lobby.isOpen());
	CHECK(lobby.allowBroadcasts(true));

	// A lobby announcement: everyone on the relay hears it, from our relay address and the lobby port.
	const char announce[] = "a game is up";
	CHECK(lobby.queueSend(INADDR_BROADCAST, LOBBY, (const UnsignedByte *)announce, sizeof(announce)));
	CHECK(lobby.update());
	UnsignedByte buf[MAX_NETWORK_MESSAGE_LEN];
	UnsignedInt fromIP = 0;
	UnsignedShort fromPort = 0;
	Int got = 0;
	CHECK(pumpUntil(*a, b, [&] { return (got = b.receive(LOBBY, buf, sizeof(buf), &fromIP, &fromPort)) > 0; }));
	CHECK_EQ(got, (Int)(sizeof(announce) + sizeof(TransportMessageHeader)));
	CHECK_EQ(fromIP, a->getRelayIP());
	CHECK_EQ(fromPort, LOBBY);
	CHECK_EQ(b.receive(GAME, buf, sizeof(buf), &fromIP, &fromPort), 0);	// another port heard nothing

	// The same bytes sent back are a valid packet, and the Transport takes them as the other game's.
	CHECK(b.send(LOBBY, a->getRelayIP(), LOBBY, buf, got));
	Bool arrived = FALSE;
	for (Int i = 0; i < 200 && !arrived; ++i)
	{
		lobby.update();
		for (Int m = 0; m < MAX_MESSAGES; ++m)
		{
			if (lobby.m_inBuffer[m].length <= 0)
				continue;
			CHECK_EQ(lobby.m_inBuffer[m].length, (Int)sizeof(announce));
			CHECK_EQ(lobby.m_inBuffer[m].addr, b.getRelayIP());
			CHECK_EQ(lobby.m_inBuffer[m].port, LOBBY);
			CHECK_MEM(lobby.m_inBuffer[m].data, announce, sizeof(announce));
			lobby.m_inBuffer[m].length = 0;
			arrived = TRUE;
		}
		b.service();
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	CHECK(arrived);

	// A packet to one address and port reaches that port only.
	const char order[] = "move out";
	CHECK(lobby.queueSend(b.getRelayIP(), GAME, (const UnsignedByte *)order, sizeof(order)));
	CHECK(lobby.update());
	CHECK(pumpUntil(*a, b, [&] { return (got = b.receive(GAME, buf, sizeof(buf), &fromIP, &fromPort)) > 0; }));
	CHECK_EQ(fromIP, a->getRelayIP());
	CHECK_EQ(fromPort, LOBBY);
	CHECK_EQ(b.receive(LOBBY, buf, sizeof(buf), &fromIP, &fromPort), 0);

	// A reset Transport has closed its port: what is sent to it now is not kept for anyone.
	lobby.reset();
	CHECK(!lobby.isOpen());
	CHECK(b.send(LOBBY, a->getRelayIP(), LOBBY, buf, got));
	pumpUntil(*a, b, [] { return false; });
	CHECK_EQ(a->receive(LOBBY, buf, sizeof(buf), &fromIP, &fromPort), 0);
	delete a;
}

TEST(relay_each_way_of_failing_has_its_own_status)
{
	if (!haveServer())
		return;
	RelayClient wrongKey;
	wrongKey.configure(server(), "not the key");
	UnsignedInt start = Clock_Milliseconds();
	CHECK(!wrongKey.connect(3000));
	CHECK_EQ(wrongKey.getStatus(), RelayClient::RELAY_WRONG_KEY);
	CHECK(Clock_Milliseconds() - start < 2000);		// told, not timed out

	RelayClient nobody;
	nobody.configure("127.0.0.1:9", key());				// discard: nothing answers there
	CHECK(!nobody.connect(300));
	CHECK_EQ(nobody.getStatus(), RelayClient::RELAY_UNREACHABLE);

	RelayClient unnamed;
	unnamed.configure(":8090", key());
	CHECK(!unnamed.connect(300));
	CHECK_EQ(unnamed.getStatus(), RelayClient::RELAY_NO_SUCH_HOST);

	// Packets offered while not connected are dropped, not queued and not an error.
	CHECK(nobody.send(8086, 0x0A580001u, 8086, (const UnsignedByte *)"x", 1));
}
