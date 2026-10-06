# Relay server: network games over the internet

The LAN screen finds games by broadcasting on your local network and then sends every packet straight
to the other players' machines. Neither gets through a home router, which is why network games have
been LAN only.

`zh_relay.py` is a small server that fixes that for you and your friends. Run it on any machine with a
public address, give your players its address and key, and their LAN screens meet there instead. You
get the same lobby, chat, settings, map transfer and match as on a LAN. Nobody forwards a port or
installs a virtual network, because every connection goes out from the player's side to the server.

It is private. Only someone who holds the key gets in, and the key is never sent over the network:
the game and the server each prove they know it. Nothing is stored on disk.

## What you need

- A machine with a public IPv4 address that stays on while you play. A small rented Linux server
  (a VPS) from any provider is plenty: game traffic is orders, not pictures, and the server only passes
  packets along. Pick one in a region roughly central to your players, since every packet goes
  through it.
- Python 3.9 or newer on it. Ubuntu 22.04, Debian 12 and their successors already have it. Nothing else
  needs installing.
- Every player on the same build of the game. The LAN screen already refuses a game between
  different builds.

## Set it up

On the server, as a user who can `sudo`:

```sh
# 1. The server itself: one file, standard library only.
curl -fsSLO https://raw.githubusercontent.com/mhalloin/CnCGeneralsZH-Reforged/main/Tools/Relay/zh_relay.py
#    (or copy Tools/Relay/zh_relay.py over from your checkout with scp)

# 2. A key.  This is what your players type into RelayKey.  Keep it to your group.
python3 zh_relay.py --new-key | sudo install -D -m 600 /dev/stdin /etc/zh-relay/relay.key
sudo cat /etc/zh-relay/relay.key

# 3. Try it in the foreground.  Ctrl+C stops it.
sudo python3 zh_relay.py --key-file /etc/zh-relay/relay.key
#    2026-10-06 19:27:22 relay listening on UDP 0.0.0.0:8090
```

Open UDP port 8090 in front of it, both in the provider's firewall (its web console usually calls this
a security group or firewall rules) and on the machine itself if it runs one:

```sh
sudo ufw allow 8090/udp      # only if ufw is active: sudo ufw status
```

Then run it as a service, so it survives reboots and restarts itself if it ever stops:

```sh
sudo install -D -m 644 zh_relay.py /opt/zh-relay/zh_relay.py
sudo cp zh-relay.service /etc/systemd/system/      # Tools/Relay/zh-relay.service
sudo systemctl enable --now zh-relay
journalctl -u zh-relay -f                          # who joins and leaves, live
```

## Each player

Add two lines to `Options.ini` in the Zero Hour Data folder (`Documents\Command and Conquer Generals
Zero Hour Data` on Windows; the main README names the Mac and Linux folders), using the server's address
and the key from step 2:

```ini
RelayServer = 203.0.113.10:8090
RelayKey = the-key-from-step-2
```

A name works as well as a number (`RelayServer = relay.example.com:8090`), and `:8090` can be left off
when the server uses its default port. Then start the game and open **Network**, **LAN** as usual. The
chat box says *Playing over the internet through the relay server at ...*, and every game hosted by
anyone on the server shows up in the list.

For a single run without editing the file, the same two settings go on the command line:
`-relay 203.0.113.10:8090 -relaykey the-key`.

Remove the two lines to go back to playing on your local network.

## When it does not connect

The LAN screen says what went wrong and goes back to the main menu.

| Message | Usually |
|:--|:--|
| *could not be found* | `RelayServer` has a typo, or the name does not resolve. |
| *did not answer* | The server is not running, UDP 8090 is closed in the provider's firewall or `ufw`, or the address is wrong. `journalctl -u zh-relay` shows nothing arriving. |
| *turned your key down* | `RelayKey` does not match the server's key (it is case sensitive). The server log says `refused ... (wrong key)`. After five wrong keys in a minute the server ignores that address for a minute. |
| *is full* | More players are connected than `--max-players` allows (16 by default). |

A player whose connection drops, or a server that restarts, reconnects on its own within a few seconds
and keeps the same place in the room.

## Server options

```text
--key-file PATH     the key, read from a file (recommended)
--key KEY           the key itself; visible to other users of the machine
                    (or set ZH_RELAY_KEY in the environment)
--port N            UDP port, 8090 by default
--bind ADDR         address to listen on, all of them by default
--max-players N     players connected at once, lobby included; 16 by default, enough
                    for a full 12-player custom map with room to spare
--timeout S         seconds of silence before a player is dropped, 60 by default
--new-key           print a fresh random key and exit
```

To change the key, write a new one to `/etc/zh-relay/relay.key`, run `sudo systemctl restart zh-relay`
and give your players the new one.

## What it does and does not protect

- Only key holders can join, see the game list or reach anyone on the server.
- The key never crosses the network, and each side proves it knows it, so a server that does not know
  the key cannot pass itself off as yours.
- Game traffic is not encrypted, the same as on a LAN. Someone who can watch your connection could see
  what is sent, but cannot join without the key.
- Everyone on one server shares one lobby. Run a second server on another port, with another key, for
  a second group.

## How it works

Each player gets an address of its own inside the relay, in `10.88.0.0/16`. The game uses it on the LAN
screen as if it were a network card's: a lobby announcement to the whole LAN reaches everyone on the
server, and a packet to another player's relay address reaches that player. The game's side is
`GeneralsMD/Code/GameEngine/Source/GameNetwork/Relay.cpp`, and the protocol is described at the top of
`Relay.h`. The tests are `test_zh_relay.py` here (`python3 -m unittest discover -s Tools/Relay`) and
`GeneralsMD/Code/Tests/run_relay_check.sh`, which runs the game's client against this server.
