#!/usr/bin/env bash
#	Zero Hour Reforged
#	Copyright 2026 the Zero Hour Reforged contributors
#
#	This program is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# The relay end to end: Tools/Relay/zh_relay.py on a loopback port with a fresh key, and test_relay's
# relay tests against it (Tests/test_relay.cpp says what they check).
#
#   run_relay_check.sh <test_relay> <zh_relay.py>
#
# Without python3, exit 77, which ctest reports as Skipped.

set -u

test_relay="$1"
server="$2"

command -v python3 > /dev/null 2>&1 || { echo "run_relay_check: no python3, skipped"; exit 77; }

work=$(mktemp -d)
trap '[ -n "${pid:-}" ] && kill "$pid" 2> /dev/null; wait 2> /dev/null; rm -rf "$work"' EXIT

port=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
key=$(python3 "$server" --new-key)

python3 "$server" --bind 127.0.0.1 --port "$port" --key "$key" > "$work/relay.log" 2>&1 &
pid=$!
for _ in $(seq 50); do
	grep -q "listening" "$work/relay.log" 2> /dev/null && break
	sleep 0.1
done
if ! grep -q "listening" "$work/relay.log"; then
	echo "run_relay_check: the relay did not start:"
	cat "$work/relay.log"
	exit 1
fi

ZH_RELAY_TEST_SERVER="127.0.0.1:$port" ZH_RELAY_TEST_KEY="$key" "$test_relay" relay_
status=$?

echo "--- relay log"
cat "$work/relay.log"
exit $status
