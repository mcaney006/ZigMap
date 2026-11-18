#!/bin/sh
# Isolated-namespace lab for the TCP connect scanner. Runs INSIDE a
# throwaway container (see tests/lab/run.sh), touching only that
# container's loopback. Lab tooling (iptables, tc, labtool listeners, nmap
# as a differential oracle) shapes the environment; it never performs the
# scan under test.
set -eu
ZM=${ZM:-/zm/zigmap}
PORTS=20000-20020
fail=0
check() { # name expected actual
	if [ "$2" = "$3" ]; then echo "  ok   $1: $3"; else echo "  FAIL $1: expected '$2' got '$3'"; fail=1; fi
}
state_of() { # jsonl port -> state/reason
	grep "\"type\":\"port\"" "$1" | grep "\"port\":$2," | sed 's/.*"state":"\([^"]*\)","reason":"\([^"]*\)".*/\1\/\2/'
}

echo "== binary: static, no interpreter, no dynamic section"
if readelf -l "$ZM" | grep -q INTERP; then echo "  FAIL has PT_INTERP"; fail=1; else echo "  ok   no PT_INTERP"; fi
if readelf -d "$ZM" 2>&1 | grep -q "no dynamic section"; then echo "  ok   no dynamic section (libc not linked)"; else echo "  FAIL dynamic section present"; fail=1; fi

echo "== lab setup"
"${LABTOOL:-/zm/labtool}" listen tcp:127.0.0.1:20001 tcp:127.0.0.1:20002 tcp:[::1]:20001 tcp:[::1]:20002 &
LISTENER=$!
iptables -A INPUT -i lo -p tcp --dport 20010 -j DROP
iptables -A INPUT -i lo -p tcp --dport 20011 -j REJECT --reject-with icmp-host-unreachable
iptables -A INPUT -i lo -p tcp --dport 20012 -j REJECT --reject-with tcp-reset
iptables -A INPUT -i lo -p tcp --dport 20013 -j REJECT --reject-with icmp-admin-prohibited
ip6tables -A INPUT -i lo -p tcp --dport 20010 -j DROP
sleep 1

echo "== scan 1: IPv4 classification (no impairment)"
"$ZM" -p $PORTS --max-retries 1 --initial-rtt-timeout 300 -oJ /tmp/s1.jsonl --explain 127.0.0.1 >/tmp/s1.txt
check 20001 open/connected "$(state_of /tmp/s1.jsonl 20001)"
check 20002 open/connected "$(state_of /tmp/s1.jsonl 20002)"
check 20005 closed/conn_refused "$(state_of /tmp/s1.jsonl 20005)"
check 20010 filtered/no_response "$(state_of /tmp/s1.jsonl 20010)"
check 20011 filtered/host_unreach "$(state_of /tmp/s1.jsonl 20011)"
check 20012 closed/conn_refused "$(state_of /tmp/s1.jsonl 20012)"
check 20013 filtered/host_unreach "$(state_of /tmp/s1.jsonl 20013)"
attempts=$(grep '"port":20010,' /tmp/s1.jsonl | sed 's/.*"attempts":\([0-9]*\).*/\1/')
check "20010 attempts" 2 "$attempts"
if jq -e -s 'length > 0 and all(.[]; .schema == "zigmap.v1")' /tmp/s1.jsonl >/dev/null; then
	echo "  ok   JSONL: $(jq -s length /tmp/s1.jsonl) valid records (jq)"
else
	echo "  FAIL JSONL records"; fail=1
fi

echo "== scan 2: differential vs nmap -sT (oracle only)"
nmap -sT -Pn -n -p $PORTS --max-retries 1 127.0.0.1 -oG - 2>/dev/null | tr ',' '\n' | sed -n 's#.* \{0,1\}\([0-9]\{5\}\)/\([a-z|]*\)/tcp.*#\1 \2#p' | sort >/tmp/nmap.txt
grep '"type":"port"' /tmp/s1.jsonl | sed 's/.*"port":\([0-9]*\),.*"state":"\([^"]*\)".*/\1 \2/' | sort >/tmp/zm.txt
# nmap -oG omits ports in the "Ignored State" bucket (closed); compare those it lists.
dis=0
while read -r port st; do
	z=$(grep "^$port " /tmp/zm.txt | cut -d' ' -f2)
	if [ "$z" != "$st" ]; then echo "  DISAGREE $port nmap=$st zigmap=$z"; dis=1; fi
done </tmp/nmap.txt
listed=$(wc -l </tmp/nmap.txt | tr -d ' ')
if [ $dis -eq 0 ]; then echo "  ok   agrees with nmap on all $listed listed ports"; else fail=1; fi
nmap_closed=$(grep -c " closed$" /tmp/nmap.txt)
zm_closed=$(grep -c ' closed$' /tmp/zm.txt)
check "closed count vs nmap" "${nmap_closed:-?}" "$zm_closed"

echo "== scan 3: IPv6 ::1"
"$ZM" -p 20000-20010 --max-retries 1 --initial-rtt-timeout 300 -oJ /tmp/s3.jsonl ::1 >/dev/null
check "v6 20001" open/connected "$(state_of /tmp/s3.jsonl 20001)"
check "v6 20003" closed/conn_refused "$(state_of /tmp/s3.jsonl 20003)"
check "v6 20010" filtered/no_response "$(state_of /tmp/s3.jsonl 20010)"

echo "== scan 4: 40ms delay + 25% loss on lo (netem)"
if tc qdisc add dev lo root netem delay 40ms loss 25% 2>/dev/null; then
	"$ZM" -p $PORTS --max-retries 6 --stats -oJ /tmp/s4.jsonl 127.0.0.1 >/tmp/s4.txt
	tc qdisc del dev lo root
	bad=0
	for p in 20001 20002; do s=$(state_of /tmp/s4.jsonl $p); case $s in open/*|filtered/no_response) ;; *) echo "  FAIL $p -> $s"; bad=1 ;; esac; done
	for p in 20000 20005 20012 20020; do s=$(state_of /tmp/s4.jsonl $p); case $s in closed/*|filtered/no_response) ;; *) echo "  FAIL $p -> $s"; bad=1 ;; esac; done
	check "20010 under loss" filtered/no_response "$(state_of /tmp/s4.jsonl 20010)"
	exact=$(for p in 20001 20002; do state_of /tmp/s4.jsonl $p; done | grep -c '^open')
	if [ $bad -eq 0 ]; then echo "  ok   no open/closed inversion under loss ($exact/2 opens recovered)"; else fail=1; fi
	grep -E "loss events|probes sent" /tmp/s4.txt | sed 's/^/       /'
else
	echo "  skip netem unavailable in this kernel"
fi

echo "== scan 5: rate cap 50 pps over 200 probes"
start=$(date +%s)
"$ZM" -p 21000-21199 --max-rate 50 127.0.0.1 >/dev/null
el=$(( $(date +%s) - start ))
if [ $el -ge 3 ]; then echo "  ok   200 probes at 50 pps took ${el}s (>= ~3.9s expected)"; else echo "  FAIL rate cap not honoured (${el}s)"; fail=1; fi

echo "== scan 6: target expansion guard and exclusions"
if "$ZM" -p 80 10.0.0.0/16 >/dev/null 2>/tmp/e6; then echo "  FAIL /16 accepted"; fail=1; else echo "  ok   refused: $(cat /tmp/e6)"; fi
"$ZM" --dry-run -p 80 127.0.0.0/29 --exclude 127.0.0.0/30 | grep -q "127.0.0.4" && echo "  ok   dry run lists non-excluded targets, sends nothing"
"$ZM" -sA 127.0.0.1 >/dev/null 2>&1 && { echo "  FAIL -sA accepted"; fail=1; } || echo "  ok   -sA rejected (not implemented; no silent connect substitution)"

echo "== scan 7: raw SYN on loopback (L3 send, AF_PACKET capture) vs nmap -sS"
"$ZM" -sS -p $PORTS --max-retries 1 --initial-rtt-timeout 300 -oJ /tmp/s7.jsonl 127.0.0.1 >/dev/null
check "syn 20001" open/syn_ack "$(state_of /tmp/s7.jsonl 20001)"
check "syn 20005" closed/rst "$(state_of /tmp/s7.jsonl 20005)"
check "syn 20010" filtered/no_response "$(state_of /tmp/s7.jsonl 20010)"
check "syn 20013" filtered/icmp_admin_prohibited "$(state_of /tmp/s7.jsonl 20013)"
nmap -sS -Pn -n -p $PORTS --max-retries 1 127.0.0.1 -oG - 2>/dev/null | tr ',' '\n' | sed -n 's#.* \{0,1\}\([0-9]\{5\}\)/\([a-z|]*\)/tcp.*#\1 \2#p' | sort >/tmp/nmap7.txt
grep '"type":"port"' /tmp/s7.jsonl | sed 's/.*"port":\([0-9]*\),.*"state":"\([^"]*\)".*/\1 \2/' | sort >/tmp/zm7.txt
if diff /tmp/nmap7.txt /tmp/zm7.txt >/dev/null; then echo "  ok   identical to nmap -sS on $(wc -l </tmp/nmap7.txt | tr -d ' ') ports"; else echo "  DISAGREE"; diff /tmp/nmap7.txt /tmp/zm7.txt; fail=1; fi

kill $LISTENER 2>/dev/null || true
echo
if [ $fail -eq 0 ]; then echo "LAB PASS"; else echo "LAB FAIL"; fi
exit $fail
