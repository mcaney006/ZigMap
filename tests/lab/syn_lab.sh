#!/bin/sh
# Raw-backend lab: throwaway containers on dedicated Docker bridges (veth
# per container, real Ethernet, ARP and NDP). The target shapes itself with
# listeners, lab service fakes and iptables; the scanner runs Zigmap and,
# as a differential oracle only, nmap. Lab tooling never scans.
#   ARCH=aarch64|x86_64 (default aarch64)
set -eu
ARCH=${ARCH:-aarch64}
case $ARCH in aarch64) PLATFORM=linux/arm64 ;; x86_64) PLATFORM=linux/amd64 ;; *) echo "unknown ARCH $ARCH" >&2; exit 2 ;; esac
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
N=$(( $$ % 200 + 10 ))
NET=zmlab-$$
NETB=zmlab-b-$$
PFX=10.231.$N
PFXB=10.232.$N
V6PFX=fd5a:$N::
TARGET_IP=$PFX.10
TARGET_B=$PFXB.10
SCANNER_IP=$PFX.20
SILENT_IP=$PFX.99
cd "$ROOT"
zig build install lab-tools -Dtarget=$ARCH-linux -Doptimize=ReleaseSafe --prefix "zig-out/$ARCH-linux"

cleanup() {
	docker rm -f zm-target-$$ >/dev/null 2>&1 || true
	docker network rm $NET >/dev/null 2>&1 || true
	docker network rm $NETB >/dev/null 2>&1 || true
	rm -f "${capout:-}"
}
trap cleanup EXIT
V6=0
if docker network create --ipv6 --subnet $PFX.0/24 --subnet ${V6PFX}/64 $NET >/dev/null 2>&1; then V6=1; else docker network create --subnet $PFX.0/24 $NET >/dev/null; fi
docker network create --subnet $PFXB.0/24 $NETB >/dev/null

TARGET_V6_ARGS=""
[ $V6 -eq 1 ] && TARGET_V6_ARGS="--ip6 ${V6PFX}10"
docker create --name zm-target-$$ --platform $PLATFORM --network $NET --ip $TARGET_IP $TARGET_V6_ARGS --cap-add NET_ADMIN \
	-v "$ROOT/zig-out/$ARCH-linux/bin:/zm:ro" alpine:3.20 sh -c '
apk add -q iptables ip6tables openssl >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key.pem -out /tmp/cert.pem -days 30 -subj /CN=lab.zigmap.test -addext subjectAltName=DNS:lab.zigmap.test 2>/dev/null
iptables -A INPUT -p tcp --dport 20010 -j DROP
iptables -A INPUT -p tcp --dport 20011 -j REJECT --reject-with icmp-host-unreachable
iptables -A INPUT -p tcp --dport 20012 -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp --dport 20013 -j REJECT --reject-with icmp-admin-prohibited
iptables -A INPUT -p udp --dport 20010 -j DROP
V6L=""
[ -e /proc/net/if_inet6 ] && V6L="tcp6only:[::]:20001"
/zm/labtool listen tcp:0.0.0.0:20001 tcp:0.0.0.0:20002 udp-echo:0.0.0.0:20053 $V6L &
openssl s_server -www -quiet -accept 8443 -cert /tmp/cert.pem -key /tmp/key.pem </dev/null >/dev/null 2>&1 &
/zm/labtool wait-tcp 127.0.0.1 8443
exec /zm/labtool serve 0.0.0.0' >/dev/null
docker network connect --ip $TARGET_B $NETB zm-target-$$
docker start zm-target-$$ >/dev/null
i=0; until docker exec zm-target-$$ test -f /tmp/ready 2>/dev/null; do i=$((i+1)); [ $i -gt 150 ] && { echo "target never became ready"; exit 1; }; sleep 1; done

SCANNER_V6_ARGS=""
[ $V6 -eq 1 ] && SCANNER_V6_ARGS="--ip6 ${V6PFX}20"
set +e
docker run --rm --platform $PLATFORM --network $NET --ip $SCANNER_IP $SCANNER_V6_ARGS --cap-add NET_ADMIN \
	-e T=$TARGET_IP -e TB=$TARGET_B -e PFXB=$PFXB -e SILENT=$SILENT_IP -e V6=$V6 -e T6=${V6PFX}10 \
	-v "$ROOT/zig-out/$ARCH-linux/bin:/zm:ro" alpine:3.20 sh -c '
set -u
apk add -q nmap iproute2-tc jq libxml2-utils >/dev/null
fail=0
check() { if [ "$2" = "$3" ]; then echo "  ok   $1: $3"; else echo "  FAIL $1: expected $2 got $3"; fail=1; fi; }
st() { grep "\"type\":\"port\"" "$1" | grep "\"port\":$2," | sed "s/.*\"state\":\"\([^\"]*\)\",\"reason\":\"\([^\"]*\)\".*/\1\/\2/"; }
svcname() { grep "\"type\":\"port\"" "$1" | grep "\"port\":$2," | sed -n "s/.*\"service\":{\"name\":\"\([^\"]*\)\",\"product\":\"\([^\"]*\)\",\"version\":\"\([^\"]*\)\".*/\1 \2 \3/p"; }
oskey() { grep "\"type\":\"host\"" "$1" | sed -n "s/.*\"os\":{\"confidence\":\"\([^\"]*\)\",\"name\":\"\([^\"]*\)\".*/\1 \2/p"; }

echo "== SYN scan over veth/bridge"
/zm/zigmap -sS -p 20000-20020 --max-retries 1 --initial-rtt-timeout 300 --stats -oJ /tmp/s.jsonl $T > /tmp/s.txt
grep -E "Raw backend|matched tcp|bad checksum" /tmp/s.txt | sed "s/^/       /"
check 20001 open/syn_ack "$(st /tmp/s.jsonl 20001)"
check 20002 open/syn_ack "$(st /tmp/s.jsonl 20002)"
check 20005 closed/rst "$(st /tmp/s.jsonl 20005)"
check 20010 filtered/no_response "$(st /tmp/s.jsonl 20010)"
check 20011 filtered/icmp_host_unreach "$(st /tmp/s.jsonl 20011)"
check 20012 closed/rst "$(st /tmp/s.jsonl 20012)"
check 20013 filtered/icmp_admin_prohibited "$(st /tmp/s.jsonl 20013)"

echo "== differential vs nmap -sS (oracle only)"
nmap -sS -Pn -n -p 20000-20020 --max-retries 1 $T -oG - 2>/dev/null | tr "," "\n" | sed -n "s#.* \{0,1\}\([0-9]\{5\}\)/\([a-z|]*\)/tcp.*#\1 \2#p" | sort > /tmp/nmap.txt
grep "\"type\":\"port\"" /tmp/s.jsonl | sed "s/.*\"port\":\([0-9]*\),.*\"state\":\"\([^\"]*\)\".*/\1 \2/" | sort > /tmp/zm.txt
if diff /tmp/nmap.txt /tmp/zm.txt >/tmp/d.txt; then echo "  ok   identical port states for $(wc -l </tmp/nmap.txt | tr -d " ") ports"; else echo "  DISAGREE:"; cat /tmp/d.txt; fail=1; fi

echo "== capture paths agree (ring+bpf, ring, recvmsg)"
for m in "ring" "ring --no-bpf" "recvmsg --no-bpf"; do
  /zm/zigmap -sS --capture $m -p 20000-20020 --max-retries 1 --initial-rtt-timeout 300 -oJ /tmp/c.jsonl $T >/dev/null
  grep "\"type\":\"port\"" /tmp/c.jsonl | sed "s/.*\"port\":\([0-9]*\),.*\"state\":\"\([^\"]*\)\".*/\1 \2/" | sort > /tmp/cm.txt
  if diff /tmp/zm.txt /tmp/cm.txt >/dev/null; then echo "  ok   --capture $m: same 21 states"; else echo "  FAIL --capture $m differs"; fail=1; fi
done

echo "== service and OS detection (-sS -sV -O)"
/zm/zigmap -sS -sV -O -p 53,2121,2222,2525,8080,8443,20005 --initial-rtt-timeout 300 -oJ /tmp/v.jsonl --json /tmp/v.json -oX /tmp/v.xml $T >/tmp/v.txt
check "53 service" "domain  9.18-lab" "$(svcname /tmp/v.jsonl 53)"
check "2121 service" "ftp vsftpd 3.0.5" "$(svcname /tmp/v.jsonl 2121)"
check "2222 service" "ssh OpenSSH 9.6p1" "$(svcname /tmp/v.jsonl 2222)"
check "2525 service" "smtp Postfix " "$(svcname /tmp/v.jsonl 2525)"
check "8080 service" "http zigmap-lab 1.0" "$(svcname /tmp/v.jsonl 8080)"
check "8443 service" "ssl/tls TLS1.2 " "$(svcname /tmp/v.jsonl 8443)"
grep -q "cn=lab.zigmap.test" /tmp/v.jsonl && echo "  ok   TLS certificate CN extracted" || { echo "  FAIL TLS CN"; fail=1; }
case "$(oskey /tmp/v.jsonl)" in "strong Linux"*|"probable Linux"*) echo "  ok   OS: $(oskey /tmp/v.jsonl)";; *) echo "  FAIL OS: $(oskey /tmp/v.jsonl)"; fail=1;; esac
jq -e ".schema == \"zigmap.v1\" and (.hosts | length) == 1" /tmp/v.json >/dev/null && echo "  ok   --json document parses (jq)" || { echo "  FAIL --json document"; fail=1; }
check "-oX document parses (xmllint), ports under /zigmaprun/host" 7 "$(xmllint --xpath "count(/zigmaprun/host/port)" /tmp/v.xml 2>&1)"

echo "== UDP scan (target kernel rate-limits ICMP unreachables)"
/zm/zigmap -sU -p 20000-20020,20053 --max-retries 2 --initial-rtt-timeout 300 --stats -oJ /tmp/u.jsonl $T >/tmp/u.txt
check "udp 20053" open/udp_reply "$(st /tmp/u.jsonl 20053)"
check "udp 20010" open\|filtered/no_response "$(st /tmp/u.jsonl 20010)"
closed=$(grep "\"type\":\"port\"" /tmp/u.jsonl | grep -c "\"state\":\"closed\"")
check "udp closed ports proven by ICMP" 20 "$closed"
grep -E "paced hosts" /tmp/u.txt | sed "s/^/       /"
nmap -sU -Pn -n -p 20000-20020,20053 $T -oG - 2>/dev/null | tr "," "\n" | sed -n "s#.* \{0,1\}\([0-9]\{5\}\)/\([a-z|]*\)/udp.*#\1 \2#p" | sort > /tmp/nu.txt
grep "\"type\":\"port\"" /tmp/u.jsonl | sed "s/.*\"port\":\([0-9]*\),.*\"state\":\"\([^\"]*\)\".*/\1 \2/" | sort > /tmp/zu.txt
if diff /tmp/nu.txt /tmp/zu.txt >/tmp/du.txt; then echo "  ok   identical to nmap -sU on $(wc -l </tmp/nu.txt | tr -d " ") ports"; else echo "  DISAGREE with nmap -sU:"; cat /tmp/du.txt; fail=1; fi

echo "== host discovery (-sn): on-link, silent on-link, routed"
ip route add $PFXB.0/24 via $T
# Earlier scans left the target in this container'"'"'s neighbour cache; a cached
# entry is not fresh evidence, so Zigmap would (correctly) fall back to ICMP.
# Flush this namespace'"'"'s cache so on-link discovery has to ARP.
ip neigh flush dev eth0 >/dev/null
/zm/zigmap -sS -sn -oJ /tmp/h.jsonl $T $SILENT $TB >/tmp/h.txt 2>&1
hs() { grep "\"host\":\"$2\"" "$1" | sed -n "s/.*\"status\":\"\([^\"]*\)\",\"discovery\":\"\([^\"]*\)\".*/\1\/\2/p"; }
check "on-link $T" up/arp_reply "$(hs /tmp/h.jsonl $T)"
check "silent $SILENT" down/no_neighbor_reply "$(hs /tmp/h.jsonl $SILENT)"
case "$(hs /tmp/h.jsonl $TB)" in up/echo_reply|up/syn_ack|up/rst) echo "  ok   routed $TB: $(hs /tmp/h.jsonl $TB)";; *) echo "  FAIL routed $TB: $(hs /tmp/h.jsonl $TB)"; fail=1;; esac
/zm/zigmap -sT -sn -oJ /tmp/hc.jsonl $T $SILENT >/dev/null 2>&1
check "unprivileged discovery $T" up/conn_refused "$(hs /tmp/hc.jsonl $T)"
check "unprivileged discovery $SILENT" down/no_response "$(hs /tmp/hc.jsonl $SILENT)"

if [ "$V6" = 1 ]; then
  echo "== IPv6 SYN over Ethernet (NDP)"
  /zm/zigmap -sS -p 20000-20003 --max-retries 1 --initial-rtt-timeout 300 -oJ /tmp/v6.jsonl $T6 >/tmp/v6.txt 2>&1
  check "v6 20001" open/syn_ack "$(st /tmp/v6.jsonl 20001)"
  check "v6 20000" closed/rst "$(st /tmp/v6.jsonl 20000)"
  if hs /tmp/v6.jsonl $T6 | grep -q "completed/nd_reply\|completed/none"; then echo "  ok   discovery: $(grep "\"type\":\"host\"" /tmp/v6.jsonl | sed -n "s/.*\"discovery\":\"\([^\"]*\)\".*/\1/p")"; else echo "  FAIL v6 discovery: $(hs /tmp/v6.jsonl $T6)"; fail=1; fi
else
  echo "== IPv6: Docker IPv6 networks unavailable here; skipped"
fi

echo "== 30 ms delay + 20% loss on scanner eth0"
tc qdisc add dev eth0 root netem delay 30ms loss 20%
/zm/zigmap -sS -p 20000-20020 --max-retries 5 --stats -oJ /tmp/l.jsonl $T > /tmp/l.txt
tc qdisc del dev eth0 root
bad=0
for p in 20001 20002; do case $(st /tmp/l.jsonl $p) in open/*|filtered/no_response) ;; *) bad=1; echo "  FAIL $p $(st /tmp/l.jsonl $p)";; esac; done
for p in 20000 20005 20012 20020; do case $(st /tmp/l.jsonl $p) in closed/*|filtered/no_response) ;; *) bad=1; echo "  FAIL $p $(st /tmp/l.jsonl $p)";; esac; done
[ $bad -eq 0 ] && echo "  ok   no open/closed inversion under loss" || fail=1
grep -E "probes sent|loss events" /tmp/l.txt | sed "s/^/       /"

[ $fail -eq 0 ] && echo "SCANNER CHECKS PASS" || echo "SCANNER CHECKS FAIL"
exit $fail'
rc=$?
set -e

echo "== missing CAP_NET_RAW"
capout=$(mktemp)
set +e
docker run --rm --platform $PLATFORM --network $NET --cap-drop NET_RAW -v "$ROOT/zig-out/$ARCH-linux/bin:/zm:ro" alpine:3.20 /zm/zigmap -sS -p 22 $TARGET_IP >"$capout" 2>&1
code=$?
set -e
if [ $code -eq 77 ] && grep -q CAP_NET_RAW "$capout"; then echo "  ok   exit 77 with explanation, no fallback"; else echo "  FAIL exit $code"; cat "$capout"; rc=1; fi
[ $rc -eq 0 ] && echo "RAW LAB PASS" || echo "RAW LAB FAIL"
exit $rc
