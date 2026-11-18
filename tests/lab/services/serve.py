# Lab-only service fakes for -sV tests. Not part of the scanner.
import socket, ssl, threading, time, http.server, socketserver, struct, sys, os

def banner_server(port, banner):
    s = socket.socket(socket.AF_INET6 if ':' in HOST else socket.AF_INET)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, port)); s.listen(64)
    while True:
        c, _ = s.accept()
        try: c.sendall(banner); time.sleep(0.2)
        except Exception: pass
        c.close()

def dns_tcp(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, port)); s.listen(16)
    while True:
        c, _ = s.accept()
        try:
            n = struct.unpack('>H', c.recv(2))[0]; q = c.recv(n)
            ver = b'9.18-lab'
            ans = q[:2] + b'\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00' + q[12:] + b'\xc0\x0c\x00\x10\x00\x03\x00\x00\x00\x00' + struct.pack('>H', len(ver)+1) + bytes([len(ver)]) + ver
            c.sendall(struct.pack('>H', len(ans)) + ans)
        except Exception: pass
        c.close()

class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass

def http_server(port):
    socketserver.TCPServer.allow_reuse_address = True
    socketserver.TCPServer((HOST, port), H).serve_forever()

def tls_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain('/tmp/cert.pem', '/tmp/key.pem')
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, port)); s.listen(16)
    while True:
        c, _ = s.accept()
        try:
            t = ctx.wrap_socket(c, server_side=True); t.recv(10); t.close()
        except Exception: pass

HOST = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
for fn, args in ((banner_server, (2222, b'SSH-2.0-OpenSSH_9.6p1 lab\r\n')),
                 (banner_server, (2121, b'220 (vsFTPd 3.0.5)\r\n')),
                 (banner_server, (2525, b'220 mail.lab ESMTP Postfix\r\n')),
                 (dns_tcp, (53,)), (http_server, (8080,)), (tls_server, (8443,))):
    threading.Thread(target=fn, args=args, daemon=True).start()
open('/tmp/ready', 'w').close()
while True: time.sleep(60)
