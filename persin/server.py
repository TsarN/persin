import ipaddress
import logging
import struct

from gevent.server import StreamServer
from gevent import socket, select

from persin.config import PROXY_RKN, UPSTREAM_PORT, UPSTREAM_HOST, HOST, PORT, PROXY_PORTS
from persin.rkn import build_blocklist

SOCKS_VERSION = 0x05
BUF_SIZE = 4096
BLOCKLIST = None
DOMAINS = []


def parse_client_hello(data):
    handshake, proto, size = struct.unpack("!BHH", data[:5])
    if handshake != 0x16:
        return
    data = data[5:]
    handshake, _, size, client_proto = struct.unpack("!BBHH", data[:6])
    if handshake != 0x01:
        return
    data = data[38:] # skip client random
    session_len = struct.unpack("!B", data[:1])[0]
    data = data[1+session_len:]
    cipher_len = struct.unpack("!H", data[:2])[0]
    data = data[2+cipher_len:]
    compression_len = struct.unpack("!B", data[:1])[0]
    data = data[1+compression_len:]
    extension_len = struct.unpack("!H", data[:2])[0]
    extensions = data[2:2+extension_len]

    while extensions:
        ext, size = struct.unpack("!HH", extensions[:4])
        data = extensions[4:4+size]
        extensions = extensions[4+size:]
        if ext != 0x00:
            continue
        _, record, size = struct.unpack("!HBH", data[:5])
        return data[5:5+size]


def exchange_loop(client, remote, tls_detect=False):
    try:
        while True:
            ready = select.select([client, remote], [], [])[0]

            if client in ready:
                data = client.recv(BUF_SIZE)
                if not data:
                    break
                if tls_detect:
                    tls_detect = False
                    try:
                        domain = parse_client_hello(data)
                        if domain in DOMAINS:
                            return data
                    except struct.error:
                        pass
                remote.sendall(data)

            if remote in ready:
                tls_detect = False
                data = remote.recv(BUF_SIZE)
                if not data:
                    break
                client.sendall(data)
    except ConnectionResetError:
        pass


def socks_handler(conn, address):
    client_hello = conn.recv(2)
    if not client_hello:
        return
    version, n_methods = struct.unpack("!BB", client_hello)
    assert version == SOCKS_VERSION
    conn.recv(n_methods)
    conn.sendall(struct.pack("!BB", SOCKS_VERSION, 0x00))

    request_header = conn.recv(4)
    if len(request_header) != 4:
        return
    version, cmd, addr_type = struct.unpack("!BBxB", request_header)
    if cmd != 0x01:
        raise ValueError("invalid or unsupported command")
    if addr_type == 0x01:
        buf = conn.recv(4)
        request_header += buf
        dest_addr = str(ipaddress.IPv4Address(buf))
    elif addr_type == 0x04:
        buf = conn.recv(16)
        request_header += buf
        dest_addr = str(ipaddress.IPv6Address(buf))
    elif addr_type == 0x03:
        size = conn.recv(1)[0]
        buf = conn.recv(size)
        request_header += struct.pack("!B", size)
        request_header += buf
        try:
            dest_addr = socket.gethostbyname(buf.decode())
            addr_type = 0x01
        except socket.gaierror as err:
            logging.info(err)
            logging.info(f"while attempting to resolve {buf.decode()}")
            request_header += conn.recv(2)
            reply = struct.pack("!BBBBB", SOCKS_VERSION, 0x04, 0x00, 0x03, size) + buf + request_header[-2:]
            conn.sendall(reply)
            return
    else:
        raise ValueError("invalid addr_type")
    request_header += conn.recv(2)
    dest_port = struct.unpack("!H", request_header[-2:])[0]
    do_proxy = False

    if PROXY_RKN and addr_type == 0x01:
        do_proxy |= dest_addr in BLOCKLIST
    do_proxy |= dest_port in PROXY_PORTS

    if do_proxy:
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.connect((UPSTREAM_HOST, UPSTREAM_PORT))
        upstream.sendall(struct.pack("!BBB", SOCKS_VERSION, 1, 0x00))
        version, auth_mode = upstream.recv(2)
        assert version == SOCKS_VERSION
        assert auth_mode == 0x00
        upstream.sendall(request_header)
        exchange_loop(conn, upstream)
        upstream.close()
        conn.close()
    else:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((dest_addr, dest_port))
        bind_address, bind_port = remote.getsockname()
        bind_address = struct.unpack("!I", socket.inet_aton(bind_address))[0]
        reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, addr_type, bind_address, bind_port)
        conn.sendall(reply)

        data = exchange_loop(conn, remote, dest_port == 443)
        if data:
            remote.close()
            # Upgrade to upstream
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.connect((UPSTREAM_HOST, UPSTREAM_PORT))
            upstream.sendall(struct.pack("!BBB", SOCKS_VERSION, 1, 0x00))
            version, auth_mode = upstream.recv(2)
            assert version == SOCKS_VERSION
            assert auth_mode == 0x00
            upstream.sendall(request_header)
            upstream.recv(10) # skip socks response
            upstream.sendall(data)
            exchange_loop(conn, upstream)
            upstream.close()
            conn.close()


def main():
    global BLOCKLIST, DOMAINS
    logging.basicConfig(level=logging.INFO)
    if PROXY_RKN:
        BLOCKLIST, DOMAINS = build_blocklist()
        DOMAINS = set(DOMAINS)
    server = StreamServer((HOST, PORT), socks_handler)
    logging.info(f"Started proxy on {HOST}:{PORT}")
    server.serve_forever()
