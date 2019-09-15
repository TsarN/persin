import ipaddress
import logging
import select
import socket
import struct
import asyncio
from socketserver import StreamRequestHandler, ThreadingTCPServer

from config import PROXY_RKN, UPSTREAM_PORT, UPSTREAM_HOST, HOST, PORT, PROXY_PORTS
from rkn import build_blocklist

SOCKS_VERSION = 0x05
BUF_SIZE = 4096
BLOCKLIST = None

ThreadingTCPServer.allow_reuse_address = True


def exchange_loop(client, remote):
    try:
        while True:
            ready = select.select([client, remote], [], [])[0]

            if client in ready:
                data = client.recv(BUF_SIZE)
                if remote.send(data) <= 0:
                    break

            if remote in ready:
                data = remote.recv(BUF_SIZE)
                if client.send(data) <= 0:
                    break
    except ConnectionResetError:
        pass


class SocksProxy(StreamRequestHandler):
    def authenticate(self):
        client_hello = self.connection.recv(2)
        version, n_methods = struct.unpack("!BB", client_hello)
        assert version == SOCKS_VERSION
        self.connection.recv(n_methods)
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0x00))

    def handle(self):
        self.authenticate()
        request_header = self.connection.recv(4)
        if len(request_header) != 4:
            print(request_header)
            return
        version, cmd, addr_type = struct.unpack("!BBxB", request_header)
        if cmd != 0x01:
            raise ValueError("invalid or unsupported command")
        if addr_type == 0x01:
            buf = self.connection.recv(4)
            request_header += buf
            dest_addr = str(ipaddress.IPv4Address(buf))
        elif addr_type == 0x04:
            buf = self.connection.recv(16)
            request_header += buf
            dest_addr = str(ipaddress.IPv6Address(buf))
        elif addr_type == 0x03:
            size = self.connection.recv(1)[0]
            buf = self.connection.recv(size)
            request_header += struct.pack("!B", size)
            request_header += buf
            try:
                dest_addr = socket.gethostbyname(buf.decode())
                addr_type = 0x01
            except socket.gaierror as err:
                logging.info(err)
                logging.info(f"while attempting to resolve {buf.decode()}")
                request_header += self.connection.recv(2)
                reply = struct.pack("!BBBBB", SOCKS_VERSION, 0x04, 0x00, 0x03, size) + buf + request_header[-2:]
                self.connection.sendall(reply)
                return
        else:
            raise ValueError("invalid addr_type")
        request_header += self.connection.recv(2)
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
            exchange_loop(self.connection, upstream)
        else:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((dest_addr, dest_port))
            bind_address, bind_port = remote.getsockname()
            bind_address = struct.unpack("!I", socket.inet_aton(bind_address))[0]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, addr_type, bind_address, bind_port)
            self.connection.sendall(reply)
            exchange_loop(self.connection, remote)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    if PROXY_RKN:
        BLOCKLIST = build_blocklist()
    with ThreadingTCPServer((HOST, PORT), SocksProxy) as server:
        try:
            logging.info(f"Started proxy on {HOST}:{PORT}")
            server.serve_forever()
        except Exception as err:
            server.shutdown()
            raise err
