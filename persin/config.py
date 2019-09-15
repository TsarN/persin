import os

HOST = "127.0.0.1"
PORT = 1080

UPSTREAM_HOST = "10.9.0.1"
UPSTREAM_PORT = 1080

PROXY_PORTS = [80]
PROXY_RKN = True
RKN_UPDATE_INTERVAL = 24 * 60 * 60
RKN_DUMP_URL = "https://github.com/zapret-info/z-i/blob/master/dump.csv?raw=true"
RKN_NXDOMAIN_URL = "https://github.com/zapret-info/z-i/blob/master/nxdomain.txt?raw=true"
RKN_PATH = os.path.expanduser("~/.rkn")
