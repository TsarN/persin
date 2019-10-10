import logging
import os
import time
import re
from urllib.request import urlretrieve

import pytricia

from persin.config import RKN_PATH, RKN_DUMP_URL
from persin.config import RKN_UPDATE_INTERVAL, PROXY_IPS

DUMP_PATH = os.path.join(RKN_PATH, "dump.csv")


def retrieve_blocklist():
    os.makedirs(RKN_PATH, exist_ok=True)
    urlretrieve(RKN_DUMP_URL, DUMP_PATH)


def is_blocklist_outdated():
    try:
        return time.time() - os.path.getmtime(DUMP_PATH) >= RKN_UPDATE_INTERVAL
    except OSError:
        return True


def build_blocklist():
    if is_blocklist_outdated():
        logging.info("RKN block list outdated, downloading it")
        retrieve_blocklist()
    url_re = re.compile(b'^https://([^/]+)')
    logging.info("Loading RKN block list")
    pyt = pytricia.PyTricia()
    domains = []
    with open(DUMP_PATH, "rb") as f:
        for line in f:
            parts = line.split(b";")
            if len(parts) <= 1:
                continue
            for ip in parts[0].split(b" | "):
                if b":" in ip or not ip:
                    continue
                try:
                    pyt[ip.decode()] = 1
                except ValueError:
                    continue
            if parts[2]:
                for url in parts[2].split(b" | "):
                    m = url_re.match(url)
                    if m:
                        domains.append(m[1])
    for ip in PROXY_IPS:
        pyt[ip] = 1
    logging.info(f"RKN block list loaded: {len(pyt)} addresses, {len(domains)} domains.")
    return pyt, domains
