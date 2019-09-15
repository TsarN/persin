import logging
import os
import time
from urllib.request import urlretrieve

import pytricia

from config import RKN_PATH, RKN_DUMP_URL, RKN_NXDOMAIN_URL, RKN_UPDATE_INTERVAL

DUMP_PATH = os.path.join(RKN_PATH, "dump.csv")
NXDOMAIN_PATH = os.path.join(RKN_PATH, "nxdomain.txt")


def retrieve_blocklist():
    os.makedirs(RKN_PATH, exist_ok=True)
    urlretrieve(RKN_DUMP_URL, DUMP_PATH)
    # urlretrieve(RKN_NXDOMAIN_URL, NXDOMAIN_PATH)


def is_blocklist_outdated():
    try:
        return time.time() - os.path.getmtime(DUMP_PATH) >= RKN_UPDATE_INTERVAL
    except OSError:
        return True


def build_blocklist():
    if is_blocklist_outdated():
        logging.info("RKN block list outdated, downloading it")
        retrieve_blocklist()
    logging.info("Loading RKN block list")
    pyt = pytricia.PyTricia()
    with open(DUMP_PATH, "rb") as f:
        for line in f:
            semicolon = line.find(b";")
            if semicolon == -1:
                continue
            for ip in line[:semicolon].split(b" | "):
                if b":" in ip or not ip:
                    continue
                try:
                    pyt[ip.decode()] = 1
                except ValueError:
                    continue
    logging.info(f"RKN block list loaded: {len(pyt)} addresses")
    return pyt
