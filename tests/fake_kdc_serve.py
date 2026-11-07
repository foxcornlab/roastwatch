#!/usr/bin/env python3
"""Serve the scripted fixture KDC on loopback for demos and manual testing.

Prints the picked TCP port, serves until interrupted. This is fixture data
with a socket on it, not a real KDC: it answers only the principals its
handlers know about, and never leaves 127.0.0.1.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fake_kdc import FakeKDC


def main():
    kdc = FakeKDC()
    kdc.start()
    print("TCP %d" % kdc.tcp_port, flush=True)
    print("UDP %d" % kdc.udp_port, flush=True)
    try:
        kdc.join()
    except KeyboardInterrupt:
        kdc.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
