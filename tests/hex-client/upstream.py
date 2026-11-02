#!/usr/bin/env python3
"""Controlled signed public-Hex fixture. Test private key is deliberately public.

Preserve the complete official Jason record (dependencies/checksums included),
replace publication dates, and sign using the isolated fixture trust anchor.
"""
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent

def varint(n):
    result = bytearray()
    while n > 127:
        result.append((n & 127) | 128)
        n >>= 7
    result.append(n)
    return bytes(result)

def read_varint(data, pos):
    value, shift = 0, 0
    while True:
        b = data[pos]
        pos += 1
        value |= (b & 127) << shift
        if b < 128:
            return value, pos
        shift += 7

def fields(data):
    pos = 0
    while pos < len(data):
        start = pos
        tag, pos = read_varint(data, pos)
        wire = tag & 7
        if wire == 2:
            size, pos = read_varint(data, pos)
            value = data[pos:pos+size]
            pos += size
        elif wire == 0:
            value, pos = read_varint(data, pos)
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            value = data[pos:pos+size]
            pos += size
        else:
            raise ValueError(f"unsupported wire type {wire}")
        yield tag >> 3, wire, value, data[start:pos]

def field(n, data):
    return varint(n << 3 | 2) + varint(len(data)) + data

def package_record(age_days):
    raw = (ROOT / "fixtures/jason.record").read_bytes()
    payload = next(v for n, _, v, _ in fields(gzip.decompress(raw)) if n == 1)
    timestamp = varint(8) + varint(int(time.time()) - age_days * 86400) + b"\x10\x00"
    rebuilt = bytearray()
    for n, _, release, original in fields(payload):
        if n == 1:
            # Only override dates; retain exact original dependencies/checksums.
            release = b"".join(raw for tag, _, _, raw in fields(release) if tag != 7)
            rebuilt.extend(field(1, release + field(7, timestamp)))
        else:
            rebuilt.extend(original)
    signature = subprocess.run(["openssl", "dgst", "-sha512", "-sign",
                                str(ROOT / "fixtures/test-private.pem")],
                               input=rebuilt, capture_output=True, check=True).stdout
    return gzip.compress(field(1, bytes(rebuilt)) + field(2, signature), mtime=0)

class Server(ThreadingHTTPServer):
    age_days = 1
    available = True

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.server.available:
            self.send_error(503)
            return
        if self.path == "/packages/jason":
            body = package_record(self.server.age_days)
        elif self.path == "/tarballs/jason-1.4.4.tar":
            body = (ROOT / "fixtures/jason-1.4.4.tar").read_bytes()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_args):
        pass
