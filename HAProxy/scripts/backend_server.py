#!/usr/bin/env python3
"""
Simple backend HTTP server for HAProxy security testing.
Echoes request details back — useful for detecting smuggling, header injection, etc.
"""

import http.server
import sys
import json
import threading
import time
from urllib.parse import urlparse, parse_qs

class EchoHandler(http.server.BaseHTTPRequestHandler):
    """Echoes all request details — essential for smuggling detection."""

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        self._handle_request()

    def do_PUT(self):
        self._handle_request()

    def do_DELETE(self):
        self._handle_request()

    def do_HEAD(self):
        self._handle_request(send_body=False)

    def do_OPTIONS(self):
        self._handle_request()

    def do_PATCH(self):
        self._handle_request()

    def _handle_request(self, send_body=True):
        # Read body if present
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''

        # Build response with full request details
        response = {
            'method': self.command,
            'path': self.path,
            'http_version': self.request_version,
            'headers': dict(self.headers),
            'body': body.decode('utf-8', errors='replace'),
            'body_length': len(body),
            'client_address': f'{self.client_address[0]}:{self.client_address[1]}',
            'timestamp': time.time()
        }

        response_body = json.dumps(response, indent=2).encode('utf-8')

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_body)))
        self.send_header('X-Backend-Server', 'echo-server')
        self.send_header('Connection', 'close')
        self.end_headers()

        if send_body:
            self.wfile.write(response_body)

    def log_message(self, format, *args):
        """Suppress default logging — we handle our own."""
        pass

def run_server(port):
    server = http.server.HTTPServer(('127.0.0.1', port), EchoHandler)
    print(f"[*] Backend echo server running on 127.0.0.1:{port}")
    server.serve_forever()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9090

    # Support running multiple backends
    ports = [int(p) for p in sys.argv[1:]] if len(sys.argv) > 1 else [9090, 9091]

    threads = []
    for p in ports:
        t = threading.Thread(target=run_server, args=(p,), daemon=True)
        t.start()
        threads.append(t)

    print(f"[*] Backend servers started on ports: {ports}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down backend servers")
