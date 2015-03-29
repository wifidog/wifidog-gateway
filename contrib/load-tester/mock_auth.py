#!/usr/bin/env python
# -*- coding: utf -*-

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

import random

def main():
    server = HTTPServer(('', 8080), AuthHandler)
    server.serve_forever()


class AuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        if "ping" in self.path:
            self.wfile.write("Pong\n")
        else:
            self.wfile.write("Auth: %s\n" % random.choice([0,1]))
        return

if __name__ == "__main__":
    main()
