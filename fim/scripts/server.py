#!/usr/bin/env python3

from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/events":
            self.send_response(404)
            self.end_headers()
            return

        print("\n──────── EVENT ────────")
        print(f"Path: {self.path}")

        print("Headers:")
        for key, val in self.headers.items():
            print(f"  {key}: {val}")

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        print("Body:")
        print(body.decode(errors="ignore"))
        print("───────────────────────\n")

        # Send only status, no body
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
