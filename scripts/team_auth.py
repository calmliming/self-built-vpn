"""Local Hysteria2 auth: preserve owner access; independently revoke team members."""
import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

USERS = Path('/etc/self-vpn/team-auth-users.json')

def authenticate(value, users):
    candidate = hashlib.sha256(value.encode()).hexdigest()
    for user_id, hashed in users.items():
        if hmac.compare_digest(candidate, hashed):
            return user_id
    return ''

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.connection.settimeout(3)
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if self.path != '/auth' or not 0 < length <= 8192:
                raise ValueError
            request = json.loads(self.rfile.read(length))
            value = request.get('auth', '')
            if not isinstance(value, str) or not 1 <= len(value) <= 1024:
                raise ValueError
            user_id = authenticate(value, json.loads(USERS.read_text()))
            body = json.dumps({'ok': bool(user_id), 'id': user_id}).encode()
            self.send_response(200)
        except (ValueError, OSError, TypeError):
            body = b'{"ok":false,"id":""}'
            self.send_response(403)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 24591), Handler).serve_forever()
