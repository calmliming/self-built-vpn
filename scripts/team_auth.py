"""Local Hysteria2 auth: preserve owner access; independently revoke team members."""
import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
from urllib.parse import urlsplit

USERS = Path('/etc/self-vpn/team-auth-users.json')
TEAM_SUB = Path('/var/lib/self-vpn/team-subscriptions')
LEGACY_SUB = Path('/var/lib/self-vpn/subscription')

def authenticate(value, users):
    candidate = hashlib.sha256(value.encode()).hexdigest()
    for user_id, hashed in users.items():
        if hmac.compare_digest(candidate, hashed):
            return user_id
    return ''

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.subscription(False)

    def do_HEAD(self):
        self.subscription(True)

    def subscription(self, head):
        from traffic_stats import DATA, POLICIES, STORE, public_snapshot, subscription_info
        self.connection.settimeout(5)
        path = urlsplit(self.path).path
        try:
            policies = json.loads(POLICIES.read_text()) if POLICIES.exists() else {}
            policy = None
            match = re.fullmatch(r'/team-sub/([A-Za-z0-9_-]{40,80})/config.yaml', path)
            if match:
                target = TEAM_SUB / match[1] / 'config.yaml'
                policy = next((p for p in policies.get('members', {}).values() if p['token'] == match[1]), None)
            else:
                match = re.fullmatch(r'/sub/([A-Za-z0-9_-]{24,80})/(config.yaml|fleet.yaml)', path)
                if not match or not hmac.compare_digest(match[1], policies.get('legacy_token', '')):
                    raise FileNotFoundError
                target = LEGACY_SUB / match[2]
                policy = next((p for p in policies.get('members', {}).values() if p.get('include_legacy')), None)
            if target.is_symlink():
                raise FileNotFoundError
            content = target.read_bytes()
            header = None
            if policy and STORE.exists():
                local = public_snapshot(json.loads(STORE.read_text()))
                snapshots = [local, *[s for code, s in policies.get('snapshots', {}).items() if code != policies.get('server_id')]]
                header = subscription_info(policy, snapshots)
            self.send_response(200)
            self.send_header('Content-Type', 'application/yaml; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'private, no-store')
            self.send_header('profile-update-interval', '1')
            self.send_header('X-Content-Type-Options', 'nosniff')
            if header:
                self.send_header('Subscription-Userinfo', header)
            self.end_headers()
            if not head:
                self.wfile.write(content)
        except (OSError, ValueError, KeyError, TypeError):
            self.send_error(404)

    def do_POST(self):
        self.connection.settimeout(3)
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if self.path == '/quota/report':
                from quota_control import authorized_peer, coordinate
                if not authorized_peer(self.headers.get('Authorization', '')):
                    raise PermissionError('Invalid quota agent')
                if not 0 < length <= 2_000_000:
                    raise ValueError
                request = json.loads(self.rfile.read(length))
                result = coordinate(request, self.headers.get('Authorization', ''))
                body = json.dumps(result).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path != '/auth' or not 0 < length <= 8192:
                raise ValueError
            request = json.loads(self.rfile.read(length))
            value = request.get('auth', '')
            if not isinstance(value, str) or not 1 <= len(value) <= 1024:
                raise ValueError
            user_id = authenticate(value, json.loads(USERS.read_text()))
            if user_id:
                from quota_control import authentication_blocked
                if authentication_blocked(user_id):
                    user_id = ''
                else:
                    from quota_control import session_identity
                    user_id = session_identity(user_id)
            body = json.dumps({'ok': bool(user_id), 'id': user_id}).encode()
            self.send_response(200)
        except (ValueError, OSError, TypeError, KeyError):
            body = b'{"ok":false,"id":""}'
            self.send_response(403)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 24591), Handler).serve_forever()
