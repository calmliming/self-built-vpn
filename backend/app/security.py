import base64
import hashlib
import hmac
import json
import os
import secrets
import uuid

from cryptography.fernet import Fernet
from .config import STATE, prepare_directories

def identity():
    return uuid.uuid4().hex

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def password_hash(value):
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(value.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return 'scrypt$' + base64.b64encode(salt + key).decode()

def password_matches(value, hashed):
    try:
        raw = base64.b64decode(hashed.split('$', 1)[1], validate=True)
        key = hashlib.scrypt(value.encode(), salt=raw[:16], n=16384, r=8, p=1, dklen=32)
        return len(raw) == 48 and hmac.compare_digest(raw[16:], key)
    except (ValueError, IndexError, TypeError):
        return False

def cipher():
    prepare_directories()
    path = STATE / 'master.key'
    if not path.exists():
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(Fernet.generate_key())
    return Fernet(path.read_bytes())

def seal(value):
    return cipher().encrypt(json.dumps(value, ensure_ascii=False).encode()).decode()

def unseal(value):
    return json.loads(cipher().decrypt(value.encode()))

def new_credentials(codes):
    return {code: {
        'uuid': str(uuid.uuid4()), 'trojan_password': secrets.token_urlsafe(32),
        'hysteria_password': secrets.token_urlsafe(32),
        'http_username': 'm_' + secrets.token_hex(8), 'http_password': secrets.token_urlsafe(32),
        'socks5_username': 'm_' + secrets.token_hex(8), 'socks5_password': secrets.token_urlsafe(32),
    } for code in codes}
