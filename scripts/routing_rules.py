"""Refresh both routing files together, preserving the old pair on failure."""
import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request

from operations import SUB, write


RULES = {
    'cn-domain.mrs': 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs',
    'cn-ip.mrs': 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs',
}
MAX_RULE_BYTES = 32_000_000


def download(url, maximum=100_000_000):
    request = urllib.request.Request(url, headers={'User-Agent': 'self-vpn-setup/1'})
    with urllib.request.urlopen(request, timeout=45) as response:
        content = response.read(maximum + 1)
    if len(content) > maximum:
        raise RuntimeError('Download exceeds size limit')
    return content


def validate_mrs(content, behavior):
    if behavior not in ['domain', 'ipcidr']:
        raise ValueError('Unknown MRS rule behavior')
    if not content.startswith(bytes.fromhex('28b52ffd')):
        raise ValueError('Routing file is not a Zstandard MRS file')
    try:
        from compression import zstd
    except ImportError:
        if not shutil.which('zstd'):
            raise RuntimeError('MRS validation needs Python compression.zstd or the zstd command') from None
        with tempfile.TemporaryDirectory(prefix='self-vpn-rules-') as folder:
            path = Path(folder) / 'rules.mrs'
            path.write_bytes(content)
            process = subprocess.Popen(['zstd', '-d', '-q', '-c', str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                raw = process.stdout.read(MAX_RULE_BYTES + 1)
                if len(raw) > MAX_RULE_BYTES:
                    raise ValueError('Decompressed routing file exceeds size limit')
                if process.wait(timeout=15) != 0:
                    raise ValueError('Routing file decompression failed')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stdout.close()
    else:
        try:
            with zstd.ZstdFile(io.BytesIO(content), options={zstd.DecompressionParameter.window_log_max: 25}) as stream:
                raw = stream.read(MAX_RULE_BYTES + 1)
        except (zstd.ZstdError, EOFError, OSError):
            raise ValueError('Routing file decompression failed') from None
    expected_behavior = 0 if behavior == 'domain' else 1
    if len(raw) > MAX_RULE_BYTES or len(raw) < 29 or raw[:4] != b'MRS\x01' or raw[4] != expected_behavior:
        raise ValueError('Routing file has an invalid MRS header')
    count = int.from_bytes(raw[5:13], 'big')
    if count <= 0:
        raise ValueError('Routing file contains no rules')
    return count


def update_rules(destination=SUB, force=True, fetch=download):
    destination = Path(destination)
    prepared = {}
    counts = {}
    for name, url in RULES.items():
        path = destination / name
        behavior = 'domain' if 'domain' in name else 'ipcidr'
        if not force and path.exists():
            content = path.read_bytes()
        else:
            content = fetch(url, maximum=8_000_000)
        counts[name] = validate_mrs(content, behavior)
        prepared[name] = content
    # No active file is touched until both downloads and both validations pass.
    changed = False
    for name, content in prepared.items():
        changed = write(destination / name, content, 0o640, 'www-data') or changed
    return {'changed': changed, 'counts': counts}
