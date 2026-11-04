"""Atomic files, service changes and rollback for the managed VPN installation."""
from datetime import datetime, timezone
import fcntl
import grp
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


BASE = Path('/etc/self-vpn')
SUB = Path('/var/lib/self-vpn/subscription')
SERVICES = ['nginx', 'self-vpn', 'self-vpn-extra', 'self-vpn-hysteria2']
RENEW_TIMER = 'snap.certbot.renew.timer'


def run(args, timeout=180):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        # Arguments and command output may contain authentication material.
        raise RuntimeError(f'{Path(args[0]).name} failed (exit {result.returncode})')
    return result.stdout.strip()


def state(service, verb='is-active'):
    result = subprocess.run(['systemctl', verb, service], capture_output=True, text=True, timeout=20)
    return result.stdout.strip()


def require_active(service):
    if state(service) != 'active':
        raise RuntimeError(f'Required service is not active: {service}')


def write(path, value, mode=0o600, group=None):
    """Return whether contents changed; never truncate an active configuration."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = value.encode() if isinstance(value, str) else value
    gid = grp.getgrnam(group).gr_gid if group else -1
    if path.is_symlink():
        raise RuntimeError(f'Refusing to overwrite a symlink: {path.name}')
    if path.exists() and path.read_bytes() == payload:
        os.chmod(path, mode)
        if gid >= 0:
            os.chown(path, 0, gid)
        return False
    descriptor, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            os.fchmod(handle.fileno(), mode)
            if gid >= 0:
                os.fchown(handle.fileno(), 0, gid)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def apply_service(service, changed, transaction, unit_changed=False, reload_service=False):
    if unit_changed:
        run(['systemctl', 'daemon-reload'])
    if state(service, 'is-enabled') != 'enabled':
        transaction.touch_service(service)
        run(['systemctl', 'enable', service])
    if changed or state(service) != 'active':
        transaction.touch_service(service)
        verb = 'reload' if reload_service and state(service) == 'active' else 'restart'
        run(['systemctl', verb, service])
    require_active(service)


def validate_xray(configuration):
    with tempfile.TemporaryDirectory(prefix='validate-', dir=BASE) as folder:
        candidate = Path(folder) / 'xray.json'
        write(candidate, json.dumps(configuration))
        run(['/usr/local/bin/xray', 'run', '-test', '-config', str(candidate)])


def validate_nginx(site):
    with tempfile.TemporaryDirectory(prefix='validate-', dir=BASE) as folder:
        candidate = Path(folder) / 'nginx.conf'
        write(candidate, 'events {}\nhttp {\n' + site + '\n}\n')
        run(['nginx', '-t', '-c', str(candidate)])


def managed_paths():
    paths = [BASE / name for name in [
        'xray.json', 'extra-xray.json', 'hysteria.yaml', 'tls', 'client.json',
        'deployment.env', 'deployment.json', 'release.json', 'multi-enabled', 'multi-client.json', 'multi-client.yaml',
        'multi-metadata.json', 'candidate.json', 'candidate.yaml', 'candidate-metadata.json',
    ]]
    paths += [SUB / name for name in ['config.yaml', 'cn-domain.mrs', 'cn-ip.mrs']]
    paths += [Path('/usr/local/bin') / name for name in ['xray', 'hysteria']]
    paths += [Path('/etc/systemd/system') / (name + '.service') for name in SERVICES if name != 'nginx']
    paths += [Path('/etc/systemd/system/multi-user.target.wants') / (name + '.service') for name in SERVICES]
    paths += [Path('/etc/nginx/sites-available/self-vpn'), Path('/etc/nginx/sites-enabled/self-vpn'), Path('/etc/nginx/sites-enabled/default')]
    paths += [Path('/etc/letsencrypt/renewal-hooks/deploy/self-vpn-nginx')]
    paths += [Path('/etc/letsencrypt/live/self-vpn-ip'), Path('/etc/letsencrypt/archive/self-vpn-ip'), Path('/etc/letsencrypt/renewal/self-vpn-ip.conf')]
    paths += [BASE / name for name in ['team-managed', 'team-members.json', 'team-auth-users.json', 'team-auth-state.json', 'team_auth.py', 'team-publications.json']]
    paths += [Path('/etc/systemd/system/self-vpn-team-auth.service'), Path('/etc/nginx/self-vpn-team'), Path('/var/lib/self-vpn/team-subscriptions')]
    paths += [BASE / 'traffic_stats.py', BASE / 'operations.py', Path('/var/lib/self-vpn/traffic/subscriptions.json')]
    paths += [BASE / name for name in ['quota_control.py', 'quota-control.json', 'quota-client.json', 'quota-coordinator.json']]
    paths += [Path('/etc/systemd/system/self-vpn-traffic.' + suffix) for suffix in ['service', 'timer']]
    paths += [Path('/etc/systemd/system/timers.target.wants/self-vpn-traffic.timer')]
    # Generated credentials deliberately survive a failed first installation.
    return paths


def _remove(path):
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def _copy(source, destination):
    if source.is_symlink():
        destination.symlink_to(os.readlink(source))
    elif source.is_dir():
        shutil.copytree(source, destination, symlinks=True)
    else:
        shutil.copy2(source, destination)


def _metadata(path):
    paths = [path]
    if path.is_dir() and not path.is_symlink():
        paths += list(path.rglob('*'))
    result = []
    for item in paths:
        info = item.lstat()
        result.append({'relative': str(item.relative_to(path)) if item != path else '',
                       'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
                       'symlink': item.is_symlink()})
    return result


class Transaction:
    """Hold the deployment lock until external validation explicitly commits."""
    def __init__(self, paths=None, base=BASE, services=SERVICES, pause_renewal=True):
        self.base = Path(base)
        self.paths = list(paths if paths is not None else managed_paths())
        self.services = list(services)
        self.pause_renewal = pause_renewal
        self.touched = set()
        self.committed = False
        self.rolled_back = False
        self.entries = []
        self.timer_active = False
        self.timer_resumed = False
        self.lock = None

    def __enter__(self):
        self.base.mkdir(parents=True, exist_ok=True)
        self.lock = (self.base / '.deployment.lock').open('a')
        os.chmod(self.lock.name, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.recover_pending()
            self.service_states = {service: {'active': state(service) == 'active', 'enabled': state(service, 'is-enabled') == 'enabled'} for service in self.services}
            self.timer_active = self.pause_renewal and state(RENEW_TIMER) == 'active'
            stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
            parent = self.base / 'backups'
            parent.mkdir(exist_ok=True, mode=0o700)
            parent.chmod(0o700)
            self.folder = parent / ('transaction-' + stamp)
            self.folder.mkdir(mode=0o700)
            self._manifest('snapshotting')
            if self.pause_renewal:
                if self.timer_active:
                    run(['systemctl', 'stop', RENEW_TIMER])
                if state('snap.certbot.renew.service') == 'active':
                    raise RuntimeError('Certificate renewal is running; retry after it finishes')
            for index, path in enumerate(self.paths):
                path = Path(path)
                exists = path.exists() or path.is_symlink()
                entry = {'path': str(path), 'backup': str(index), 'exists': exists}
                if exists:
                    entry['metadata'] = _metadata(path)
                    _copy(path, self.folder / str(index))
                self.entries.append(entry)
            self._manifest('pending')
            return self
        except BaseException:
            self._release()
            raise

    def _manifest(self, status):
        write(self.folder / 'manifest.json', json.dumps({'status': status, 'entries': self.entries, 'services': self.service_states, 'touched': sorted(self.touched), 'renew_timer_active': self.timer_active}, indent=2))

    def recover_pending(self):
        for manifest in sorted((self.base / 'backups').glob('transaction-*/manifest.json')):
            record = json.loads(manifest.read_text())
            if record['status'] not in ['snapshotting', 'pending', 'rollback-incomplete']:
                continue
            interrupted = Transaction(paths=[], base=self.base, services=list(record['services']), pause_renewal=False)
            interrupted.folder = manifest.parent
            interrupted.entries = record['entries']
            interrupted.service_states = record['services']
            interrupted.touched = set(record.get('touched', []))
            interrupted.timer_active = record.get('renew_timer_active', False)
            if interrupted.timer_active:
                if state('snap.certbot.renew.service') == 'active':
                    raise RuntimeError('Certificate renewal is running; retry recovery after it finishes')
                run(['systemctl', 'stop', RENEW_TIMER])
            try:
                if interrupted.timer_active and state('snap.certbot.renew.service') == 'active':
                    raise RuntimeError('Certificate renewal is running; retry recovery after it finishes')
                if record['status'] != 'snapshotting':
                    interrupted.rollback()
                else:
                    interrupted._manifest('cancelled')
            finally:
                if interrupted.timer_active:
                    run(['systemctl', 'start', RENEW_TIMER])

    def touch_service(self, service):
        self.touched.add(service)
        self._manifest('pending')

    def commit(self):
        if self.timer_active and not self.timer_resumed:
            run(['systemctl', 'start', RENEW_TIMER])
            self.timer_resumed = True
        self._manifest('committed')
        self.committed = True

    def rollback(self):
        failures = []
        for service in self.touched:
            old = self.service_states[service]
            try:
                if not old['active'] and state(service) == 'active':
                    run(['systemctl', 'stop', service])
                if not old['enabled'] and state(service, 'is-enabled') == 'enabled':
                    run(['systemctl', 'disable', service])
            except RuntimeError:
                failures.append(service)
        for entry in reversed(self.entries):
            path = Path(entry['path'])
            try:
                _remove(path)
                if entry['exists']:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    _copy(self.folder / entry['backup'], path)
                    for info in reversed(entry['metadata']):
                        item = path / info['relative'] if info['relative'] else path
                        current = item.lstat()
                        if (current.st_uid, current.st_gid) != (info['uid'], info['gid']):
                            os.chown(item, info['uid'], info['gid'], follow_symlinks=False)
                        if not info['symlink']:
                            os.chmod(item, info['mode'])
            except OSError:
                failures.append(path.name)
        if self.touched:
            try:
                run(['systemctl', 'daemon-reload'])
            except RuntimeError:
                failures.append('daemon-reload')
        for service in self.services:
            if service not in self.touched:
                continue
            old = self.service_states[service]
            try:
                if old['enabled']:
                    run(['systemctl', 'enable', service])
                elif state(service, 'is-enabled') == 'enabled':
                    run(['systemctl', 'disable', service])
                if old['active']:
                    run(['systemctl', 'restart', service])
                    require_active(service)
                elif state(service) == 'active':
                    run(['systemctl', 'stop', service])
            except RuntimeError:
                failures.append(service)
        self._manifest('rollback-incomplete' if failures else 'rolled-back')
        if failures:
            raise RuntimeError('Rollback incomplete: ' + ', '.join(failures) + f'; private snapshot: {self.folder}')
        self.rolled_back = True

    def _release(self):
        try:
            if self.timer_active and not self.timer_resumed:
                run(['systemctl', 'start', RENEW_TIMER])
        finally:
            if self.lock:
                self.lock.close()
                self.lock = None

    def __exit__(self, kind, value, traceback):
        try:
            if not self.committed:
                self.rollback()
        finally:
            self._release()
        return False
