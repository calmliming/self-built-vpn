"""Combine durable VPS payload counters without mixing members or periods."""
from datetime import datetime, timezone, timedelta
import json
from sqlalchemy import select
from .models import TrafficSnapshot, User
from .security import unseal
from . import remote  # Also registers the server scripts import path.
from traffic_stats import month_key, subscription_info


def traffic_policy(user):
    return {'user_id': user.id, 'token': unseal(user.token_blob), 'total_bytes': user.traffic_limit_bytes,
            'period': user.traffic_period, 'include_legacy': user.include_legacy_traffic,
            'enforce': user.traffic_enforced, 'enabled': user.enabled and not user.deleted,
            'regions': json.loads(user.regions), 'revision': user.revision}


def metadata(db, server_id):
    return {'server_id': server_id,
            'policies': [traffic_policy(user) for user in db.scalars(select(User).where(User.deleted == False))],
            'snapshots': {item.server_id: json.loads(item.data) for item in db.scalars(select(TrafficSnapshot)) if item.collected_at}}


def traffic_data(db, user, at=None):
    at = at or datetime.now(timezone.utc)
    items = db.scalars(select(TrafficSnapshot)).all()
    snapshots = [json.loads(item.data) for item in items if item.collected_at]
    # Same calculation is used for the public subscription header on the VPS.
    values = dict(pair.strip().split('=', 1) for pair in subscription_info(traffic_policy(user), snapshots, at).split(';'))
    upload, download = int(values['upload']), int(values['download'])
    failures, stamps, starts = [], [], []
    for code in ['hk', 'sg', 'us']:
        item = next((s for s in items if s.server_id == code), None)
        data = json.loads(item.data) if item else {}
        source_stamps = data.get('sampled_at', {})
        if (not item or not item.collected_at or item.error or data.get('errors') or len(source_stamps) != 3
                or any(at - datetime.fromisoformat(value) > timedelta(minutes=5) for value in source_stamps.values())):
            failures.append(code)
        stamps.extend(source_stamps.values())
        if data.get('started_at'):
            starts.append(data['started_at'])
    used = upload + download
    total = user.traffic_limit_bytes
    available = any(bool(snapshot.get('sampled_at')) for snapshot in snapshots)
    required = ['hk', 'sg', 'us'] if user.include_legacy_traffic else json.loads(user.regions)
    guards = [json.loads(item.data).get('quota', {}) for item in items if item.server_id in required]
    quota_ready = len(guards) == len(required) and all(
        guard.get('enabled') and not guard.get('error') and not guard.get('apply_error') for guard in guards)
    reasons = [(guard.get('reasons') or {}).get(identity) for guard in guards
               for identity in [user.id, *(['legacy-owner'] if user.include_legacy_traffic else [])]]
    reason = next((r for r in reasons if r), None)
    quota_status = 'off' if not user.traffic_enforced or total is None else 'blocked' if reason else 'active' if quota_ready else 'pending'
    return {'total_bytes': total, 'upload_bytes': upload if available else None,
            'download_bytes': download if available else None, 'used_bytes': used if available else None,
            'remaining_bytes': max(0, total - used) if total is not None and available else None,
            'period': user.traffic_period, 'month': month_key(at), 'timezone': 'Asia/Shanghai',
            'status': 'pending' if not available else 'partial' if failures else 'ready',
            'unavailable_regions': failures, 'updated_at': min(stamps) if stamps else None,
            'started_at': min(starts) if starts else None, 'includes_legacy': user.include_legacy_traffic,
            'exceeded': total is not None and available and used >= total, 'enforced': user.traffic_enforced,
            'quota_status': quota_status, 'quota_reason': reason}
