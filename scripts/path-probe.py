#!/usr/bin/python3
"""Read-only config inventory and fail-closed supervisor of tzsingbox's own probes.
Never writes, signals or restarts the production sing-box process.
"""
import hashlib, json, os, pwd, signal, subprocess, time
from pathlib import Path

CONFIG = Path(os.environ.get('SINGBOX_CONFIG', '/etc/sing-box/config.json'))
STATE = Path(os.environ.get('TZSINGBOX_CONFIG_DIR', '/etc/tzsingbox'))
INVENTORY = Path(os.environ.get('TZSINGBOX_INVENTORY_FILE', '/var/lib/tzsingbox-inventory/outbounds.json'))


def inventory(config, verified):
    outbounds = config.get('outbounds', [])
    by_tag = {o['tag']: o for o in outbounds if o.get('tag')}
    roots = set()

    def references(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ('outbound', 'final', 'detour') and isinstance(item, str):
                    roots.add(item)
                else:
                    references(item)
        elif isinstance(value, list):
            for item in value:
                references(item)

    references(config.get('route', {}))
    pending = list(roots)
    while pending:
        tag = pending.pop()
        outbound = by_tag.get(tag, {})
        links = list(outbound.get('outbounds', []))
        if outbound.get('detour'):
            links.append(outbound['detour'])
        for link in links:
            if link not in roots:
                roots.add(link)
                pending.append(link)
    return {'routes_verified': verified, 'outbounds': [
        {'tag': o['tag'], 'type': o['type'], 'bound': o['tag'] in roots}
        for o in outbounds if o.get('tag') and o.get('type')
    ]}


def write_inventory(data):
    account = pwd.getpwnam('tzsingbox-agent')
    target = INVENTORY
    tmp = target.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream)
    os.chown(tmp, 0, account.pw_gid)
    os.chmod(tmp, 0o640)
    os.replace(tmp, target)


def main():
    attestation = STATE / 'route-attestation.json'
    expected = json.loads(attestation.read_text())['sha256'] if attestation.exists() else ''
    child = None
    stopped = False

    def stop_child():
        nonlocal child
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        child = None

    def stop(*_):
        nonlocal stopped
        stopped = True
        stop_child()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    previous = None
    while not stopped:
        try:
            raw = CONFIG.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            valid = digest == expected
            if digest != previous:
                write_inventory(inventory(json.loads(raw), valid))
                previous = digest
            if not valid:
                stop_child()
            elif child is None or child.poll() is not None:
                child = subprocess.Popen([
                    '/usr/sbin/runuser', '-u', 'tzsingbox-agent', '--',
                    '/usr/local/bin/sing-box', 'run', '-c', str(STATE / 'probe.json')])
        except (OSError, ValueError, KeyError):
            stop_child()
            # Preserve identities but disable unverifiable probing.
            previous = None
            try:
                data = json.loads(INVENTORY.read_text())
                data['routes_verified'] = False
                write_inventory(data)
            except (OSError, ValueError):
                pass
        for _ in range(10):
            if stopped:
                break
            time.sleep(1)
    stop_child()


if __name__ == '__main__':
    main()
