#!/usr/bin/python3
"""Read-only config inventory and fail-closed supervisor of tzsingbox's own probes.
Never writes, signals or restarts the production sing-box process.
"""
import hashlib, json, os, pwd, signal, subprocess, time, secrets, socket
from pathlib import Path
from inbound_inventory import inbound_inventory

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
    return {'config_hash': hashlib.sha256(json.dumps(config,sort_keys=True,separators=(',',':')).encode()).hexdigest(), 'inbounds': inbound_inventory(config), 'routes_verified': verified, 'outbounds': [
        {'tag': o['tag'], 'type': o['type'], 'bound': o['tag'] in roots, 'members': o.get('outbounds', []), 'detour': o.get('detour', '')}
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


def runtime_identity():
    """Bind proof to the running service, not merely a valid file on disk.

    A config written after exec is unproven until that service is activated.
    ctime prevents preserved mtime from disguising an unapplied edit. The exact
    argv restriction excludes conf directories/overrides and alternate files.
    """
    pid = int(subprocess.check_output(
        ['systemctl', 'show', 'sing-box.service', '-p', 'MainPID', '--value'],
        timeout=3, stderr=subprocess.DEVNULL).strip())
    if pid <= 0:
        raise OSError('production service unavailable')
    proc = Path('/proc') / str(pid)
    argv = (proc / 'cmdline').read_bytes().split(b'\0')[:-1]
    expected = [b'/usr/local/bin/sing-box', b'run', b'-c', os.fsencode(CONFIG)]
    if argv != expected:
        raise OSError('running configuration source is ambiguous')
    ticks = int((proc / 'stat').read_text().rsplit(')', 1)[1].split()[19])
    boot_wall = time.time() - time.clock_gettime(time.CLOCK_BOOTTIME)
    started = boot_wall + ticks / os.sysconf('SC_CLK_TCK')
    if CONFIG.stat().st_ctime >= started:
        raise OSError('disk configuration has not been activated')
    if not os.path.samefile(proc / 'exe', '/usr/local/bin/sing-box'):
        raise OSError('running executable differs')
    return pid, ticks


def main():
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
            runtime = runtime_identity()
            receipt_path=INVENTORY.parent / 'applied-exits.json'
            receipt_raw=receipt_path.read_bytes() if receipt_path.exists() else b''
            inventory_version=(digest,hashlib.sha256(receipt_raw).hexdigest(),runtime)
            if inventory_version != previous or child is None or child.poll() is not None:
                stop_child()
                config=json.loads(raw)
                data=inventory(config,False); data["config_hash"]=digest
                write_inventory(data)
                # A disposable SOCKS listener routes each authenticated probe only to
                # its configured real tag. No production listener, UUID or route edits.
                actual=[o for o in config.get('outbounds',[]) if o.get('type') not in ('selector','urltest','block','dns') and o.get('tag')]
                sock=socket.socket(); sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]; sock.close()
                proxies=[]; users=[]; rules=[]
                for o in actual:
                    user=hashlib.sha256(o['tag'].encode()).hexdigest()[:24]; password=secrets.token_urlsafe(24)
                    proxies.append(dict(tag=o['tag'],server='127.0.0.1',port=port,username=user,password=password,mode='singbox_route',eligible=True))
                    users.append(dict(username=user,password=password))
                    rules.append(dict(auth_user=[user],action='route',outbound=o['tag']))
                probe=dict(log=dict(disabled=True),inbounds=[dict(type='socks',tag='path-probe',listen='127.0.0.1',listen_port=port,users=users)],outbounds=config.get('outbounds',[]),route=dict(rules=rules+[dict(action='reject')]))
                for key in ('default_domain_resolver','auto_detect_interface','default_interface','default_mark','default_network_strategy','default_network_type','default_fallback_network_type','default_fallback_delay'):
                    if key in config.get('route',{}): probe['route'][key]=config['route'][key]
                if config.get('dns'): probe['dns']=config['dns']
                account=pwd.getpwnam('tzsingbox-agent')
                def publish(name,data):
                    target=INVENTORY.parent/name; tmp=target.with_suffix('.tmp')
                    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o640)
                    with os.fdopen(fd,'w') as f: json.dump(data,f)
                    os.chown(tmp,0,account.pw_gid); os.chmod(tmp,0o640); os.replace(tmp,target)
                publish('probe-runtime.json',probe)
                command=['/usr/sbin/runuser','-u','tzsingbox-agent','--','/usr/local/bin/sing-box']
                subprocess.run(command+['check','-c',str(INVENTORY.parent/'probe-runtime.json')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
                child=subprocess.Popen(command+['run','-c',str(INVENTORY.parent/'probe-runtime.json')])
                ready=False
                for _ in range(30):
                    if child.poll() is not None: break
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1): ready=True
                        break
                    except OSError: time.sleep(.1)
                if not ready: raise OSError('isolated probe unavailable')
                # Do not publish paths from a file which changed during setup.
                if CONFIG.read_bytes()!=raw or runtime_identity()!=runtime: raise OSError('configuration changed')
                publish('probe-paths.json',dict(config_hash=digest,proxies=proxies))
                data=inventory(config,True); data['config_hash']=digest
                write_inventory(data); previous=inventory_version
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
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
