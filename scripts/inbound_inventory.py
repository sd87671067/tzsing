"""Conservative route analysis. Every configured inbound tag is an identity.
Credentials and listen addresses never enter inventory. Named authentication
users are exported only as stable digests; VLESS UUIDs define stable identities; names are mutable display labels.
Conditional matches contribute all possible routes; ambiguity stays explicit.
"""

import hashlib
import uuid
import re

def auth_id(name):
    return hashlib.sha256(name.encode()).hexdigest()

def inbound_inventory(config):
    out = []
    all_names = [u.get('name') for i in config.get('inbounds',[]) for u in i.get('users',[])]
    stats = config.get('experimental',{}).get('v2ray_api',{}).get('stats',{})
    stats_names = stats.get('users',[]) if stats.get('enabled') else []
    final = config.get('route', {}).get('final')
    if not final:
        final = next((o.get('tag') for o in config.get('outbounds', []) if o.get('tag')), None)
    for inbound in config.get('inbounds', []):
        if not inbound.get('tag'):
            continue
        tag = inbound['tag']
        candidates, unknown, stopped = set(), False, False
        for rule in config.get('route', {}).get('rules', []):
            # Logical/not matches cannot safely be evaluated without a request.
            match = rule.get('inbound')
            if isinstance(match, str):
                match = [match]
            if match and tag not in match and not rule.get('invert'):
                continue
            action = rule.get('action', 'route')
            if action in ('sniff', 'resolve', 'route-options'):
                continue
            unconditional = set(rule) <= {'inbound', 'outbound', 'action'} and (not match or tag in match)
            if action == 'route' and rule.get('outbound'):
                candidates.add(rule['outbound'])
            else:
                unknown = True
            if unconditional:
                stopped = True
                break
        if not stopped:
            if final:
                candidates.add(final)
            else:
                unknown = True
        users = inbound.get('users', [])
        names = [u.get('name') or u.get('username') for u in users]
        legacy = {}
        labels = {}
        bindings = {}
        native = {}
        scheme = ''
        if inbound.get('type') == 'vless':
            scheme = 'uuid-v1'
            def canonical_uuid(value):
                try:
                    return str(uuid.UUID(value)) if isinstance(value,str) and str(uuid.UUID(value)) == value.lower() else None
                except (ValueError, AttributeError):
                    return None
            values = [canonical_uuid(u.get('uuid')) for u in users]
            identities = []
            for index, value in enumerate(values):
                if value and values.count(value) == 1:
                    identity = auth_id('vless-uuid-v1\x00'+value)
                    identities.append(identity)
                    name = names[index]
                    if isinstance(name, str) and name:
                        labels[identity] = name[:128]
                    if isinstance(name,str) and name and names.count(name) == 1:
                        legacy[identity] = auth_id(name)
                        # Only complete, simple authenticated rules have a proven
                        # upstream String() representation. Never parse substrings
                        # or infer a user from a shared destination/selector chain.
                        safe = lambda v: isinstance(v,str) and re.fullmatch(r'[A-Za-z0-9_.:/-]{1,128}',v)
                        if safe(tag) and safe(name):
                            for rule in config.get('route',{}).get('rules',[]):
                                if (set(rule) == {'inbound','auth_user','action','outbound'}
                                    and rule['inbound'] == [tag] and rule['auth_user'] == [name]
                                    and rule['action'] == 'route' and safe(rule['outbound'])):
                                    rendered = 'inbound='+tag+' auth_user='+name+' => route('+rule['outbound']+')'
                                    bindings[auth_id(rendered)] = {'id':identity,'outbound':rule['outbound']}

                        if name in stats_names and all_names.count(name)==1 and '>>>' not in name:
                            native[identity] = auth_id(name)
            identities.sort()
        else:
            identities = sorted({auth_id(n) for n in names if isinstance(n, str) and n and names.count(n) == 1})
        out.append({'tag': tag, 'type': inbound['type'], 'routes': sorted(candidates), 'unknown': unknown,
                    'auth_ids': identities, 'auth_scheme':scheme, 'legacy_auth_ids':legacy,
                    'native_users': native, 'auth_names': labels, 'rule_bindings': bindings, 'auth_count': len(users), 'auth_unsupported': len(users)-len(identities)})
    return out
