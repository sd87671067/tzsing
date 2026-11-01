"""Conservative route analysis. Every configured inbound tag is an identity.
Credentials, listen addresses and authentication users never enter inventory.
Conditional matches contribute all possible routes; ambiguity stays explicit.
"""

def inbound_inventory(config):
    out = []
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
        out.append({'tag': tag, 'type': inbound['type'], 'routes': sorted(candidates), 'unknown': unknown})
    return out
