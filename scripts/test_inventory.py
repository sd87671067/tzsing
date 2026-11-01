"""Isolated fixtures; never reads production configuration or starts sing-box."""
import importlib.util
import pathlib
import unittest
import os
import tempfile
import stat
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('probe', pathlib.Path(__file__).with_name('path-probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class InventoryTests(unittest.TestCase):
    def test_multiple_direct_and_bound_route_graph(self):
        config = {'outbounds': [
            {'tag': 'a', 'type': 'direct', 'bind_interface': 'fixture0'},
            {'tag': 'b', 'type': 'direct'},
            {'tag': 'relay', 'type': 'socks', 'password': 'fixture-secret'},
            {'tag': 'unused', 'type': 'socks'},
            {'tag': 'selector', 'type': 'selector', 'outbounds': ['relay']},
        ], 'route': {'rules': [{'action': 'route', 'outbound': 'selector'}]}}
        actual = probe.inventory(config, False)
        tags = {o['tag']: o for o in actual['outbounds']}
        self.assertEqual(len(tags), 5)
        self.assertTrue(tags['relay']['bound'])
        self.assertFalse(tags['unused']['bound'])
        self.assertEqual(tags['a']['type'], 'direct')
        self.assertEqual(tags['b']['type'], 'direct')
        self.assertNotIn('fixture-secret', str(actual))
        self.assertNotIn('bind_interface', str(actual))
        self.assertFalse(actual['routes_verified'])

    def test_inventory_readable_under_hardened_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / 'inventory.json'
            old_mask = os.umask(0o077)
            try:
                with patch.object(probe, 'INVENTORY', target), patch.object(probe.pwd, 'getpwnam', return_value=SimpleNamespace(pw_gid=os.getgid())), patch.object(probe.os, 'chown'):
                    probe.write_inventory({'outbounds': []})
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
            finally:
                os.umask(old_mask)

    def test_config_removal_and_new_identity(self):
        before = {'outbounds': [{'tag': 'old', 'type': 'direct'}]}
        after = {'outbounds': [{'tag': 'new', 'type': 'direct'}]}
        self.assertNotEqual(probe.inventory(before, True), probe.inventory(after, True))
        self.assertEqual(probe.inventory(after, True)['outbounds'][0]['tag'], 'new')


class RuntimeProofTests(unittest.TestCase):
    def proof(self, changed=False, argv=None, same_binary=True):
        cfg=SimpleNamespace(stat=lambda:SimpleNamespace(st_ctime=601 if changed else 599), __fspath__=lambda:'/fixture.json')
        # Use a real Path for os.fsencode and mock only stat/read calls.
        with patch.object(probe,'CONFIG',pathlib.Path('/fixture.json')), \
             patch.object(probe.subprocess,'check_output',return_value=b'123'), \
             patch.object(pathlib.Path,'read_bytes',return_value=argv or b'/usr/local/bin/sing-box\0run\0-c\0/fixture.json\0'), \
             patch.object(pathlib.Path,'read_text',return_value='123 (sing-box) '+' '.join(['S']+['0']*18+['10000'])), \
             patch.object(pathlib.Path,'stat',return_value=SimpleNamespace(st_ctime=601 if changed else 599)), \
             patch.object(probe.time,'time',return_value=1000), \
             patch.object(probe.time,'clock_gettime',return_value=500), \
             patch.object(probe.os,'sysconf',return_value=100), \
             patch.object(probe.os.path,'samefile',return_value=same_binary):
            return probe.runtime_identity()

    def test_current_runtime_can_reverify_new_hash(self):
        self.assertEqual(self.proof(),(123,10000))

    def test_unapplied_disk_edit_fails_closed(self):
        with self.assertRaises(OSError): self.proof(changed=True)

    def test_ambiguous_config_and_replaced_binary_fail_closed(self):
        with self.assertRaises(OSError): self.proof(argv=b'/usr/local/bin/sing-box\0run\0-C\0/extra\0')
        with self.assertRaises(OSError): self.proof(same_binary=False)


if __name__ == '__main__':
    unittest.main()
