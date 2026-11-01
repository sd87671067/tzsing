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


if __name__ == '__main__':
    unittest.main()
