import importlib.util
import pathlib
import unittest
from unittest.mock import patch
import io

spec = importlib.util.spec_from_file_location('path_probe', pathlib.Path(__file__).with_name('path-probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class Paths(unittest.TestCase):
    def test_dynamic_choices_pinned_without_modifying_source(self):
        config = {'outbounds': [{'type': 'urltest', 'tag': 'auto', 'outbounds': ['exit', 'other']}, {'type': 'http', 'tag': 'exit', 'detour': 'hop'}], 'experimental': {'clash_api': {'external_controller': '127.0.0.1:9090', 'secret': 'synthetic-test'}}}
        opener = unittest.mock.Mock()
        opener.open.return_value = io.BytesIO(b'{"proxies":{"auto":{"now":"exit"}}}')
        with patch.object(probe.urllib.request, 'build_opener', return_value=opener):
            choices = probe.runtime_choices(config)
        pinned = probe.pinned_outbounds(config, choices)
        self.assertEqual(pinned[0]['default'], 'exit')
        self.assertEqual(pinned[0]['outbounds'], ['exit'])
        self.assertEqual(pinned[1]['detour'], 'hop')
        self.assertEqual(config['outbounds'][0]['type'], 'urltest')
        opener.open.return_value = io.BytesIO(b'{"proxies":{"auto":{"now":"guessed"}}}')
        with patch.object(probe.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(OSError):
                probe.runtime_choices(config)

    def test_no_runtime_endpoint_is_unknown(self):
        with self.assertRaises((ValueError, OSError)):
            probe.runtime_choices({'outbounds': [{'tag': 'auto', 'type': 'selector'}]})

if __name__ == '__main__':
    unittest.main()
