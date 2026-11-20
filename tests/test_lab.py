import importlib.util
import pathlib
import tempfile
import json
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lab", ROOT / "lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class Configuration(unittest.TestCase):
    def test_data_connection_selection(self):
        text = " cubic rtt:2 bytes_sent:100\n reno rtt:40 bytes_sent:9000\n"
        self.assertIn("rtt:40", lab.select_connection(text, "reno"))
        text = " cubic rtt:2 bytes_sent:100\n cubic rtt:40 bytes_sent:9000\n"
        self.assertIn("rtt:40", lab.select_connection(text, "cubic"))

    def test_high_rate_requires_native_generator(self):
        c = json.loads((ROOT / "configs/demo.json").read_text())
        c["rate_bps"] = 200000000
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "c.json"
            p.write_text(json.dumps(c))
            with self.assertRaises(AssertionError):
                lab.config(p)
            c["generator"] = "native"
            p.write_text(json.dumps(c))
            self.assertEqual(lab.config(p)["rate_bps"], 200000000)
            c["rate_bps"] = 200000001
            p.write_text(json.dumps(c))
            with self.assertRaises(AssertionError):
                lab.config(p)

    def test_default(self):
        self.assertEqual(lab.config(ROOT / "configs/demo.json")["algorithm"], "reno")

    def test_reject_unbounded(self):
        c = json.loads((ROOT / "configs/demo.json").read_text())
        c["rate_bps"] = 10**12
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "c.json"
            p.write_text(json.dumps(c))
            with self.assertRaises(AssertionError):
                lab.config(p)

    def test_reject_bad_timing(self):
        c = json.loads((ROOT / "configs/demo.json").read_text())
        c["active"] = 100
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "c.json"
            p.write_text(json.dumps(c))
            with self.assertRaises(AssertionError):
                lab.config(p)


if __name__ == "__main__":
    unittest.main()
