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

    def test_temporary_results_removed_on_interrupt(self):
        try:
            with lab.experiment_output(None) as (path, save):
                self.assertFalse(save)
                path.mkdir()
                (path / "capture.json").write_text("{}")
                raise KeyboardInterrupt
        except KeyboardInterrupt:
            self.assertFalse(path.parent.exists())

    def test_console_report_does_not_create_files(self):
        from contextlib import redirect_stdout
        from io import StringIO

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            run = root / "run"
            run.mkdir()
            (run / "config.json").write_text(
                json.dumps({"scenario": "none", "policy": "disabled"})
            )
            (run / "summary.json").write_text(
                json.dumps({"goodput_bps": 1000000, "retransmits": 0})
            )
            before = set(root.rglob("*"))
            output = StringIO()
            with redirect_stdout(output):
                lab.report(root)
            self.assertEqual(before, set(root.rglob("*")))
            self.assertIn("mean_mbps", output.getvalue())

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
