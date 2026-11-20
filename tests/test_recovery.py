import importlib.util
import pathlib
import unittest
import json
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "search", ROOT / "scripts/recovery_search.py"
)
search = importlib.util.module_from_spec(spec)
spec.loader.exec_module(search)


class RecoveryMeasurements(unittest.TestCase):
    def test_partial_interval_weighting(self):
        rows = [
            {"sum": {"start": 0, "end": 2, "bits_per_second": 10}},
            {"sum": {"start": 2, "end": 4, "bits_per_second": 20}},
        ]
        self.assertEqual(search.rate(rows, 1, 3), 15)
        self.assertIsNone(search.rate(rows, 5, 6))

    def test_ack_interpolation(self):
        rows = [{"ns": 100, "bytes_acked": 1000}, {"ns": 200, "bytes_acked": 2000}]
        self.assertEqual(search.ack_at(rows, 150), 1500)
        self.assertEqual(search.ack_at(rows, 50), 1000)
        self.assertEqual(search.ack_at(rows, 250), 2000)

    def test_control_socket_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)
            records = [
                {"ns": 1, "sport": 10, "bytes_sent": 185},
                {"ns": 2, "sport": 20, "bytes_sent": 4000},
                {"ns": 3, "sport": 10, "bytes_sent": 185},
                {"ns": 4, "sport": 20, "bytes_sent": 8000},
            ]
            (p / "tcp-info.jsonl").write_text("\n".join(json.dumps(x) for x in records))
            self.assertEqual([r["sport"] for r in search.flow(p)], [20, 20])


if __name__ == "__main__":
    unittest.main()
