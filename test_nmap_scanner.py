import unittest
from unittest.mock import MagicMock, patch
import tkinter as tk
import sys
import types

nmap_mock = types.ModuleType("nmap")
nmap_mock.PortScanner = MagicMock
nmap_mock.PortScannerError = Exception
sys.modules["nmap"] = nmap_mock

from nmap_scanner import NmapScanner  
class TestNmapScanner(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = NmapScanner(self.root)
    def tearDown(self):
        self.root.destroy()
    def test_valid_ip(self):
        self.assertTrue(self.app.validate_target("192.168.1.1"))
    def test_valid_hostname(self):
        self.assertTrue(self.app.validate_target("example.com"))
    def test_invalid_target(self):
        self.assertFalse(self.app.validate_target("bad!!target"))
    def test_clear_placeholder(self):
        self.app.custom_args.delete(0, tk.END)
        self.app.custom_args.insert(0, "Optional (e.g. -sS -T4)")
        self.app._clear_placeholder(None)
        self.assertEqual(self.app.custom_args.get(), "")
    def test_restore_placeholder(self):
        self.app.custom_args.delete(0, tk.END)
        self.app._restore_placeholder(None)
        self.assertEqual(self.app.custom_args.get(), "Optional (e.g. -sS -T4)")
    def test_scan_blocked_when_running(self):
        self.app.scan_running = True
        with patch("nmap_scanner.messagebox.showwarning") as mock_warn:  # fixed path
            self.app.start_scan()
            mock_warn.assert_called_once()
    def test_empty_target_shows_error(self):
        self.app.target_entry.delete(0, tk.END)
        with patch("nmap_scanner.messagebox.showerror") as mock_err:  # fixed path
            self.app.start_scan()
            mock_err.assert_called_once()
    def test_clear_results(self):
        self.app.result_box.insert(tk.END, "some output")
        self.app.clear_results()
        self.assertEqual(self.app.result_box.get(1.0, tk.END).strip(), "")
    def test_quick_scan_args(self):
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = []
        self.app.scanner = mock_scanner
        self.app.target_entry.delete(0, tk.END)
        self.app.target_entry.insert(0, "127.0.0.1")
        self.app.scan_type.set("Quick Scan")
        self.app.run_scan()
        mock_scanner.scan.assert_called_once_with("127.0.0.1", arguments="-F -T4")

if __name__ == "__main__":
    unittest.main()