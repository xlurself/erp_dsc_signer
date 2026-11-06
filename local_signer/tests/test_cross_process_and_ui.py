"""Regressions for the two round-3 review findings.

1. `--revoke` runs in a separate process from the daemon. It must change what the
   RUNNING service authorises, and a daemon holding stale state must not write a
   revoked origin back.
2. DialogHost's mutex is held for the whole `run_exclusive` call, so a second request
   is refused rather than queued behind a dialog that is still on screen.  (Spec 001
   removed the executor and the hard timeout; the dialog child, its deadline and the
   un-reapable-child case are covered in test_dialog_host.py.)
"""

import tempfile
import threading
import unittest
from pathlib import Path

from erp_dsc_local.trust import TrustStore
from erp_dsc_local.ui import DialogHost, UiBusy


ERP = "https://site.example"


class TestRevokeReachesARunningDaemon(unittest.TestCase):
	def setUp(self):
		self._dir = tempfile.TemporaryDirectory()
		self.addCleanup(self._dir.cleanup)
		self.path = Path(self._dir.name) / "allowed_origins.json"
		# Two independent instances, standing in for the daemon and the CLI process.
		self.daemon = TrustStore(self.path)
		self.cli = TrustStore(self.path)

	def test_cli_revoke_is_visible_to_the_daemon_without_restart(self):
		self.daemon.allow(ERP)
		self.assertTrue(self.daemon.is_allowed(ERP))

		self.assertTrue(self.cli.revoke(ERP))

		# The daemon must not keep authorising a revoked origin until it restarts.
		self.assertFalse(self.daemon.is_allowed(ERP))

	def test_cli_allow_is_visible_to_the_daemon(self):
		self.assertFalse(self.daemon.is_allowed(ERP))
		self.cli.allow(ERP)
		self.assertTrue(self.daemon.is_allowed(ERP))

	def test_stale_daemon_write_does_not_resurrect_a_revoked_origin(self):
		self.daemon.allow(ERP)
		self.daemon.allow("https://other.example")
		self.cli.revoke(ERP)

		# The daemon still has ERP in memory from before the revoke. A later unrelated
		# mutation must re-read first rather than write its stale map back.
		self.daemon.record_denial("https://unrelated.example")

		self.assertFalse(TrustStore(self.path).is_allowed(ERP))
		self.assertTrue(TrustStore(self.path).is_allowed("https://other.example"))

	def test_daemon_sees_a_denial_recorded_by_another_process(self):
		self.cli.record_denial(ERP)
		self.assertTrue(self.daemon.is_denied(ERP))

	def test_list_origins_reflects_other_process_changes(self):
		self.cli.allow(ERP)
		self.assertEqual([ERP], [e["origin"] for e in self.daemon.list_origins()])
		self.cli.revoke(ERP)
		self.assertEqual([], self.daemon.list_origins())

	def test_concurrent_allows_from_two_instances_all_survive(self):
		origins = [f"https://s{i}.example" for i in range(8)]
		stores = [TrustStore(self.path) for _ in origins]
		threads = [
			threading.Thread(target=store.allow, args=(origin,))
			for store, origin in zip(stores, origins)
		]
		for thread in threads:
			thread.start()
		for thread in threads:
			thread.join()

		final = TrustStore(self.path)
		missing = [o for o in origins if not final.is_allowed(o)]
		self.assertEqual([], missing, "a concurrent write lost an origin")


class TestDialogHostLifecycle(unittest.TestCase):
	def test_mutex_is_held_for_the_whole_call(self):
		host = DialogHost()
		release = threading.Event()
		started = threading.Event()
		box = {}

		def slow_dialog():
			started.set()
			release.wait(5)
			return "done"

		first = threading.Thread(target=lambda: box.setdefault("result", host.run_exclusive(slow_dialog)))
		first.start()
		self.assertTrue(started.wait(2))

		# The first call is still running, so a second caller must be REJECTED, not
		# silently queued behind a prompt that is still on screen.
		self.assertTrue(host.busy)
		with self.assertRaises(UiBusy):
			host.run_exclusive(lambda: "second")

		release.set()
		first.join(5)
		self.assertEqual("done", box["result"])
		self.assertFalse(host.busy)
		self.assertEqual("later", host.run_exclusive(lambda: "later"))

	def test_run_exclusive_is_not_reentrant(self):
		host = DialogHost()
		with self.assertRaises(UiBusy):
			host.run_exclusive(lambda: host.run_exclusive(lambda: "inner"))
		self.assertFalse(host.busy)

	def test_dialog_exception_releases_the_mutex(self):
		host = DialogHost()

		def boom():
			raise RuntimeError("dialog failed")

		with self.assertRaises(RuntimeError):
			host.run_exclusive(boom)
		self.assertFalse(host.busy)
		self.assertEqual("ok", host.run_exclusive(lambda: "ok"))
		host.shutdown()


if __name__ == "__main__":
	unittest.main()
