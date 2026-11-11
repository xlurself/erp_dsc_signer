"""The signing time must be the real instant, not the site's wall clock mislabelled as the server's zone.

Windows + Frappe Cloud test 2026-11-11: the site is set to Asia/Kolkata and the Cloud server's
operating system runs UTC.  ``frappe.utils.now_datetime()`` is the site's wall clock without a zone,
and ``.astimezone()`` then labelled it with the server's zone (+00:00): the signature said 13:24 UTC
when it was 07:54 UTC, and Adobe reported "Signature seems to be signed in future".
"""

import os
import re
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from erp_dsc_signer.utils import pdf_signer


class SigningTimeTest(unittest.TestCase):
	def setUp(self):
		old = os.environ.get("TZ")

		def restore():
			if old is None:
				os.environ.pop("TZ", None)
			else:
				os.environ["TZ"] = old
			time.tzset()

		self.addCleanup(restore)
		os.environ["TZ"] = "UTC"  # the Cloud server's operating system zone
		time.tzset()

	def test_the_moment_is_the_real_instant_in_the_site_zone(self):
		with mock.patch("frappe.utils.get_system_timezone", return_value="Asia/Kolkata"):
			moment = pdf_signer.signing_now()
		self.assertEqual(timedelta(hours=5, minutes=30), moment.utcoffset())
		self.assertLess(abs(moment - datetime.now(timezone.utc)), timedelta(seconds=5))
		self.assertEqual("+05'30'", pdf_signer._format_tz_offset(moment))

	def test_the_pdf_date_string_names_the_same_instant(self):
		with mock.patch("frappe.utils.get_system_timezone", return_value="Asia/Kolkata"):
			moment = pdf_signer.signing_now()
		text = moment.strftime("D:%Y%m%d%H%M%S") + pdf_signer._format_tz_offset(moment)
		parsed = re.fullmatch(r"D:(\d{14})([+-])(\d\d)'(\d\d)'", text)
		local = datetime.strptime(parsed.group(1), "%Y%m%d%H%M%S")
		sign = 1 if parsed.group(2) == "+" else -1
		utc = local - sign * timedelta(hours=int(parsed.group(3)), minutes=int(parsed.group(4)))
		self.assertLess(abs(utc.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)), timedelta(seconds=5))

	def test_unknown_or_missing_site_zone_falls_back_to_utc(self):
		for value in (None, "", "Not/AZone"):
			with self.subTest(value=value), mock.patch("frappe.utils.get_system_timezone", return_value=value):
				self.assertEqual(timedelta(0), pdf_signer.signing_now().utcoffset())

	def test_no_signing_path_labels_a_naive_site_clock_with_the_server_zone(self):
		root = Path(__file__).resolve().parents[1]
		for relative in ("utils/pdf_signer.py", "api/signing.py"):
			source = (root / relative).read_text(encoding="utf-8")
			self.assertNotIn("now_datetime().astimezone()", source, relative)
