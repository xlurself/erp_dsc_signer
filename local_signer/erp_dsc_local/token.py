"""PKCS#11 access.  This module is imported only on workstations with middleware.

PIN boundary (spec 001 §7): a PIN is sent in exactly ONE ``C_Login`` per entry, on the slot
the selected certificate came from, and only while that slot still reports the selected
token's serial.  From ``session.login`` through ``sign`` no driver text reaches an error,
and every error on that path is raised outside any ``except`` block, so neither
``__cause__`` nor ``__context__`` carries a driver exception.

Signing diagnostic: ``TOKEN_SIGNING_FAILED`` keeps its one fixed message and carries
``details = {"stage", "error", "ckr"}`` (``errors.TokenSigningFailed``): the step that
failed (``login``, ``find_key``, ``c_sign``, ``cms``, ``tsa``), the exception's CLASS
NAME if it is in ``SIGNING_ERROR_CLASSES`` (else "other") and, for a ``PyKCS11Error``, the
return-code name looked up in ``PyKCS11.CKR`` by its integer ``value`` (else None).  The
exception's text, args and traceback are never read, so a driver, endesive or a TSA that
echoes the PIN cannot put it there.  The same three fields go to stderr as one fixed line
(``SIGNING_FAILED_LOG``).

Digest (spec §7): ``_TokenHSM.sign`` signs with ``CKM_SHA256_RSA_PKCS`` only and refuses any
other digest endesive asks for (one taken from the PDF's own /Perms /DocMDP) before
``C_Login``, as ``TOKEN_SIGNING_FAILED`` stage ``c_sign``.

PIN lifetime (I7): ``_TokenHSM`` drops its reference to the PIN as soon as ``C_Login``
returns or raises, so the PIN is not held through signing or the timestamp request.
Residual: PyKCS11's ``Session.login`` copies the PIN into its own byte list for
``C_Login``; that copy is not ours to clear and cannot be wiped from Python.

Timestamp bound: the caller holds the token lock and the session stays logged in until
endesive returns, so the timestamp request is bounded by ``TSA_TIMEOUT_SECONDS``; a TSA
that times out or fails ends as ``TOKEN_SIGNING_FAILED`` after logout and close.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager

from .certificates import build_issuer_chain, parse_token_certificate, select_certificate
from .errors import (
	CKR_NAME,
	SIGNING_ERROR_CLASSES,
	SIGNING_STAGES,
	CertificatesHidden,
	LocalSignerError,
	PinIncorrect,
	PinLocked,
	TokenSigningFailed,
	TokenUnavailable,
)

TOKEN_NOT_AVAILABLE = "The USB token is not available. Check that it is plugged in and try again."
SIGNING_FAILED = TokenSigningFailed.MESSAGE
# The one stderr line per TOKEN_SIGNING_FAILED: the three closed-vocabulary fields only.
SIGNING_FAILED_LOG = "erp-dsc-local: the USB token could not sign (stage={stage} error={error} ckr={ckr})"
KEY_NOT_AVAILABLE = "The selected signing key is no longer available on a connected token."

# The timestamp request endesive makes (``requests.post(url, ..., **timestamp_req_options)``
# in endesive 2.19.3 signer.timestamp) as a requests ``(connect, read)`` timeout.  Defined
# here and nowhere else.
TSA_CONNECT_TIMEOUT_SECONDS = 5
TSA_TIMEOUT_SECONDS = 15

_LOGIN_OK = "ok"
_LOGIN_PIN_INCORRECT = "pin_incorrect"
_LOGIN_PIN_LOCKED = "pin_locked"
_LOGIN_FAILED = "failed"

# C_Login results that mean a wrong PIN was presented (spec §7).  Middleware differs in
# which one it returns and any of them may burn a try on the token, so all three are
# counted by the limiter and reported as PinIncorrect.  No other result is counted.
_WRONG_PIN_RESULTS = ("CKR_PIN_INCORRECT", "CKR_PIN_INVALID", "CKR_PIN_LEN_RANGE")


def _token_field(info, name: str) -> str:
	"""The one normaliser for a CK_TOKEN_INFO text field (label, serialNumber)."""
	return str(getattr(info, name)).split("\\0")[0].strip()


def _signing_failed(stage, diagnosis=None) -> TokenSigningFailed:
	"""The ``TOKEN_SIGNING_FAILED`` to raise (outside any ``except``), logged once to stderr.

	``diagnosis`` is ``_diagnosis()``'s ``(error, ckr)``.  A value outside the closed
	vocabularies becomes "other" (stage, error) or None (ckr) here, never a ``ValueError``.
	"""
	error, ckr = diagnosis if diagnosis is not None else ("other", None)
	if type(stage) is not str or stage not in SIGNING_STAGES:
		stage = "other"
	if type(error) is not str or error not in SIGNING_ERROR_CLASSES:
		error = "other"
	if ckr is not None and (type(ckr) is not str or not CKR_NAME.fullmatch(ckr)):
		ckr = None
	failure = TokenSigningFailed(stage=stage, error=error, ckr=ckr)
	try:
		sys.stderr.write(SIGNING_FAILED_LOG.format(stage=stage, error=error, ckr=ckr or "none") + "\n")
		sys.stderr.flush()
	except Exception:
		pass  # a closed stderr must not turn the failure into a different error
	return failure


def _diagnosis(exc, pk) -> tuple[str, str | None]:
	"""``(error, ckr)`` for ``exc``, from closed vocabularies only.  Called inside the
	``except`` that caught ``exc``; reads its class name and, for a ``PyKCS11Error``, its
	integer ``value`` -- never its text, args or traceback.  Never raises."""
	try:
		name = type(exc).__name__
		error = name if type(name) is str and name in SIGNING_ERROR_CLASSES else "other"
		ckr = None
		error_type = getattr(pk, "PyKCS11Error", None)
		table = getattr(pk, "CKR", None)
		if isinstance(error_type, type) and isinstance(exc, error_type) and type(table) is dict:
			value = getattr(exc, "value", None)
			found = table.get(value) if type(value) is int else None
			ckr = found if type(found) is str and CKR_NAME.fullmatch(found) else None
	except Exception:
		return "other", None
	return error, ckr


def _is_timestamp_error(exc) -> bool:
	"""Is ``exc`` a requests exception, i.e. from the timestamp request?  With
	``signature_meta`` allowlisted (no ``ltv``), the TSA request is endesive's only network
	call.  Read from ``sys.modules``: a requests exception implies requests is loaded."""
	base = getattr(sys.modules.get("requests.exceptions"), "RequestException", None)
	try:
		return isinstance(base, type) and isinstance(exc, base)
	except Exception:
		return False


class TokenClient:
	def __init__(self, module):
		try:
			import PyKCS11
		except ImportError as exc:
			raise LocalSignerError("DEPENDENCY_MISSING", "Install PyKCS11 to use a USB DSC token.", status=503) from exc
		self.pk = PyKCS11
		self.module = module
		self.lib = PyKCS11.PyKCS11Lib()
		try:
			self.lib.load(module.path)
		except Exception as exc:
			raise TokenUnavailable(f"Unable to load the selected token middleware: {exc}") from exc

	def certificates(self):
		"""List certificates without a PIN.

		``CertificatesHidden`` only when a session opened and ``findObjects`` returned ``[]``
		without error and nothing else went wrong; every other zero-certificate outcome is
		``TokenUnavailable`` (pre-login, so driver text may be named).
		"""
		try:
			slots = self.lib.getSlotList(tokenPresent=True)
		except Exception as exc:
			raise TokenUnavailable(self._unreadable(exc)) from exc
		if not slots:
			raise TokenUnavailable()
		certificates = []
		opened_empty = False
		last_error = None
		for slot in slots:
			try:
				info = self.lib.getTokenInfo(slot)
				label = _token_field(info, "label")
				serial = _token_field(info, "serialNumber")
				with self._session(slot) as session:
					objects = session.findObjects([(self.pk.CKA_CLASS, self.pk.CKO_CERTIFICATE)])
					if not objects:
						opened_empty = True
						continue
					usable = 0
					for obj in objects:
						der, key_id, value = session.getAttributeValue(
							obj, [self.pk.CKA_VALUE, self.pk.CKA_ID, self.pk.CKA_LABEL]
						)
						if not der or key_id is None:
							continue
						certificates.append(parse_token_certificate(bytes(der), bytes(key_id), str(value), slot, label, serial))
						usable += 1
					if not usable:
						last_error = "its certificates carry no CKA_ID"
			except Exception as exc:
				# One unreadable slot must not hide certificates on another.
				last_error = exc
				continue
		if certificates:
			return certificates
		if opened_empty and last_error is None:
			raise CertificatesHidden()
		raise TokenUnavailable(self._unreadable(last_error))

	def select(self, selector):
		"""The ONE selection point: returns ``(selected, certificates)``."""
		certificates = self.certificates()
		return select_certificate(certificates, selector), certificates

	def token_state(self, selected):
		"""``(flags, serial)`` of the selected token, read without a PIN.

		Raises ``TokenUnavailable`` when the selected slot no longer holds, alone, the
		selected token's serial — so flags are never read from a different token.
		"""
		info = self._chosen_slot_info(selected)
		return info.flags, _token_field(info, "serialNumber")

	def sign_pdf(self, pdf_bytes, selected, certificates, metadata, pin, timestamp_url=None, *, login_guard):
		"""Sign with the already-selected certificate; no re-enumeration.

		``login_guard`` is a context manager supplied by the caller, who already holds the
		per-serial token lock. ``with login_guard as guard`` is entered immediately before the
		single ``C_Login`` (it re-checks the limiter and may raise). Inside it the slot's
		flags are re-read and passed to ``guard.check_flags(flags)``, which may raise; then
		no ``C_Login`` is made. ``guard.succeeded()`` is called as soon as ``C_Login``
		returns, ``guard.failed()`` only for a wrong-PIN result (``_WRONG_PIN_RESULTS``);
		for any other outcome neither is called.

		The timestamp request is bounded by ``TSA_TIMEOUT_SECONDS``.  Any exception from
		endesive that is not a ``LocalSignerError`` (a TSA timeout, a refused connection, a
		bad reply) becomes ``TOKEN_SIGNING_FAILED`` with fixed text, raised outside the
		``except``, with stage ``tsa`` if it is a requests exception or if ``timestamp_url``
		is set and a C_Sign had already returned, and ``cms`` otherwise (see the module
		docstring for ``details``); in every case the session is logged out and closed
		before this returns.
		"""
		adapter = _TokenHSM(self, selected, pin, login_guard)
		pin = None
		try:
			from endesive.pdf import cms

			diagnosis = None
			try:
				appended = cms.sign(
					pdf_bytes,
					metadata,
					None,
					None,
					build_issuer_chain(selected, certificates),
					"sha256",
					hsm=adapter,
					timestampurl=timestamp_url,
					timestamp_req_options={"timeout": (TSA_CONNECT_TIMEOUT_SECONDS, TSA_TIMEOUT_SECONDS)},
				)
			except LocalSignerError:
				raise
			except Exception as exc:
				# A TSA that answers but refuses is no requests exception: endesive raises a
				# plain ValueError (signer.py ~143/145), as asn1crypto does for a status-only
				# reply.  With a TSA, whatever fails after a C_Sign returned is stage "tsa".
				after_c_sign_with_tsa = timestamp_url is not None and adapter.c_sign_returned
				stage = "tsa" if after_c_sign_with_tsa or _is_timestamp_error(exc) else "cms"
				diagnosis = (stage, _diagnosis(exc, self.pk))
			if diagnosis is not None:
				raise _signing_failed(*diagnosis) from None
			return pdf_bytes + appended, selected.metadata
		finally:
			adapter.close()
			adapter.pin = None

	def _chosen_slot_info(self, selected):
		"""Freshly re-read every present slot (no PIN) and return the selected slot's info.

		Only when ``selected.slot_id`` is the one and only present slot whose normalised
		serial equals ``selected.token_serial``; otherwise ``TokenUnavailable``.
		"""
		expected = selected.token_serial
		slots = self._present_slots() if expected else None
		chosen = None
		holders = 0
		for slot in slots or ():
			info = self._token_info_or_none(slot)
			if info is None or _token_field(info, "serialNumber") != expected:
				continue
			holders += 1
			if slot == selected.slot_id:
				chosen = info
		if chosen is None or holders != 1:
			raise TokenUnavailable(TOKEN_NOT_AVAILABLE) from None
		return chosen

	def _present_slots(self):
		try:
			return list(self.lib.getSlotList(tokenPresent=True))
		except Exception:
			return None

	def _token_info_or_none(self, slot):
		try:
			return self.lib.getTokenInfo(slot)
		except Exception:
			return None

	def _open_session_or_none(self, slot):
		try:
			return self.lib.openSession(slot, self.pk.CKF_SERIAL_SESSION)
		except Exception:
			return None

	def _unreadable(self, error) -> str:
		return (
			f"A USB token is connected, but the selected middleware ({self.module.label}) cannot read it "
			f"({error}). The token probably needs its own vendor's driver, not this one. "
			"Install the driver for your token and try again."
		)

	@contextmanager
	def _session(self, slot):
		session = self.lib.openSession(slot, self.pk.CKF_SERIAL_SESSION)
		try:
			yield session
		finally:
			try:
				session.closeSession()
			except Exception:
				pass


def _attempt_login(session, pin, pk) -> tuple[str, tuple | None]:
	"""Call ``C_Login`` once and classify the outcome; never lets the driver error escape.

	Returns ``(outcome, diagnosis)``; ``diagnosis`` (``_diagnosis``) only for ``_LOGIN_FAILED``.
	"""
	try:
		session.login(pin)
	except Exception as exc:
		error_type = getattr(pk, "PyKCS11Error", None)
		code = getattr(exc, "value", None) if error_type is not None and isinstance(exc, error_type) else None
		if code is not None and any(code == getattr(pk, name, object()) for name in _WRONG_PIN_RESULTS):
			return _LOGIN_PIN_INCORRECT, None
		if code is not None and code == getattr(pk, "CKR_PIN_LOCKED", object()):
			return _LOGIN_PIN_LOCKED, None
		return _LOGIN_FAILED, _diagnosis(exc, pk)
	return _LOGIN_OK, None


class _TokenHSM:
	"""endesive HSM adapter.  Logs in lazily, once, on the selected token only."""

	def __init__(self, client, certificate, pin, login_guard):
		self.client, self.certificate_data, self.pin = client, certificate, pin
		self.login_guard = login_guard
		self.session = None
		self.logged_in = False
		self.login_attempted = False
		self.c_sign_returned = False  # set once a C_Sign has returned a signature

	def certificate(self):
		"""``(CKA_ID, DER)``.  endesive loads the HSM certificate with asn1crypto from bytes
		(``signer.cert2asn(cert, False)`` in 2.19.3); a cryptography object raises
		``TypeError`` there, which ended every real USB signing as TOKEN_SIGNING_FAILED.
		``othercerts`` (``build_issuer_chain``) stay cryptography certificates: endesive calls
		``public_bytes`` on each of them."""
		return self.certificate_data.key_id, self.certificate_data.der

	def sign(self, key_id, data, hash_algorithm):
		pk = self.client.pk
		# SHA-256 only (spec §7).  endesive does not keep the "sha256" sign_pdf passes: a PDF
		# whose catalog has /Perms /DocMDP /Reference[0] /DigestMethod makes it sign with THAT
		# digest (cms.py ~715-727), and PyKCS11 has CKM_MD5_RSA_PKCS and CKM_SHA1_RSA_PKCS.
		# Anything else is refused BEFORE C_Login, so no PIN is sent for it.  The mechanism is
		# never derived from the argument, and the argument never reaches a message or a log.
		mechanism = getattr(pk, "CKM_SHA256_RSA_PKCS", None)
		if type(hash_algorithm) is not str or hash_algorithm != "sha256" or type(mechanism) is not int:
			raise _signing_failed("c_sign") from None
		if not self.logged_in:
			if self.login_attempted:
				raise _signing_failed("login") from None
			self._login()
		key = self._signing_key(key_id)
		diagnosis = None
		try:
			signature = bytes(bytearray(self.session.sign(key, data, pk.Mechanism(mechanism, None))))
		except Exception as exc:
			diagnosis = _diagnosis(exc, pk)
		if diagnosis is not None:
			raise _signing_failed("c_sign", diagnosis) from None
		# From here endesive's only remaining network step is the timestamp request.
		self.c_sign_returned = True
		return signature

	def _login(self):
		self.login_attempted = True
		client = self.client
		with self.login_guard as guard:
			info = client._chosen_slot_info(self.certificate_data)
			guard.check_flags(info.flags)  # re-read immediately before C_Login; may refuse
			session = client._open_session_or_none(self.certificate_data.slot_id)
			if session is None:
				raise TokenUnavailable(TOKEN_NOT_AVAILABLE) from None
			self.session = session
			try:
				outcome, diagnosis = _attempt_login(session, self.pin, client.pk)
			finally:
				# One C_Login per entry: the PIN is never needed again, so it is not held
				# through signing or the timestamp request (I7).
				self.pin = None
			if outcome == _LOGIN_OK:
				guard.succeeded()
			elif outcome == _LOGIN_PIN_INCORRECT:
				guard.failed()
		if outcome == _LOGIN_OK:
			self.logged_in = True
			return
		if outcome == _LOGIN_PIN_INCORRECT:
			raise PinIncorrect() from None
		if outcome == _LOGIN_PIN_LOCKED:
			raise PinLocked() from None
		raise _signing_failed("login", diagnosis) from None

	def _signing_key(self, key_id):
		pk = self.client.pk
		diagnosis = None
		try:
			keys = self.session.findObjects([(pk.CKA_CLASS, pk.CKO_PRIVATE_KEY), (pk.CKA_ID, key_id)])
		except Exception as exc:
			diagnosis = _diagnosis(exc, pk)
		if diagnosis is not None:
			raise _signing_failed("find_key", diagnosis) from None
		if not keys:
			raise TokenUnavailable(KEY_NOT_AVAILABLE) from None
		return keys[0]

	def close(self):
		"""Log out and close the session.  Does NOT clear ``pin``: ``_login`` drops it once
		``C_Login`` returns, and ``sign_pdf``'s ``finally`` covers every path that never
		reached ``C_Login``."""
		session, self.session = self.session, None
		if session is None:
			return
		if self.logged_in:
			try:
				session.logout()
			except Exception:
				pass
		self.logged_in = False
		try:
			session.closeSession()
		except Exception:
			pass
