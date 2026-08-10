"""PKCS#11 access.  This module is imported only on workstations with middleware."""

from __future__ import annotations

from contextlib import contextmanager

from .certificates import build_issuer_chain, parse_token_certificate, select_certificate
from .errors import LocalSignerError, PinRequired, TokenUnavailable


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
		certificates = []
		for slot in self.lib.getSlotList(tokenPresent=True):
			try:
				info = self.lib.getTokenInfo(slot)
				label = str(info.label).split("\\0")[0].strip()
				serial = str(info.serialNumber).split("\\0")[0].strip()
				with self._session(slot) as session:
					objects = session.findObjects([(self.pk.CKA_CLASS, self.pk.CKO_CERTIFICATE)])
					for obj in objects:
						der, key_id, value = session.getAttributeValue(
							obj, [self.pk.CKA_VALUE, self.pk.CKA_ID, self.pk.CKA_LABEL]
						)
						if not der or key_id is None:
							continue
						certificates.append(parse_token_certificate(bytes(der), bytes(key_id), str(value), slot, label, serial))
			except Exception:
				# A token may require login even to enumerate certificates; preserve the
				# PIN boundary and let signing prompt locally.
				continue
		if not certificates:
			raise PinRequired()
		return certificates

	def sign_pdf(self, pdf_bytes, metadata, selector, pin, timestamp_url=None):
		certificates = self.certificates()
		selected = select_certificate(certificates, selector)
		if not pin:
			raise LocalSignerError("PIN_REQUIRED", "Enter the DSC token PIN in the local signer.", status=409)
		adapter = _TokenHSM(self, selected, pin)
		try:
			from endesive.pdf import cms
			appended = cms.sign(pdf_bytes, metadata, None, None, build_issuer_chain(selected, certificates), "sha256", hsm=adapter, timestampurl=timestamp_url)
			return pdf_bytes + appended, selected.metadata
		finally:
			adapter.close()

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


class _TokenHSM:
	def __init__(self, client, certificate, pin):
		self.client, self.certificate_data, self.pin = client, certificate, pin
		self.session = None

	def certificate(self):
		return self.certificate_data.key_id, self.certificate_data.crypto_certificate

	def sign(self, key_id, data, hash_algorithm):
		for slot in self.client.lib.getSlotList(tokenPresent=True):
			try:
				self.session = self.client.lib.openSession(slot, self.client.pk.CKF_SERIAL_SESSION)
				self.session.login(self.pin)
				keys = self.session.findObjects([(self.client.pk.CKA_CLASS, self.client.pk.CKO_PRIVATE_KEY), (self.client.pk.CKA_ID, key_id)])
				if not keys:
					self.close()
					continue
				mechanism_name = f"CKM_{str(hash_algorithm).upper()}_RSA_PKCS"
				mechanism = getattr(self.client.pk, mechanism_name, None)
				if mechanism is None:
					raise LocalSignerError("UNSUPPORTED_ALGORITHM", f"Token does not support {hash_algorithm} RSA signing.")
				return bytes(bytearray(self.session.sign(keys[0], data, self.client.pk.Mechanism(mechanism, None))))
			except LocalSignerError:
				raise
			except Exception as exc:
				raise LocalSignerError("TOKEN_SIGNING_FAILED", f"The USB token could not sign the document: {exc}", status=502) from exc
		raise TokenUnavailable("The selected signing key is no longer available on a connected token.")

	def close(self):
		if self.session is not None:
			try:
				self.session.logout()
			except Exception:
				pass
			try:
				self.session.closeSession()
			except Exception:
				pass
			self.session = None
