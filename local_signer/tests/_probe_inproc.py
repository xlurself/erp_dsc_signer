"""Test seam: run ``TokenClient``'s PIN-free reads IN-PROCESS over a fake PKCS#11 library.

Only the subprocess transport is replaced.  The request is still built by
``token.run_probe`` and decoded by the real child ``token_probe.handle``, which runs the
real ``token_probe.probe`` over the fake ``(pk, lib)``; the reply line it encodes goes
through the real strict parser in ``token``.  ``client.pk`` and ``client.lib`` are read
at call time, so a test may swap them after ``make_client``.  Not a test module.
"""

from erp_dsc_local import token, token_probe


def in_process_transport(load):
	"""A ``run_probe`` transport: ``load(module_path) -> (pk, lib)`` runs in this process."""

	def transport(request, timeout):
		return None, token_probe.handle(request, load=load)

	return transport


def use_in_process_probe(client):
	transport = in_process_transport(lambda path: (client.pk, client.lib))
	client._probe = lambda op: token.run_probe(client.module.path, op, transport=transport)
	return client
