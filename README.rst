aioquic_mitmproxy
=================

|rtd| |pypi-v| |pypi-pyversions| |pypi-l| |tests| |codecov| |black|

.. |rtd| image:: https://readthedocs.org/projects/aioquic/badge/?version=latest
    :target: https://aioquic.readthedocs.io/

.. |pypi-v| image:: https://img.shields.io/pypi/v/aioquic-mitmproxy.svg
    :target: https://pypi.python.org/pypi/aioquic-mitmproxy

.. |pypi-pyversions| image:: https://img.shields.io/pypi/pyversions/aioquic-mitmproxy.svg
    :target: https://pypi.python.org/pypi/aioquic-mitmproxy

.. |pypi-l| image:: https://img.shields.io/pypi/l/aioquic-mitmproxy.svg
    :target: https://pypi.python.org/pypi/aioquic-mitmproxy

.. |tests| image:: https://github.com/meitinger/aioquic_mitmproxy/workflows/tests/badge.svg
    :target: https://github.com/meitinger/aioquic_mitmproxy/actions

.. |codecov| image:: https://img.shields.io/codecov/c/github/meitinger/aioquic_mitmproxy.svg
    :target: https://codecov.io/gh/meitinger/aioquic_mitmproxy

.. |black| image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/python/black

What is ``aioquic_mitmproxy``?
------------------------------

``aioquic_mitmproxy`` is a fork of `aioquic`_, that is specifically targeted
towards `mitmproxy`_.

If you want to use QUIC and/or HTTP/3 in your Python project, you should use
``aioquic`` instead: https://pypi.org/project/aioquic/

Any code contributions to ``aioquic`` should also be submitted directly to
upstream: https://github.com/aiortc/aioquic

What is ``aioquic``?
--------------------

``aioquic`` is a library for the QUIC network protocol in Python. It features
a minimal TLS 1.3 implementation, a QUIC stack and an HTTP/3 stack.

QUIC was standardised in `RFC 9000`_ and HTTP/3 in `RFC 9114`_.
``aioquic`` is regularly tested for interoperability against other
`QUIC implementations`_.

To learn more about ``aioquic`` please `read the documentation`_.

Why should I use ``aioquic``?
-----------------------------

``aioquic`` has been designed to be embedded into Python client and server
libraries wishing to support QUIC and / or HTTP/3. The goal is to provide a
common codebase for Python libraries in the hope of avoiding duplicated effort.

Both the QUIC and the HTTP/3 APIs follow the "bring your own I/O" pattern,
leaving actual I/O operations to the API user. This approach has a number of
advantages including making the code testable and allowing integration with
different concurrency models.

Features
--------

- QUIC stack conforming with `RFC 9000`_
- HTTP/3 stack conforming with `RFC 9114`_
- minimal TLS 1.3 implementation conforming with `RFC 8446`_
- IPv4 and IPv6 support
- connection migration and NAT rebinding
- logging TLS traffic secrets
- logging QUIC events in QLOG format
- HTTP/3 server push support

Requirements
------------

``aioquic`` requires Python 3.8 or better.

Running the examples
--------------------

`aioquic` comes with a number of examples illustrating various QUIC usecases.

You can browse these examples here: https://github.com/aiortc/aioquic/tree/main/examples

License
-------

``aioquic`` is released under the `BSD license`_.

.. _read the documentation: https://aioquic.readthedocs.io/en/latest/
.. _QUIC implementations: https://github.com/quicwg/base-drafts/wiki/Implementations
.. _cryptography: https://cryptography.io/
.. _Chocolatey: https://chocolatey.org/
.. _BSD license: https://aioquic.readthedocs.io/en/latest/license.html
.. _RFC 8446: https://datatracker.ietf.org/doc/html/rfc8446
.. _RFC 9000: https://datatracker.ietf.org/doc/html/rfc9000
.. _RFC 9114: https://datatracker.ietf.org/doc/html/rfc9114
.. _aioquic: https://github.com/aiortc/aioquic
.. _mitmproxy: https://github.com/mitmproxy/mitmproxy
