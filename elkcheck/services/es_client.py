import warnings

from elasticsearch import Elasticsearch, __version__ as _ES_VERSION
from elasticsearch.exceptions import ConnectionError as ESConnectionError
from elasticsearch.exceptions import ElasticsearchWarning, TransportError


def elasticsearch_client(host, username="", password="", request_timeout=30):
    """
    Connection kwargs tuned for corporate / IP-based HTTPS endpoints.

    - http_compress=False: default client uses gzip; some proxies or ES builds
      drop the connection when Accept-Encoding is negotiated.
    - ssl_assert_hostname=False with verify_certs=False: avoids TLS hostname
      checks against raw IPs / internal cert SANs.
    - timeout=...: pool default (elasticsearch-py ignores ``request_timeout`` here).

    Auth: elasticsearch-py 7.x expects ``http_auth``; 8+ uses ``basic_auth``.
    Passing only ``basic_auth`` on 7.x is ignored, so ES returns 401 "missing credentials".
    """
    timeout = float(request_timeout)
    host = (host or "").strip()
    auth_pair = (username or "", password or "")
    kw = dict(
        ssl_show_warn=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        http_compress=False,
        timeout=timeout,
        retry_on_timeout=True,
    )
    if int(_ES_VERSION[0]) >= 8:
        kw["basic_auth"] = auth_pair
    else:
        kw["http_auth"] = auth_pair
    return Elasticsearch(host, **kw)


def search_silencing_product_warning(es, *, index, body):
    """Run search; suppress privilege warning when GET / is forbidden but search works."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ElasticsearchWarning)
        return es.search(index=index, body=body)


_CONN_HINT = (
    "Check that the host uses the correct scheme (https:// vs http://), port, "
    "and network path (VPN/firewall). If the server is plain HTTP, do not use https://."
)


def format_transport_error(exc):
    # ConnectionError subclasses TransportError; check connection issues first for the extra hint.
    if isinstance(exc, ESConnectionError):
        return f"{exc} {_CONN_HINT}"
    if isinstance(exc, TransportError):
        return str(exc)
    return str(exc)
