import socket
from urllib.parse import urlparse


def isaws(base_url: str) -> bool:
    try:
        host = urlparse(base_url).netloc
        return "amazonaws" in socket.gethostbyaddr(host)[0]
    except Exception:
        return False
