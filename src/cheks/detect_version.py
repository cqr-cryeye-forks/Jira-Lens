import socket
import sys
from typing import Any
from urllib.parse import urlparse

import requests

from src.cheks.config import Colors


def detect_version(base_url: str) -> dict[str, Any] | None:
    """Detect server version and related information."""
    url = f"{base_url}/rest/api/latest/serverInfo"
    try:
        response = requests.get(url, allow_redirects=False, timeout=5)

        # Check if response is successful and contains JSON
        if response.status_code != 200:
            return None

        try:
            server_data = response.json()
        except requests.exceptions.JSONDecodeError:
            return None

        print('\n')
        print(f"\t{Colors.GREEN}-------- Server Information -----------{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA} [*] URL --> {server_data.get('baseUrl')}")
        print(f"{Colors.BOLD_RESET} [*] Server Title --> {server_data.get('serverTitle')}")
        print(f" [*] Version --> {server_data.get('version')}")
        print(f" [*] Deployment Type --> {server_data.get('deploymentType')}")
        print(f" [*] Build Number --> {server_data.get('buildNumber')}")
        print(f" [*] Database Build Number --> {server_data.get('databaseBuildNumber')}")

        server_data_result = {
            "baseUrl": server_data.get('baseUrl'),
            "serverTitle": server_data.get('serverTitle'),
            "version": server_data.get('version'),
            "deploymentType": server_data.get('deploymentType'),
            "buildNumber": server_data.get('buildNumber'),
            "databaseBuildNumber": server_data.get('databaseBuildNumber'),
        }

        try:
            host = urlparse(base_url).netloc
            host_info = socket.gethostbyaddr(host)
            print(f" [*] Host Address --> {host_info[0]}")
            server_data_result["hostname"] = host_info[0]
        except Exception:
            print(" [*] Host Address --> Error While Resolving Host")

        try:
            ip_address = socket.gethostbyaddr(urlparse(base_url).netloc)[2][0]
            print(f" [*] IP Address --> {ip_address}")
            server_data_result["ip"] = ip_address
        except Exception:
            print(" [*] IP Address --> Error While Resolving IP Address")

        return server_data_result
    except KeyboardInterrupt:
        print(f"{Colors.RED} Keyboard Interrupt Detected {Colors.RESET}")
        sys.exit(0)

    except requests.exceptions.ConnectionError:
        print(f"{Colors.RED}Connection error for {url}: Unable to resolve host (check URL or network){Colors.RESET}")
    return None
