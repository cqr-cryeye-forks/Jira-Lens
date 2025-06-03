import requests

from src.cheks.config import HEADERS, Colors


def Unauth_User_picker(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/secure/popups/UserPickerBrowser.jspa"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and "user-picker" in r.text:
        print(f"{Colors.RED}[+] {Colors.CYAN}[INFO]{Colors.RESET} User Picker Enabled : {url}?max=1000")
        finding = {
            "title": "User Picker Enabled",
            "severity": "INFO",
            "target-url": f"{url}?max=1000",
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] User Picker Disabled{Colors.RESET}")
        return None


def Unauth_Group_Picker(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/rest/api/2/groupuserpicker"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200:
        if "You are not authenticated. Authentication required to perform this operation." in r.text:
            print(f"{Colors.GRAY}[-] REST GroupUserPicker is not available")
            return None
        else:
            print(f"{Colors.RED}[+] {Colors.CYAN}[INFO]{Colors.RESET} REST GroupUserPicker is available : {url}")
            finding = {
                "title": "REST GroupUserPicker is available",
                "severity": "INFO",
                "target-url": url,
            }
            return finding
    else:
        print(f"{Colors.GRAY}[-] REST GroupUserPicker is not available")
        return None


def Unauth_Resolutions(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/rest/api/2/resolution"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and any(key in r.text for key in ['self', 'description', 'name']):
        print(f"{Colors.RED}[+] {Colors.CYAN}[INFO]{Colors.RESET} Resolutions Found : {url}")
        finding = {
            "title": "Resolutions Found",
            "severity": "INFO",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] No Resolutions Found")
        return None


def Unauth_Projects(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/rest/api/2/project?maxResults=100"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and all(key in r.text for key in ['projects', 'startAt', 'maxResults']):
        print(f"{Colors.RED}[+] {Colors.GREEN}[LOW]{Colors.RESET} Projects Found : {url}")
        finding = {
            "title": "Projects Found",
            "severity": "LOW",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] Projects Not Found")
        return None


def Unauth_Project_categories(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/rest/api/2/projectCategory?maxResults=1000"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and any(key in r.text for key in ['self', 'description', 'name']):
        print(f"{Colors.RED}[+] {Colors.GREEN}[LOW]{Colors.RESET} Project Groups Found : {url}")
        finding = {
            "title": "Project Groups Found",
            "severity": "LOW",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] Project Groups Not Found{Colors.RESET}")
        return None


def Unauth_Dashboard(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/rest/api/2/dashboard?maxResults=100"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and all(key in r.text for key in ['dashboards', 'startAt', 'maxResults']):
        print(f"{Colors.RED}[+] {Colors.CYAN}[INFO]{Colors.RESET} Found Unauthenticated DashBoard Access : {url}")
        finding = {
            "title": "Found Unauthenticated DashBoard Access",
            "severity": "INFO",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] No Unauthenticated DashBoard Access Found{Colors.RESET}")
        return None


def Unauth_Dashboard_Popular(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/secure/ManageFilters.jspa?filter=popular&filterView=popular"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and "Popular Filters" in r.text:
        print(f"{Colors.RED}[+] {Colors.CYAN}[INFO]{Colors.RESET} Filters Accessible : {url}")
        finding = {
            "title": "Filters Accessible",
            "severity": "INFO",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] Filters Not Accessible{Colors.RESET}")
        return None


def Unauth_Dashboard_admin(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/rest/menu/latest/admin"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and all(key in r.text for key in ['key', 'link', 'label', 'self']):
        print(f"{Colors.RED}[+] {Colors.CYAN}[INFO]{Colors.RESET} Admin Project Dashboard Accessible : {url}")
        finding = {
            "title": "Admin Project Dashboard Accessible",
            "severity": "INFO",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] Admin Project Dashboard UnAccessible")
        return None


def Service_desk_signup(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/servicedesk/customer/user/signup"
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and "Service Management" in r.text:
        print(
            f"{Colors.RED}[+] {Colors.GREEN}[MEDIUM]{Colors.RESET} Service Desk Signup Enabled : {url}{Colors.RESET}")
        finding = {
            "title": "Service Desk Signup Enabled",
            "severity": "MEDIUM",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] Service Desk Signup Disabled{Colors.RESET}")
        return None


def Unauth_Install_Gadgets(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/rest/config/1.0/directory"
    r = requests.get(url)
    if r.status_code == 200 and "jaxbDirectoryContents" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN}[LOW]{Colors.RESET} REST Gadgets Accessible : {url}{Colors.RESET}")
        finding = {
            "title": "REST Gadgets Accessible",
            "severity": "LOW",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] REST Gadgets UnAccessible")
        return None


def Unauth_Screens(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/rest/api/2/screens"
    r = requests.get(url, allow_redirects=False)
    if r.status_code == 200 and any(key in r.text for key in ['id', 'name', 'description']):
        print(f"{Colors.RED}[+] {Colors.GREEN}[LOW]{Colors.RESET} Unauthenticated Access To Screens : {url}")
        finding = {
            "title": "Unauthenticated Access To Screens",
            "severity": "LOW",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] No Unauthenticated Access To Screens Found{Colors.RESET}")
        return None


def FieldNames_QueryComponentJql(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/secure/QueryComponent!Jql.jspa?jql="
    r = requests.get(url, allow_redirects=False, headers=HEADERS)
    if r.status_code == 200 and "searchers" in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN}[LOW]{Colors.RESET} Found Query Component Fields : {url}")
        finding = {
            "title": "Found Query Component Fields",
            "severity": "LOW",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] No Query Component Fields Found{Colors.RESET}")
        return None


def user_reg(base_url: str) -> dict[str, str] | None:
    try:
        url = f"{base_url}/secure/Signup!default.jspa"
        r = requests.get(url, allow_redirects=False)
        if r.status_code == 200:
            if "private" in r.text:
                print(f"{Colors.GRAY}[-] User registration is Disabled{Colors.RESET}")
            else:
                print(f"{Colors.RED}[+] {Colors.GREEN}[MEDIUM]{Colors.RESET} User registration is Enabled : {url}")
                finding = {
                    "title": "User registration is Enabled",
                    "severity": "MEDIUM",
                    "target-url": url
                }
                return finding
        else:
            print(f"{Colors.GRAY}[-] User registration is Disabled{Colors.RESET}")
    except KeyboardInterrupt:
        print(f"{Colors.RED} User Aborted the Program {Colors.RESET}")
    return None


def dev_mode(base_url: str) -> dict[str, str] | None:
    url = f"{base_url}/"
    r = requests.get(url, allow_redirects=False)
    if r.status_code == 200 and '<meta name="ajs-dev-mode" content="true">' in r.text:
        print(f"{Colors.RED}[+] {Colors.GREEN} [LOW]{Colors.RESET} Dev Mode is Enabled : {url}")
        finding = {
            "title": "Dev Mode is Enabled",
            "severity": "LOW",
            "target-url": url,
        }
        return finding
    else:
        print(f"{Colors.GRAY}[-] Dev Mode is Disabled{Colors.RESET}")
        return None
