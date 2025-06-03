import argparse
import json
import pathlib
import sys
from typing import Any, Final

import requests

from src.cheks.config import Colors
from src.cheks.cve_cheks.main import (
    CVE_2017_9506,
    CVE_2018_20824,
    CVE_2019_3402,
    CVE_2019_3403,
    CVE_2019_3396,
    CVE_2019_8442,
    CVE_2019_8443,
    CVE_2019_8449,
    CVE_2019_8451,
    CVE_2019_11581,
    CVE_2020_14179,
    CVE_2020_14181,
    CVE_2020_36289,
    CVE_2020_36287_helper,
)
from src.cheks.detect_version import detect_version
from src.cheks.unauthenticated_checks.main import (
    Unauth_User_picker,
    Unauth_Resolutions,
    Unauth_Projects,
    Unauth_Project_categories,
    Unauth_Dashboard,
    Unauth_Dashboard_admin,
    Service_desk_signup,
    Unauth_Install_Gadgets,
    Unauth_Group_Picker,
    Unauth_Screens,
    FieldNames_QueryComponentJql,
    user_reg,
    dev_mode,
)


def clean_url(url):
    while url.endswith("/"):
        url = url[0:-1]
    return url


def save_results(all_results_of_target: list[str], JSON_OUTPUT) -> None:
    with open(JSON_OUTPUT, 'w', encoding='utf-8') as final_jf:
        json.dump(all_results_of_target, final_jf, indent=2)
    print(f"\t{Colors.RED}File Written to : {str(JSON_OUTPUT)}{Colors.RESET}")


def worker(url: str) -> dict[str, Any]:
    try:
        base_url = clean_url(url)
        detect_version(base_url)

        findings = []

        # CVE checks
        cve_funcs = [
            CVE_2017_9506,
            CVE_2018_20824,
            CVE_2019_3402,
            CVE_2019_3403,
            CVE_2019_3396,
            CVE_2019_8442,
            CVE_2019_8443,
            CVE_2019_8449,
            CVE_2019_8451,
            CVE_2019_11581,
            CVE_2020_14179,
            CVE_2020_14181,
            CVE_2020_36287_helper,
            CVE_2020_36289,
        ]

        for func in cve_funcs:
            result = func(base_url)
            if result:
                if isinstance(result, list):
                    findings.extend(result)
                else:
                    findings.append(result)

        # Unauthenticated checks
        unauth_funcs = [
            Unauth_User_picker,
            Unauth_Resolutions,
            Unauth_Projects,
            Unauth_Project_categories,
            Unauth_Dashboard,
            Unauth_Dashboard_admin,
            Service_desk_signup,
            Unauth_Install_Gadgets,
            user_reg,
            Unauth_Group_Picker,
            Unauth_Screens,
            FieldNames_QueryComponentJql,
            dev_mode,
        ]

        for func in unauth_funcs:
            result = func(base_url)
            if result:
                if isinstance(result, list):
                    findings.extend(result)
                else:
                    findings.append(result)

        return {
            "target-url": url,
            "findings": findings,
        }

    except KeyboardInterrupt:
        print(f"{Colors.RED} Keyboard Interrupt Detected {Colors.RESET}")
        sys.exit(0)

    except requests.exceptions.ConnectionError:
        print(f"{Colors.RED}Connection error for {url}: Unable to resolve host (check URL or network){Colors.RESET}")
        return {
            "target-url": url,
            "findings": [],
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Jira-Lens : Jira Security Auditing Tool")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--file", type=argparse.FileType('r'), dest='input_file')
    parser.add_argument("--output", help="Output file", default="result.json")

    args = parser.parse_args()

    MAIN_DIR: Final[pathlib.Path] = pathlib.Path(__file__).parents[1]
    JSON_OUTPUT: Final[pathlib.Path] = MAIN_DIR / "output" / args.output

    if not args.url and not args.input_file:
        print(f"{Colors.RED}\tNo URL Provided\n\tUse -u/--url to provide a target{Colors.RESET}")
        sys.exit(0)

    if args.url and args.input_file:
        print(f"{Colors.RED}\tMultiple Inputs Provided\n\tUse either -u (URL) or -f (FILE), not both{Colors.RESET}")
        sys.exit(0)

    results = []
    if args.input_file:
        print(f"{Colors.CYAN}Input File Provided : {args.input_file.name}{Colors.RESET}")
        urls = set(line.strip() for line in args.input_file if line.strip())
        print(f"{Colors.CYAN}{len(urls)} Unique URLs Found{Colors.RESET}")
        for url in urls:
            result = worker(url=url)
            if result:
                results.append(result)
    else:
        url = args.url
        result = worker(url=url)
        if result:
            results.append(result)

    save_results(results, JSON_OUTPUT)
    exit()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"{Colors.RED} Keyboard Interrupt Detected {Colors.RESET}")
        sys.exit(0)
