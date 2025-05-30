import colorama
colorama.init()

import colorama

# Initialize colorama
colorama.init(autoreset=True)

# ----------------------------------------
# HTTP Headers
# ----------------------------------------

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/88.0.4324.190 Safari/537.36"
    ),
    "Content-Type": "application/json",
}

# ----------------------------------------
# AWS Metadata Endpoints
# ----------------------------------------

class AWSConfig:
    BASE = "http://169.254.169.254/latest"
    METADATA = f"{BASE}/meta-data/"
    IAM_ROLE = f"{METADATA}iam/security-credentials/"
    IAM_CRED = IAM_ROLE + "%s"  # %s -> IAM role name

# ----------------------------------------
# Terminal Colors
# ----------------------------------------

class Colors:
    GREEN = colorama.Fore.GREEN
    GRAY = colorama.Fore.LIGHTBLACK_EX
    RED = colorama.Fore.RED
    BLUE = colorama.Fore.BLUE
    CYAN = colorama.Fore.CYAN
    YELLOW = colorama.Fore.YELLOW
    MAGENTA = colorama.Fore.MAGENTA
    RESET = colorama.Fore.RESET

    RESET_BACK = colorama.Back.RESET
    BOLD = colorama.Style.BRIGHT
    BOLD_RESET = colorama.Style.RESET_ALL


    DIM=colorama.Style.BRIGHT
    DIM_RESET=colorama.Style.RESET_ALL
    RESET2 = colorama.Back.RESET