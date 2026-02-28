"""
SHEIN Bot Configuration
⚡ Made by RIVEN
"""

import os

# ================= TELEGRAM =================
TOKEN = os.environ.get("BOT_TOKEN", "8376618298:AAEVC1jF_LxKKRt9bZ2BlKqr-kAcork6NyE")
ADMIN_ID = int(os.environ.get("ADMIN_ID", "7482489989"))

# ================= FILE PATHS =================
PROXY_FILE = "proxy.txt"
VOUCHER_FILE = "voucher.txt"
APPLICABLE_FILE = "applicable_vouchers.txt"
NOT_APPLICABLE_FILE = "not_applicable_vouchers.txt"
LOGS_FILE = "logs.json"
COOKIES_FILE = "cookies.json"

# ================= SCANNER API =================
SECRET_KEY = "3LFcKwBTXcsMzO5LaUbNYoyMSpt7M3RP5dW9ifWffzg"
CLIENT_TOKEN_URL = "https://api.services.sheinindia.in/uaas/jwt/token/client"
ACCOUNT_CHECK_URL = "https://api.services.sheinindia.in/uaas/accountCheck?client_type=Android%2F29&client_version=1.0.8"
SHEIN_BASE_URL = "https://shein-creator-backend-151437891745.asia-south1.run.app/api"
CREATOR_TOKEN_URL = f"{SHEIN_BASE_URL}/v1/auth/generate-token"
PROFILE_URL = f"{SHEIN_BASE_URL}/v1/user"

# ================= CHECKER API =================
APPLY_URL = "https://www.sheinindia.in/api/cart/apply-voucher"
RESET_URL = "https://www.sheinindia.in/api/cart/reset-voucher"

# ================= PERFORMANCE =================
WORKERS_PER_PROXY = 1
TOKEN_REUSE_COUNT = 8
MAX_RETRIES = 3
VOUCHER_POLL_RETRIES = 3
VOUCHER_POLL_DELAY = 0.8
QUEUE_SIZE = 500
TIMEOUT = (10, 15)
CHECK_WORKERS = 5

# ================= FINGERPRINTS =================
BROWSER_PROFILES = [
    "chrome120", "chrome119", "chrome124", "chrome131",
    "chrome110", "chrome116", "chrome107", "chrome104",
    "chrome101", "chrome100", "chrome99",
]

DEVICES = [
    {"model": "SM-G991B",      "android": "12", "build": "SP1A.210812.016",  "sdk": "31"},
    {"model": "SM-S918B",      "android": "14", "build": "UP1A.231005.007",  "sdk": "34"},
    {"model": "SM-A536B",      "android": "13", "build": "TP1A.220624.014",  "sdk": "33"},
    {"model": "SM-G998B",      "android": "13", "build": "TP1A.220624.014",  "sdk": "33"},
    {"model": "Pixel 7",       "android": "13", "build": "TQ3A.230901.001",  "sdk": "33"},
    {"model": "Pixel 8",       "android": "14", "build": "UD1A.230803.022",  "sdk": "34"},
    {"model": "Pixel 6a",      "android": "13", "build": "TQ3A.230705.001",  "sdk": "33"},
    {"model": "OnePlus 9",     "android": "13", "build": "TP1A.220905.001",  "sdk": "33"},
    {"model": "OnePlus 11",    "android": "14", "build": "UKQ1.230924.001",  "sdk": "34"},
    {"model": "Redmi Note 12", "android": "13", "build": "TKQ1.220829.002",  "sdk": "33"},
    {"model": "Redmi K60",     "android": "14", "build": "UKQ1.231003.002",  "sdk": "34"},
    {"model": "Vivo V29",      "android": "13", "build": "TP1A.220624.014",  "sdk": "33"},
    {"model": "OPPO Reno 10",  "android": "13", "build": "TP1A.220624.014",  "sdk": "33"},
    {"model": "RMX3561",       "android": "13", "build": "TP1A.220905.001",  "sdk": "33"},
    {"model": "M2101K6G",      "android": "12", "build": "SP1A.210812.016",  "sdk": "31"},
    {"model": "CPH2493",       "android": "13", "build": "TP1A.220624.014",  "sdk": "33"},
]
