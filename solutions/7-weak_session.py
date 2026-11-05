from dvwa import DVWA

SECURITY = "low"
COUNT = 10
"""
Low: 每次 +1 的递增整数
Medium: Unix 时间戳
High: 递增值的 md5, 需要反推
"""

target = DVWA("weak_id", SECURITY)

for index in range(COUNT):
    target.post("", data={"generate": "Generate"})
    value = target.session.cookies.get("dvwaSession")
    print(f"No. {index + 1}: {value}")
