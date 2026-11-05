import html
import os
import re

import requests

# 靶机地址与会话都从环境变量读取, 默认值只适用于本机起的 DVWA.
BASE_URL = os.environ.get("DVWA_URL", "http://127.0.0.1:8080")
PHPSESSID = os.environ.get("DVWA_PHPSESSID", "")
LEVELS = ("low", "medium", "high")
TOKEN_PATTERN = re.compile(
    r"name='user_token' value='([^']+)'"
)


class DVWAError(RuntimeError):
    """会话失效, 或者页面结构不符合预期."""


class DVWA:
    """一个漏洞模块的会话封装, 模块名就是 URL 里的目录名."""

    def __init__(
        self,
        module,
        security="low",
        base_url=BASE_URL,
        phpsessid=PHPSESSID,
    ):
        if not phpsessid:
            raise DVWAError(
                "缺少 PHPSESSID, 先 export DVWA_PHPSESSID=<浏览器 Cookie 里的值>."
            )
        self.module = module
        self.security = security
        self.base_url = base_url.rstrip("/")
        self.url = (
            f"{self.base_url}/vulnerabilities/{module}/"
        )
        self.session = requests.Session()
        self.session.cookies.set("PHPSESSID", phpsessid)
        self.session.cookies.set("security", security)

    def get(self, path="", **kwargs):
        return self._send("GET", path, **kwargs)

    def post(self, path="", **kwargs):
        return self._send("POST", path, **kwargs)

    def token(self, path=""):
        """取页面里的 user_token, 只有 high 级别需要."""
        response = self.get(path)
        match = TOKEN_PATTERN.search(response.text)
        if not match:
            raise DVWAError(
                f"{self.url}{path} 里没有 user_token"
            )
        return match.group(1)

    def _send(self, method, path, **kwargs):
        """strict=False 时不因 4xx 抛错, 盲注模块会用 404 表示没命中."""
        strict = kwargs.pop("strict", True)
        kwargs.setdefault("timeout", 30)
        response = self.session.request(
            method, self._resolve(path), **kwargs
        )
        if "login.php" in response.url:
            raise DVWAError(
                "会话已失效, 更新 PHPSESSID 后再试."
            )
        if strict:
            response.raise_for_status()
        return response

    def _resolve(self, path):
        if path.startswith(("http://", "https://")):
            return path
        return self.url + path


def clean(text):
    """删掉标签并压缩空白, 方便做字符串判断."""
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def pre_blocks(text):
    """返回所有 pre 块, 保留内部换行, 用于命令执行这类输出."""
    blocks = re.findall(
        r"<pre>(.*?)</pre>", text, re.DOTALL
    )
    return [
        html.unescape(block).strip() for block in blocks
    ]


def sql_rows(text):
    """返回 SQL 注入页面里的 (First name, Surname)."""
    return re.findall(
        r"First name:\s*(\S+)\s*Surname:\s*(\S+)",
        clean(text),
    )
