# OWASP Top 10 靶机题解: DVWA 全关卡

> [!WARNING]
> 本仓库仅用于自建靶场的授权测试与学习.
> 请勿把脚本指向任何你未获得书面授权的系统.

## 快速开始

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

脚本不会把靶机地址和会话写死在代码里, 全部从环境变量读取:

```bash
export DVWA_URL=http://127.0.0.1:8080
export DVWA_PHPSESSID=<浏览器里的 PHPSESSID>
```

`PHPSESSID` 的取法: 在浏览器里登录 DVWA, 打开开发者工具, `Application -> Cookies -> DVWA 域名 -> PHPSESSID`.
`security` 这个 cookie 由脚本按 `SECURITY` 常量自己设置, 不用手动改.

然后挑一个脚本跑:

```bash
python solutions/1-brute.py
```

每个脚本顶部的 `SECURITY` 常量决定打哪一档:

```python
SECURITY = "low"   # low / medium / high
```

## 关卡与脚本对照

| # | 关卡 | 脚本 | 笔记章节 |
| --- | --- | --- | --- |
| 1 | 暴力破解 | [1-brute.py](solutions/1-brute.py) | [暴力撞库](docs/owasp-top10-walkthrough.md#暴力撞库) |
| 2 | 命令注入 | [2-cmd_injection.py](solutions/2-cmd_injection.py) | [Command Injection](docs/owasp-top10-walkthrough.md#command-injection) |
| 3 | CSRF | [3-csrf.py](solutions/3-csrf.py) | [CSRF 跨站请求](docs/owasp-top10-walkthrough.md#csrf-跨站请求) |
| 4 | 文件上传 | [4-file_upload.py](solutions/4-file_upload.py) | [File Upload 注入](docs/owasp-top10-walkthrough.md#file-upload-注入) |
| 5 | SQL 注入 | [5-sql_injection.py](solutions/5-sql_injection.py) | [SQL 注入](docs/owasp-top10-walkthrough.md#sql-注入) |
| 6 | SQL 盲注 | [6-sql_blind.py](solutions/6-sql_blind.py) | [SQL 盲注](docs/owasp-top10-walkthrough.md#sql-盲注) |
| 7 | 弱会话 ID | [7-weak_session.py](solutions/7-weak_session.py) | [弱 Sessions ID 预测](docs/owasp-top10-walkthrough.md#弱-sessions-id-预测) |
| 8 | DOM 型 XSS | [8-xss_dom.py](solutions/8-xss_dom.py) | [XSS (DOM) DOM 型](docs/owasp-top10-walkthrough.md#xss-dom-dom-型) |
| 9 | 反射型 XSS | [9-xss_reflected.py](solutions/9-xss_reflected.py) | [XSS (Reflected) 反射型](docs/owasp-top10-walkthrough.md#xss-reflected-反射型) |
| 10 | 存储型 XSS | [10-xss_stored.py](solutions/10-xss_stored.py) | [XSS (Stored) 存储型](docs/owasp-top10-walkthrough.md#xss-stored-存储型) |
| 11 | CSP 绕过 | [11-csp.py](solutions/11-csp.py) | [CSP Bypass](docs/owasp-top10-walkthrough.md#content-security-policy-csp-bypass) |
| 12 | JavaScript 关卡 | [12-javascript.py](solutions/12-javascript.py) | [JavaScript 关卡](docs/owasp-top10-walkthrough.md#javascript-关卡) |

## 几点注意

- 有副作用的关卡别在别人正在用的靶机上跑:

  - `3-csrf.py` 会改掉当前登录用户的密码, 默认改成和原密码一样.
  - `4-file_upload.py` 会往 `hackable/uploads/` 里写文件, 记得清掉.
  - `10-xss_stored.py` 会往留言板写一条记录.

- 有些关卡脚本只能验证到 `注入成功` 这一步, 弹窗和 token 的实际效果要用浏览器确认, 笔记里都标了.
- `solutions/payloads/high.js` 是 High 关卡的混淆脚本, `unpack-high.js` 是解混淆后的版本, 留着方便复现.
