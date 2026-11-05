import codecs
import hashlib

from dvwa import DVWA

SECURITY = "high"
PHRASE = "success"
"""
Low: token = md5(rot13(phrase))
Medium: token = XX + reverse(phrase) + XX
High: token = sha256(sha256(XX + reverse(phrase)) + ZZ)
"""

target = DVWA("javascript", SECURITY)


def make_token(phrase):
    if SECURITY == "low":
        rotated = codecs.encode(phrase, "rot13")
        return hashlib.md5(rotated.encode()).hexdigest()
    if SECURITY == "medium":
        return "XX" + phrase[::-1] + "XX"
    step = hashlib.sha256(("XX" + phrase[::-1]).encode())
    return hashlib.sha256(
        (step.hexdigest() + "ZZ").encode()
    ).hexdigest()


token = make_token(PHRASE)
response = target.post(
    "",
    data={
        "phrase": PHRASE,
        "token": token,
        "send": "Submit",
    },
)

print(f"Phrase: {PHRASE}")
print(f"Token: {token}")
print(f"Passed: {'Well done' in response.text}")
