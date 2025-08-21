from __future__ import annotations
import random, urllib.parse, base64

SPECIAL_CHARS=['"',"'",";","|","&"]

def random_case(s: str) -> str:
    return ''.join(c.upper() if random.random()>0.5 else c.lower() for c in s)

def percent_encode_random(s: str) -> str:
    out=[]
    for ch in s:
        if ch.isalnum() or random.random()>0.5:
            out.append(ch)
        else:
            out.append("%{:02x}".format(ord(ch)))
    return ''.join(out)

def insert_special(s: str) -> str:
    ch=random.choice(SPECIAL_CHARS)
    pos=random.randint(0, len(s))
    return s[:pos]+ch+s[pos:]

def encode_alt(s: str) -> list[str]:
    q=urllib.parse.quote(s, safe='')
    return [q, urllib.parse.quote(q, safe=''), base64.b64encode(s.encode()).decode()]

def generate_variants(probe: str) -> list[str]:
    variants={probe, random_case(probe), percent_encode_random(probe), insert_special(probe)}
    variants.update(encode_alt(probe))
    return list(variants)

def alternate_encodings(probe: str) -> list[str]:
    return encode_alt(probe)
