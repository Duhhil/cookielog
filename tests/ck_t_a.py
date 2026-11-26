#!/usr/bin/env python3
"""Test A: ingest faithful to the ckdll.cpp wire format.
Raw socket: Host with port, X-CookieLog-Host, Connection: close.
"""
import json, socket, sys, time, urllib.request

RUN = 'V%d' % (int(time.time()) % 100000)

HOST, PORT = "127.0.0.1", 9411
PATH = "/"


def post_raw(victim, body_obj, port=PORT, claim_len=None):
    body = json.dumps(body_obj, ensure_ascii=False).encode()
    n = len(body) if claim_len is None else claim_len
    head = (
        "POST %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
        "User-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
        "Content-Type: application/json\r\nContent-Length: %d\r\n"
        "Connection: close\r\nX-CookieLog-Host: %s\r\n\r\n" % (PATH, port, n, victim)
    ).encode()
    s = socket.create_connection((HOST, port), timeout=10)
    s.sendall(head + body)
    s.shutdown(socket.SHUT_WR)
    resp = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        resp += chunk
    s.close()
    status = resp.split(b"\r\n", 1)[0].decode(errors="replace")
    return status, resp


def health():
    with urllib.request.urlopen("http://%s:%d/health" % (HOST, PORT), timeout=5) as r:
        return json.loads(r.read())


def get_json(path):
    with urllib.request.urlopen("http://%s:%d%s" % (HOST, PORT, path), timeout=5) as r:
        return json.loads(r.read())


def main():
    base = health()["records"]
    print("[baseline] %d records" % base)
    fails = []

    def check(name, cond, detail=""):
        print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  <- " + detail))
        if not cond:
            fails.append(name)

    # --- 1. Normal dump: Chrome + Edge with the same name, password, token, Firefox, invalid expiry
    dump1 = [
        {"domain": ".example.com", "name": "sid", "value": "chrome-a", "path": "/",
         "secure": True, "httpOnly": True, "sameSite": "lax", "expirationDate": 1900000000,
         "browser": "Chrome", "profile": "Default", "session": False, "storeId": "0"},
        {"domain": ".example.com", "name": "sid", "value": "edge-a", "path": "/",
         "secure": True, "httpOnly": False, "sameSite": "no_restriction", "expirationDate": 1900000001,
         "browser": "Edge", "profile": "Default", "session": False, "storeId": "0"},
        {"domain": ".example.com", "name": "sid", "value": "ff-a", "path": "/",
         "secure": False, "httpOnly": True, "sameSite": "unspecified", "expirationDate": 0,
         "browser": "Firefox", "profile": "abc.default-release", "session": True, "storeId": None},
        {"domain": "https://site.test", "name": "password", "value": "hunter2",
         "path": "/", "_username": "kai", "browser": "Chrome", "profile": "Default",
         "expirationDate": 0},
        {"domain": ".discord.com", "name": "token", "value": "TOK_A", "path": "/",
         "secure": True, "expirationDate": 0, "browser": "Chrome", "profile": "Default"},
        {"domain": ".discord.com", "name": "token", "value": "TOK_B", "path": "/",
         "secure": True, "expirationDate": 0, "browser": "Chrome", "profile": "Default"},
        {"domain": ".bad-exp.com", "name": "x", "value": "1", "path": "/",
         "expirationDate": "not-a-number", "browser": "Chrome", "profile": "Default"},
    ]
    st, _ = post_raw(RUN + "-A", dump1)
    check("POST normal -> 200", "200" in st, st)

    rows = get_json("/all")
    mine = [c for c in rows if c.get("_host") == RUN + "-A"]
    check("6 cookies stored (password goes to a separate file)", len(mine) == 6, "got %d" % len(mine))
    sids = sorted(c["value"] for c in mine if c["name"] == "sid")
    check("same name across 3 browsers preserved", sids == ["chrome-a", "edge-a", "ff-a"], str(sids))
    toks = sorted(c["value"] for c in mine if c["name"] == "token")
    check("two tokens from the same profile preserved", toks == ["TOK_A", "TOK_B"], str(toks))
    check("password fora de /all", not any(c["name"] == "password" for c in rows))
    pw = get_json("/passwords")
    _hit = [c for c in pw if c.get("_username") == "kai" and c.get("value") == "hunter2"]
    check("password in /passwords with _username", bool(_hit), "pw=%r" % (pw[:2],))
    sess = get_json("/session")
    check("session separated (FF + tokens + corrupted expiry)", len([c for c in sess if c.get("_host") == RUN + "-A"]) == 4,
          str(len([c for c in sess if c.get("_host") == RUN + "-A"])))

    # --- 2. Same host updates a value and adds another
    dump2 = [
        {"domain": ".example.com", "name": "sid", "value": "chrome-a2", "path": "/",
         "secure": True, "expirationDate": 1900000000, "browser": "Chrome", "profile": "Default"},
        {"domain": ".example.com", "name": "new", "value": "n1", "path": "/",
         "expirationDate": 1900000002, "browser": "Chrome", "profile": "Default"},
    ]
    st, _ = post_raw(RUN + "-A", dump2)
    check("POST update -> 200", "200" in st, st)
    mine = [c for c in get_json("/all") if c.get("_host") == RUN + "-A"]
    sids = sorted(c["value"] for c in mine if c["name"] == "sid")
    check("update replaces, does not duplicate", sids == ["chrome-a2", "edge-a", "ff-a"], str(sids))
    check("new record inserted", any(c["name"] == "new" for c in mine))

    # --- 3. Second victim with the same domain/name does not collide
    st, _ = post_raw(RUN + "-B", [{"domain": ".example.com", "name": "sid", "value": RUN + "-B",
                                   "path": "/", "browser": "Chrome", "profile": "Default"}])
    check("POST 2nd victim -> 200", "200" in st, st)
    allrows = get_json("/all")
    vb = [c["value"] for c in allrows if c.get("_host") == RUN + "-B" and c["name"] == "sid"]
    check("attribution by X-CookieLog-Host", vb == [RUN + "-B"], str(vb))

    # --- 4. Missing host header falls back to the peer
    body = json.dumps([{"domain": ".nohost.test", "name": "a", "value": "1", "path": "/"}]).encode()
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(b"POST / HTTP/1.1\r\nHost: 127.0.0.1:9411\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
    s.shutdown(socket.SHUT_WR)
    s.recv(65536); s.close()
    check("missing X-CookieLog-Host falls back to peer",
          any(c.get("_host") == "127.0.0.1" for c in get_json("/all")))

    # --- 5. Invalid JSON returns 400 and writes nothing
    before = health()["records"]
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 9\r\nConnection: close\r\n\r\n{not json")
    s.shutdown(socket.SHUT_WR)
    r = s.recv(65536); s.close()
    check("invalid JSON -> 400", b" 400 " in r.split(b"\r\n")[0], r[:40].decode(errors="replace"))
    check("invalid JSON leaves the collection unchanged", health()["records"] == before)

    # --- 6. Content-Length above the limit returns 413
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 40000000\r\nConnection: close\r\n\r\n")
    r = s.recv(65536); s.close()
    check("body 40MB -> 413", b" 413 " in r.split(b"\r\n")[0], r[:40].decode(errors="replace"))

    # --- 7. A standalone object (not a list) becomes a list
    st, _ = post_raw(RUN + "-C", {"domain": ".solo.test", "name": "solo", "value": "1", "path": "/"})
    check("standalone object accepted", "200" in st and
          any(c["name"] == "solo" for c in get_json("/all")), st)

    # --- 8. Records without a name and non-dict entries are discarded
    st, _ = post_raw(RUN + "-C", [{"domain": ".x.test", "value": "sem-nome"}, "lixo",
                                  {"domain": ".x.test", "name": "ok", "value": "1", "path": "/"}])
    check("invalid record discarded", "200" in st and
          sum(1 for c in get_json("/all") if c.get("_host") == RUN + "-C" and c["name"] == "ok") == 1, st)

    # --- 9. Resending identical data does not duplicate it
    before = health()["records"]
    st, _ = post_raw(RUN + "-A", dump1)
    after = health()["records"]
    check("identical resend does not grow the collection", "200" in st and after == before,
          "%d -> %d" % (before, after))

    # --- 10. UTF-8 preserved end to end
    uni = "são-paulo-\u2713-\u65e5\u672c\u8a9e-\U0001f36a"
    st, _ = post_raw(RUN + "-U", [{"domain": ".uni.test", "name": "u", "path": "/", "value": uni}])
    got_u = [c.get("value") for c in get_json("/all") if c.get("_host") == RUN + "-U"]
    check("UTF-8 preserved", "200" in st and got_u == [uni], repr(got_u))

    print("\n"=== %d failures ==="" % len(fails))
    for f in fails:
        print("  - " + f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

