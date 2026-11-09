#!/usr/bin/env python3
"""Test F: 8 vitimas simultaneas + swap com containers do Firefox."""
import json, socket, sys, time, threading, urllib.request

HOST, PORT = "127.0.0.1", 9411
RUN = "SIM%d" % (int(time.time()) % 100000)
N = 8


def post_raw(victim, rows):
    body = json.dumps(rows, ensure_ascii=False).encode()
    head = ("POST / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\n"
            "Content-Length: %d\r\nConnection: close\r\nX-CookieLog-Host: %s\r\n\r\n"
            % (PORT, len(body), victim)).encode()
    s = socket.create_connection((HOST, PORT), timeout=15)
    s.sendall(head + body)
    s.shutdown(socket.SHUT_WR)
    r = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        r += c
    s.close()
    return r.split(b"\r\n", 1)[0]


def get(path):
    with urllib.request.urlopen("http://%s:%d%s" % (HOST, PORT, path), timeout=10) as r:
        return json.loads(r.read())


def main():
    fails = []
    results = {}
    big = [{"domain": ".sim.test", "name": "c%d" % i, "value": "v%d" % i, "path": "/"} for i in range(200)]

    def worker(i):
        st = post_raw("%s-%d" % (RUN, i), big)
        results[i] = st.decode()

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    t0 = time.time()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    dt = time.time() - t0
    print("[simultaneo] %d POSTs de %d registros em %.2fs" % (N, len(big), dt))

    ok = sum(1 for v in results.values() if "200" in v)
    fails.append("POSTs simultaneos") if ok != N else None
    print(("  PASS  " if ok == N else "  FAIL  ") + "todos os %d POSTs -> 200" % N)

    rows = get("/all")
    for i in range(N):
        got = [c for c in rows if c.get("_host") == "%s-%d" % (RUN, i)]
        if len(got) != 200:
            fails.append("vitima %d perdeu registros" % i)
            print("  FAIL  vitima %d: %d/200" % (i, len(got)))
    if len(fails) == 0:
        print("  PASS  cada vitima com 200 registros intactos")

    # swap com cookies de container do Firefox: duas linhas mesmo nome/path
    src = json.load(open(r"C:\Users\Dun\Documents\Codigos\tools\cookielog\cookies_all.json", encoding="utf-8"))
    dup = {}
    for c in src:
        k = (c.get("domain"), c.get("name"), c.get("path"))
        dup.setdefault(k, set()).add(c.get("value"))
    multi = [k for k, v in dup.items() if len(v) > 1]
    print("[swap] %d cookies com mesmo dominio/nome/path e valores distintos" % len(multi))

    print("\n=== %d falhas ===" % len(fails))
    for f in fails:
        print("  - " + f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
