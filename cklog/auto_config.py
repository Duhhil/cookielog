"""auto/config.py — configuration persistence and Telegram preflight.

Extracted from auto.py to keep the orchestrator thin. All public names are
re-exported by auto.py so existing imports and tests keep working.
"""
import json
import os
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(HERE, "config.json")


def load_config():
    """Load config.json. Returns dict with telegram, discord, port, persist."""
    if os.path.exists(CONFIG):
        try:
            with open(CONFIG, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_config(cfg):
    """Save config dict to config.json."""
    try:
        with open(CONFIG, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as ex:
        print("[-] failed to save config: %s" % ex)


def telegram_probe(token):
    """getMe preflight. Returns (state, info) with state ok / dead / unknown."""
    if not token:
        return "dead", "empty"
    if ":" not in token:
        return "dead", "expected bot_token:chat_id (got no ':'); run: python auto.py --tg-chatid <token>"
    bot = token.rsplit(":", 1)[0]
    try:
        with urllib.request.urlopen("https://api.telegram.org/bot%s/getMe" % bot, timeout=8) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        if data.get("ok"):
            return "ok", (data.get("result") or {}).get("username") or "bot"
        return "dead", data.get("description") or "reply not ok"
    except urllib.error.HTTPError as ex:
        try:
            body = json.loads(ex.read().decode("utf-8", "replace"))
            return "dead", "%s (%s)" % (body.get("description", "HTTP %d" % ex.code), ex.code)
        except Exception:
            return "dead", "HTTP %d" % ex.code
    except Exception as ex:
        return "unknown", "%s: %s" % (ex.__class__.__name__, ex)


def gate_telegram(token):
    """Verify a Telegram key before it is passed to the listener. None = no relay."""
    if not token:
        return None
    state, info = telegram_probe(token)
    if state == "ok":
        print("[+] Telegram relay: enabled (@%s)" % info)
        return token
    if state == "dead":
        print("[!] Telegram relay: disabled -- the saved key is not a live bot token")
        print("[!]   %s" % info)
        print("[!]   fix it: python auto.py --telegram bot_token:chat_id")
        return None
    print("[!] Telegram relay: enabled (could not verify now: %s)" % info)
    return token


def show_config():
    """Print current saved config."""
    cfg = load_config()
    print("=" * 50)
    print("  Saved configuration (config.json)")
    print("=" * 50)
    if not cfg:
        print("  (empty -- no saved settings)")
    else:
        tg = cfg.get("telegram", "")
        if tg:
            parts = tg.rsplit(":", 1)
            if len(parts) == 2:
                bot, chat = parts
                masked = bot[:8] + "..." + bot[-4:] if len(bot) > 12 else bot
                print("  Telegram:  %s : %s" % (masked, chat))
            else:
                print("  Telegram:  %s" % tg)
        else:
            print("  Telegram:  (not set)")
        dc = cfg.get("discord", "")
        if dc:
            masked = dc[:50] + "..." if len(dc) > 50 else dc
            print("  Discord:   %s" % masked)
        else:
            print("  Discord:   (not set)")
        print("  Port:      %s" % cfg.get("port", 9090))
        print("  Persist:   %s" % ("enabled" if cfg.get("persist") else "disabled"))
    print("=" * 50)


def tg_lookup_chatid(bot_token):
    """Query Telegram getUpdates API to find the chat_id of the latest message sender."""
    try:
        url = "https://api.telegram.org/bot%s/getUpdates" % bot_token
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode("utf-8"))
        if data.get("ok") and data.get("result"):
            last = data["result"][-1]
            chat_id = last["message"]["chat"]["id"]
            return str(chat_id)
        return None
    except Exception:
        return None
