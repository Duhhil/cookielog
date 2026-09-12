#!/usr/bin/env python3
"""tg_chatid.py -- finds your Telegram chat ID by querying the bot's getUpdates API.

  EDUCATIONAL USE ONLY -- FOR SECURITY RESEARCH AND TRAINING

Usage:
    python tg_chatid.py <bot_token>

Example:
    python tg_chatid.py 8975447629:AAFzK9wam_2jfoZzoyRNegU6Dfnd5M9PS2M

Prerequisites:
    1. You already created a bot via @BotFather and have the API token
    2. You sent at least one message to the bot (open the bot in Telegram, type "hi")

Output:
    Prints your chat ID and the full --telegram string to paste into auto.py.
    Also saves it to config.json automatically.
"""
import json, os, sys, urllib.request

HERE   = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(HERE, "config.json")

def main():
    if len(sys.argv) < 2:
        print("Usage: python tg_chatid.py <bot_token>")
        print("Example: python tg_chatid.py 8975447629:AAFzK9wam_2jfoZzoyRNegU6Dfnd5M9PS2M")
        sys.exit(1)

    bot_token = sys.argv[1].strip()

    # Validate token format (should contain a colon)
    if ":" not in bot_token:
        print("[-] Invalid token format. Expected: 123456789:AAHxxx...")
        sys.exit(1)

    print("[*] Querying Telegram API for chat ID...")
    url = "https://api.telegram.org/bot%s/getUpdates" % bot_token
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode("utf-8"))
    except Exception as ex:
        print("[-] API request failed: %s" % ex)
        sys.exit(1)

    if not data.get("ok"):
        print("[-] Telegram API returned error: %s" % data)
        sys.exit(1)

    results = data.get("result", [])
    if not results:
        print("[-] No messages found.")
        print("    Open Telegram, find your bot, and send it a message (e.g. 'hi')")
        print("    Then run this script again.")
        sys.exit(1)

    # Get chat ID from the latest message
    last = results[-1]
    if "message" in last:
        chat_id = last["message"]["chat"]["id"]
        chat_name = last["message"]["chat"].get("first_name", "")
        if "username" in last["message"]["chat"]:
            chat_name += " @" + last["message"]["chat"]["username"]
    elif "callback_query" in last:
        chat_id = last["callback_query"]["message"]["chat"]["id"]
        chat_name = last["callback_query"]["message"]["chat"].get("first_name", "")
    else:
        print("[-] Could not find chat ID in the latest update.")
        print("    Raw data: %s" % json.dumps(last, indent=2))
        sys.exit(1)

    full_telegram = "%s:%s" % (bot_token, chat_id)

    print()
    print("=" * 55)
    print("  Telegram Chat ID Found!")
    print("=" * 55)
    print("  Chat ID:   %s" % chat_id)
    print("  Name:      %s" % chat_name if chat_name else "  Name:      (unknown)")
    print("  Bot token: %s...%s" % (bot_token[:8], bot_token[-4:]))
    print()
    print("  Full --telegram string:")
    print("  %s" % full_telegram)
    print()
    print("  Use with auto.py:")
    print("  python auto.py game.exe --telegram %s" % full_telegram)
    print("=" * 55)

    # Save to config.json
    cfg = {}
    if os.path.exists(CONFIG):
        try:
            with open(CONFIG, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            pass
    cfg["telegram"] = full_telegram
    try:
        with open(CONFIG, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        print("\n[+] Saved to config.json -- next time just run: python auto.py game.exe")
    except Exception as ex:
        print("\n[-] Could not save config: %s" % ex)

if __name__ == "__main__":
    main()
