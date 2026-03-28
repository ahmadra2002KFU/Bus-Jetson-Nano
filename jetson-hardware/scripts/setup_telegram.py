#!/usr/bin/env python3
"""Interactive Telegram bot setup wizard.

Guides the user through creating a Telegram bot and configuring alerts.
Updates config.ini with the bot token and chat ID.
"""

import sys
import configparser
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config.ini')


def main():
    print("=" * 60)
    print("  Telegram Bot Setup for Al-Ahsa Smart Bus System")
    print("=" * 60)
    print()
    print("Step 1: Create a bot")
    print("  1. Open Telegram and search for @BotFather")
    print("  2. Send /newbot")
    print("  3. Name: AlAhsa Bus Security Bot")
    print("  4. Username: alahsa_bus_security_bot")
    print("     (must end in 'bot', must be unique)")
    print()

    token = input("Paste your bot token here: ").strip()
    if not token or ':' not in token:
        print("Invalid token format. Expected: 1234567890:AAH...")
        sys.exit(1)

    # Validate token
    try:
        import requests
        resp = requests.get(
            f"https://api.telegram.org/bot{token}/getMe", timeout=10
        )
        if resp.status_code != 200:
            print(f"Token validation failed: {resp.text}")
            sys.exit(1)
        bot_info = resp.json()['result']
        print(f"\nBot verified: @{bot_info['username']}")
    except ImportError:
        print("Warning: 'requests' not installed, skipping validation")
    except Exception as e:
        print(f"Warning: Could not validate token: {e}")

    print()
    print("Step 2: Create a group and add the bot")
    print("  1. Create a new Telegram group")
    print("  2. Add your bot to the group")
    print("  3. Send any message in the group")
    print()
    input("Press Enter when done...")

    # Get chat ID
    try:
        import requests
        resp = requests.get(
            f"https://api.telegram.org/bot{token}/getUpdates", timeout=10
        )
        updates = resp.json().get('result', [])
        chat_id = None
        for update in reversed(updates):
            msg = update.get('message', {})
            chat = msg.get('chat', {})
            if chat.get('type') in ('group', 'supergroup'):
                chat_id = str(chat['id'])
                print(f"Found group: {chat.get('title', 'Unknown')}")
                print(f"Chat ID: {chat_id}")
                break

        if not chat_id:
            print("Could not find group automatically.")
            chat_id = input("Enter chat_id manually: ").strip()
    except ImportError:
        chat_id = input("Enter chat_id manually: ").strip()

    if not chat_id:
        print("No chat_id provided. Exiting.")
        sys.exit(1)

    # Send test message
    print("\nSending test message...")
    try:
        import requests
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id,
                  "text": "Al-Ahsa Smart Bus Security System - Bot connected!"},
            timeout=10,
        )
        if resp.status_code == 200:
            print("Test message sent! Check your Telegram group.")
        else:
            print(f"Warning: {resp.text}")
    except Exception as e:
        print(f"Warning: {e}")

    # Update config.ini
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    if 'telegram' not in config:
        config['telegram'] = {}
    config['telegram']['bot_token'] = token
    config['telegram']['chat_id'] = chat_id
    config['telegram']['enabled'] = 'true'

    with open(CONFIG_PATH, 'w') as f:
        config.write(f)

    print(f"\nConfig updated: {os.path.abspath(CONFIG_PATH)}")
    print("Telegram alerts are now enabled!")


if __name__ == '__main__':
    main()
