"""
Builds app/ml/training/data/brand_impersonation.csv. Run from backend/:

    python -m app.ml.training.prepare_brand_dataset

Sources
  phishing  : REAL rows from phishing_sms.tsv labeled "phishing" that name a
              known brand (whole-word match).
  legitimate: (a) REAL rows from phishing_sms.tsv labeled "legitimate" that
              name a brand AND survive a scam-signal filter. The source
              dataset's "legitimate" label is unreliable for this purpose —
              it contains job scams, fake Find-My links and bulk-spam labeled
              as legitimate — so raw rows are NOT used as-is.
              (b) SYNTHETIC ordinary chat + genuine-looking notifications
              from varied templates, capped at a minority share so the
              model can't learn "synthetic style = legitimate".

Every negative mentions a brand, on purpose: if negatives didn't, the model
would learn "mentions a brand = phishing".
"""
import os
import random
import re

import pandas as pd

from app.detectors.brand_text import find_brands

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
SRC = os.path.join(DATA, "phishing_sms.tsv")
OUT = os.path.join(DATA, "brand_impersonation.csv")

SCAM_SIGNALS = re.compile(
    r"http|www\.|\.com|\.in\b|whatsapp\s*(no|number|me|us)?\s*\d|earn|job|recruit|part[- ]?time|offer|coupon|"
    r"promo|discount|% ?off|order id|helpline|\brs\b|₹|bonus|\bwin\b|prize|winner|click|link|subscribe|bulk|"
    r"database|check location|lost device|lose device|rate or like|task|commission|xx+|\d{10}|@",
    re.I,
)

DISPLAY_BRANDS = ["Amazon", "Netflix", "PayPal", "Microsoft", "Apple", "Instagram", "WhatsApp", "DHL", "FedEx",
                  "Spotify", "LinkedIn", "Adobe", "Zoom", "eBay", "Dropbox", "Google", "Facebook", "Telegram",
                  "Snapchat", "Twitter", "Coinbase", "Docusign"]
NAMES = ["Rohan", "Priya", "Amit", "Sneha", "Arjun", "Kavya", "Vikram", "Ananya", "Rahul", "Meera", "Karan", "Divya"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday", "tomorrow", "tonight"]
ITEMS = ["laptop", "headphones", "phone case", "keyboard", "backpack", "book", "monitor", "charger", "shoes"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October"]


def slot(rng: random.Random) -> dict:
    return dict(
        brand=rng.choice(DISPLAY_BRANDS), name=rng.choice(NAMES), day=rng.choice(DAYS), item=rng.choice(ITEMS),
        month=rng.choice(MONTHS), n=rng.randint(100, 99999), code=rng.randint(100000, 999999),
        amt=f"{rng.randint(1, 499)}.{rng.randint(10, 99)}", date=f"{rng.randint(1, 28)}/{rng.randint(1, 12):02d}",
        time=f"{rng.randint(1, 11)}:{rng.choice(['00', '15', '30', '45'])}", time2=f"{rng.randint(1, 11)}:{rng.choice(['00', '30'])}",
    )


CHAT = [
    "watching {brand} tonight want to join",
    "did u see the new {brand} update it looks weird",
    "i logged into {brand} from my laptop just now and it works fine",
    "can you share the {brand} doc with {name} before the {day} meeting",
    "my {brand} keeps crashing on my phone any idea why",
    "just bought a new {item} on {brand} it arrives {day}",
    "{name} said the {brand} thing is free this month",
    "we should use {brand} for the group call tomorrow at {time}",
    "i cancelled my {brand} subscription yesterday, too expensive",
    "uploaded the photos to {brand}, check them when you get time",
    "the {brand} app is so slow today lol",
    "remember to renew the {brand} plan before {day}",
    "sent you the invite through {brand}, let me know if it doesn't show up",
    "honestly {brand} has gotten so much better lately",
    "I'm on {brand} if you want to message me there",
    "do you have a {brand} account? I can add you to the family plan",
    "my brother works at {brand}, he says the office is huge",
    "The {brand} customer support was actually really helpful today",
    "left my {brand} charger at your place, can I pick it up {day}?",
    "learning how to use {brand} for work, any tips?",
    "ok thx will check {brand} when i get home, ref {n}",
    "bro the {brand} thing finally worked, took like {n} tries lol",
    "just {brand}'d you the money for the {item}, let me know when it lands",
    "send it over {brand} when you can, no rush",
    "sent {amt} to {name} through {brand} for the {item}",
    "the {brand} link for the meeting is in the calendar invite for {day}",
    "we're on {brand} for the standup at {time}, just join from the invite",
    "{name} accepted my request on {brand} finally",
    "got the {brand} delivery at the door, thanks for waiting",
    "ordered from {brand} again, should reach by {day}",
]
NOTIFY = [
    "Your {brand} order #{n} has shipped and will arrive by {day}.",
    "{brand}: your verification code is {code}. Do not share it with anyone.",
    "Thanks for your {brand} purchase of ${amt}. A receipt has been sent to your email.",
    "Hi {name}, your {brand} subscription will renew on {date}. You can manage it in your account settings.",
    "We noticed a sign-in to your {brand} account from a new device. If this was you, no action is needed.",
    "Your {brand} password was successfully changed. If you didn't do this, contact support through the official app.",
    "{brand}: your delivery is scheduled for {day} between {time} and {time2}.",
    "Your {brand} refund of ${amt} has been processed and should appear within 5-7 business days.",
    "Reminder: your {brand} trial ends on {date}. You will not be charged unless you choose a plan.",
    "Your {brand} meeting with {name} starts in 15 minutes.",
    "{brand} team: thank you for contacting support. Your ticket #{n} has been resolved.",
    "Your {brand} invoice for {month} is now available in your billing dashboard.",
    "Welcome to {brand}, {name}! Your account has been created successfully.",
    "Your {brand} storage is 80% full. You can free up space or upgrade your plan in settings.",
    "{brand}: {name} shared a file with you.",
    "Your {brand} payment of Rs {n} was processed successfully. Thank you.",
    "Your {brand} package was delivered to your address at {time}.",
    "{brand}: {name} accepted your connection request.",
    "Your {brand} order #{n} is out for delivery today.",
    "You have a new message from {name} on {brand}.",
    "{brand}: your ticket #{n} was updated by our support team.",
    "Payment received: ${amt} from {name} via {brand}.",
    "Your {brand} account settings were updated on {date}.",
]


def fill(templates, target, tag, seen, rng):
    rows, attempts = [], 0
    while len(rows) < target and attempts < target * 30:
        attempts += 1
        text = rng.choice(templates).format(**slot(rng))
        if rng.random() < 0.2:
            text = text.lower()
        if text not in seen:
            seen.add(text)
            rows.append((text, "legitimate", tag))
    return rows


def main() -> None:
    rng = random.Random(11)
    df = pd.read_csv(SRC, sep="\t", header=None, names=["label", "text"]).dropna()
    df["text"] = df["text"].astype(str)
    named = df[df.text.map(lambda t: bool(find_brands(t)))].drop_duplicates("text")

    phish = named[named.label == "phishing"]
    phish_rows = [(t, "phishing", "phishing_sms.tsv (real)") for t in phish.text]

    real_leg = named[(named.label == "legitimate")]
    real_leg = real_leg[~real_leg.text.str.contains(SCAM_SIGNALS) & real_leg.text.str.len().between(15, 220)]
    real_leg_rows = [(t, "legitimate", "phishing_sms.tsv (real, filtered)") for t in real_leg.text]

    seen: set[str] = set()
    synth = fill(CHAT, 800, "synthetic-chat", seen, rng) + fill(NOTIFY, 800, "synthetic-notification", seen, rng)

    out = pd.DataFrame(phish_rows + real_leg_rows + synth, columns=["text", "label", "source"])
    out = out.sample(frac=1, random_state=42).reset_index(drop=True)
    out.to_csv(OUT, index=False)
    print(f"phishing (real):                 {len(phish_rows):,}")
    print(f"legitimate (real, filtered):     {len(real_leg_rows):,}")
    print(f"legitimate (synthetic):          {len(synth):,}")
    print(f"saved {len(out):,} rows -> {OUT}")


if __name__ == "__main__":
    main()