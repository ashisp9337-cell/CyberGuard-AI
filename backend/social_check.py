"""
CyberGuard - live check of the Social-media page on YOUR PC (with internet), added 21 Oct.

The workspace where this was built has no internet, so posts that contain LINKS could only be checked there with
the link checks switched off. This runs 20 normal posts and 5 scam messages through the same check as the
Social Media page, WITH the live link checks. The normal posts link only to real sites (Medium, Infosys, Google
Forms); the scam links are made-up names that are not registered, so no phishing site is contacted.
Nothing is saved to the database and no alert is sent.

Run from backend/ with the venv active:
    python social_check.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
OUT = []

REAL = [
    "Congrats to our team for winning the BPUT hackathon prelims! Proud of everyone 🎉 #hackathon #odisha",
    "Hey! Are you coming to the college fest tomorrow? We're meeting at the canteen at 5",
    "New video is up on my channel! Link in bio. Thanks for 10k subscribers ❤️",
    "Happy birthday bro! Have an amazing year ahead 🎂",
    "Check out my new blog post about learning Python: https://medium.com/@ashis/learning-python-3a2b",
    "We are hiring interns for summer 2027. Apply through our careers page https://careers.infosys.com",
    "Flipkart Big Billion Days starts tomorrow! Get up to 80% off on electronics. Shop now on the Flipkart app",
    "Thank you all for the wishes! Feeling blessed 🙏",
    "Giveaway time! Follow us and tag 3 friends to win a free T-shirt. Winners announced Sunday.",
    "Your order has been shipped and will arrive by Friday. Track it in the app.",
    "Reminder: Mid-sem exams start Monday. All the best everyone!",
    "Can you send me the notes from today's DBMS class?",
    "Join our free webinar on cybersecurity careers this Saturday 6 PM. Register: https://forms.gle/abc123",
    "I just got my first salary credited! Treat at my place this weekend 😄",
    "Limited seats left for the workshop on ethical hacking. DM to register.",
    "Please vote for our project in the innovation contest, link in comments 🙏",
    "OMG I won the photography contest!! Thank you everyone who voted 😭❤️",
    "Lost my wallet near the library, if anyone finds it please DM me",
    "Selling my old laptop, i5 8th gen, 8GB RAM, 25k negotiable. DM if interested",
    "Your account security matters. Enable two-factor authentication in Settings > Security.",
]
SCAM = [
    "Congratulations! You have been selected for the Instagram Blue Tick. Verify your account here: "
    "http://insta-verify-badge.top/login",
    "Hi dear, I am a crypto trader, invest 5000 and get 50000 in 7 days guaranteed. DM me on WhatsApp +44 7700 900123",
    "Your Facebook page will be deleted in 24 hours due to copyright violation. Appeal now: "
    "https://meta-appeal-center.vercel.app",
    "Earn 3000/day working from home, just like YouTube videos. Contact HR on Telegram @easyjob_hr",
    "I'm stuck abroad and lost my wallet, please send 10,000 via UPI to help me, will return tomorrow",
]


def say(s=""):
    print(s, flush=True)
    OUT.append(s)


def main():
    from app.detectors.phishing import analyze_text
    say("=" * 100)
    say(f"CyberGuard social-media live check  -  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    say("=" * 100)
    flagged, caught = [], 0
    for label, posts in (("real", REAL), ("scam", SCAM)):
        for text in posts:
            t = time.time()
            try:
                score = analyze_text(text, subtopic_title="Social Media Message Analysis",
                                     subtopic_id="social-media-analysis")["riskScore"]
            except Exception as e:                  # a crash is reported, never hidden
                score = None
                say(f"  ERROR {type(e).__name__}: {str(e)[:100]}")
            bad = score is not None and score >= 51
            if label == "real" and bad:
                flagged.append(text)
            caught += label == "scam" and bad
            mark = ("FALSE ALARM" if bad else "ok") if label == "real" else ("caught" if bad else "MISSED")
            say(f"  {label:4s} {score!s:>4s}  {mark:11s} {time.time() - t:4.1f} s  {text[:70]}")
    say(f"\nRESULT: normal posts flagged {len(flagged)}/{len(REAL)}, scams caught {caught}/{len(SCAM)}")


if __name__ == "__main__":
    try:
        main()
    finally:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "social_check.txt"), "w",
                  encoding="utf-8") as f:
            f.write("\n".join(OUT) + "\n")
        print("\nSaved to backend\\social_check.txt  -  send me that file or a screenshot.")
