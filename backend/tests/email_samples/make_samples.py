"""
Generates the sample .eml files used by tests/test_email_pipeline.py.

    cd backend
    pip install qrcode[pil] reportlab        # only needed to regenerate
    python tests/email_samples/make_samples.py

The generated .eml files are committed, so the tests themselves do not need
qrcode/reportlab. Domains marked as attacker-controlled are fictional.
"""
import io
import os
import zipfile
from email.message import EmailMessage
from email.utils import make_msgid

HERE = os.path.dirname(os.path.abspath(__file__))


def auth(spf, dkim, dmarc, domain, dkim_d=None):
    return (f"mx.google.com; spf={spf} smtp.mailfrom={domain}; "
            f"dkim={dkim} header.d={dkim_d or domain}; dmarc={dmarc} header.from={domain}")


def base(frm, to, subject, auth_results, received_ip="185.220.101.4", reply_to=None, in_reply_to=None, mailer=None):
    m = EmailMessage()
    m["Received"] = "from mx.google.com by mx.example.in with ESMTPS id x1; Tue, 06 Oct 2026 10:01:00 +0000"
    m["Received"] = f"from mail.sender.example ([{received_ip}]) by mx.google.com with ESMTP id y2; Tue, 06 Oct 2026 10:00:58 +0000"
    m["Authentication-Results"] = auth_results
    m["From"] = frm
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = "Tue, 06 Oct 2026 10:00:57 +0000"
    m["Message-ID"] = make_msgid(domain="sender.example")
    if reply_to:
        m["Reply-To"] = reply_to
    if in_reply_to:
        m["In-Reply-To"] = in_reply_to
        m["References"] = in_reply_to
    if mailer:
        m["X-Mailer"] = mailer
    return m


def qr_png(data: str) -> bytes:
    import qrcode
    buf = io.BytesIO()
    qrcode.make(data).save(buf, format="PNG")
    return buf.getvalue()


def pdf_with_qr(url: str) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.drawString(72, 780, "Microsoft 365 - Multi-factor authentication renewal")
    c.drawString(72, 760, "Scan the code below with your phone to keep access to your mailbox.")
    c.drawImage(ImageReader(io.BytesIO(qr_png(url))), 72, 480, width=240, height=240)
    c.save()
    return buf.getvalue()


def write(name, msg):
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(bytes(msg))
    print("wrote", name)


# 1. Spoofed SBI KYC: DMARC fail, display-name impersonation, deceptive link, freemail reply-to
m = base('"State Bank of India" <alerts@sbi-yono-kyc.com>', "ashis@example.com",
         "Urgent: Your YONO account will be blocked today - complete KYC",
         auth("fail", "none", "fail", "sbi-yono-kyc.com"), reply_to="sbi.kyc.helpdesk@gmail.com", mailer="PHPMailer 6.8")
m.set_content("Dear Customer,\nYour SBI YONO account will be blocked today as your KYC is pending. "
              "Update PAN immediately: https://sbi-yono-kyc.web.app/update\nState Bank of India")
m.add_alternative('<html><body><p>Dear Customer,</p><p>Your <b>SBI YONO</b> account will be blocked today as your KYC '
                  'is pending.</p><p>Login here to update PAN: <a href="https://sbi-yono-kyc.web.app/update">'
                  'https://www.onlinesbi.sbi/kyc</a></p><p>State Bank of India</p></body></html>', subtype="html")
write("attack_sbi_kyc_spoof.eml", m)

# 2. CEO gift-card BEC from a free Gmail account, fake RE: thread
m = base('"Rajesh Kumar (CEO)" <rajesh.ceo.acme@gmail.com>', "priya@acme-industries.com", "RE: quick favour",
         auth("pass", "pass", "pass", "gmail.com"))
m.set_content("Priya,\nAre you at your desk? I need a quick favour and it's confidential. I'm in a board meeting and "
              "can't take calls. Please buy 5 Google Play gift cards of Rs 5000 each for a client and send me photos "
              "of the codes within the hour. I'll reimburse you today.\n\nRajesh Kumar\nCEO, Acme Industries")
write("attack_ceo_giftcard_bec.eml", m)

# 3. Malware delivery: invoice.pdf.exe, password-protected zip, macro doc, HTML login page
m = base('"Accounts Payable" <billing@invoices-portal.xyz>', "ashis@example.com", "Invoice INV-20931 overdue - final notice",
         auth("softfail", "none", "none", "invoices-portal.xyz"))
m.set_content("Hi,\nPlease find attached the overdue invoice and remittance form. The archive password is 2931.\nRegards, Accounts")
m.add_attachment(b"MZ\x90\x00" + b"\x00" * 200, maintype="application", subtype="octet-stream", filename="INV-20931.pdf.exe")
zbuf = io.BytesIO()
with zipfile.ZipFile(zbuf, "w") as z:
    zi = zipfile.ZipInfo("remittance_form.js")
    zi.flag_bits |= 0x1  # marks the entry as encrypted (password-protected)
    z.writestr(zi, b"var x='payload';")
zbytes = bytearray(zbuf.getvalue())
# Python's zipfile clears the "encrypted" flag on write, so set general-purpose bit 0
# by hand in the local header (offset 6) and the central-directory entry (offset 8).
zbytes[6] |= 0x01
cd = zbytes.find(b"PK\x01\x02")
zbytes[cd + 8] |= 0x01
m.add_attachment(bytes(zbytes), maintype="application", subtype="zip", filename="remittance.zip")
dbuf = io.BytesIO()
with zipfile.ZipFile(dbuf, "w") as z:
    z.writestr("[Content_Types].xml", "<Types/>")
    z.writestr("word/document.xml", "<w:document/>")
    z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0 Attribute VB_Name AutoOpen Shell")
m.add_attachment(dbuf.getvalue(), maintype="application", subtype="vnd.ms-word.document.macroEnabled.12", filename="statement.docm")
m.add_attachment(b'<html><body><h3>Microsoft 365</h3><form action="https://m365-docs-login.top/p.php" method="post">'
                 b'<input name="email"><input type="password" name="pw"></form>'
                 b'<script>eval(atob("d2luZG93LmxvY2F0aW9u"))</script></body></html>',
                 maintype="text", subtype="html", filename="Remittance_View.html")
write("attack_invoice_malware.eml", m)

# 4. Quishing: QR code inline + inside a PDF, pointing at a phishing page
phish = "https://m365-mfa-renew.pages.dev/login?user=ashis"
m = base('"Microsoft 365 Security" <security@m365-mfa-notice.com>', "ashis@example.com",
         "Action required: renew your multi-factor authentication",
         auth("pass", "pass", "none", "m365-mfa-notice.com"))
m.set_content("Your MFA registration expires today. Scan the attached QR code with your phone to renew access.")
m.add_attachment(qr_png(phish), maintype="image", subtype="png", filename="mfa_qr.png")
m.add_attachment(pdf_with_qr(phish), maintype="application", subtype="pdf", filename="MFA_Renewal.pdf")
write("attack_qr_quishing.eml", m)

# 5. 'Digital arrest' government impersonation from a free account
m = base('"CBI Cyber Crime Cell" <cbi.investigation.cell@gmail.com>', "ashis@example.com",
         "Notice: Aadhaar linked to money laundering case - digital arrest",
         auth("pass", "pass", "pass", "gmail.com"))
m.set_content("This is the Central Bureau of Investigation. Your Aadhaar number has been linked to a money laundering "
              "case. You are under digital arrest. Join the video call immediately and do not inform anyone. Transfer your "
              "savings to the RBI safe account for verification or a warrant will be issued.\n- Inspector Vikram Singh, CBI")
write("attack_cbi_digital_arrest.eml", m)

# 6. Fake security alert (look-alike domain, unauthenticated)
m = base('"Microsoft account team" <account-security-noreply@microsoft-accountprotection.info>', "ashis@example.com",
         "Unusual sign-in activity", auth("fail", "none", "fail", "microsoft-accountprotection.info"))
m.set_content("We detected something unusual about a recent sign-in to your Microsoft account. Sign-in from Russia. "
              "If this wasn't you, secure your account now: https://microsoft-accountprotection.info/recover")
write("attack_fake_microsoft_alert.eml", m)

# ---------------- genuine look-alikes (must NOT be flagged) ----------------
# 7. Genuine Google security alert -> account-takeover signal, not phishing
m = base('Google <no-reply@accounts.google.com>', "ashis@example.com", "Security alert",
         auth("pass", "pass", "pass", "accounts.google.com"), received_ip="209.85.220.41")
m.set_content("New sign-in on Windows\nashis@example.com\nWe noticed a new sign-in to your Google Account on a Windows "
              "device. If this was you, you don't need to do anything. If not, we'll help you secure your account.\n"
              "Check activity: https://myaccount.google.com/notifications")
write("genuine_google_signin_alert.eml", m)

# 8. Genuine HDFC statement (the old financial model flagged these)
m = base('"HDFC Bank" <alerts@hdfcbank.net>', "ashis@example.com", "Your HDFC Bank credit card statement for September",
         auth("pass", "pass", "pass", "hdfcbank.net"), received_ip="203.199.32.10")
m.set_content("Dear Customer,\nYour credit card statement for September 2026 is ready. Total amount due: Rs 3,240. "
              "Payment due date: 25 Oct 2026. You can view it in NetBanking or the HDFC Bank MobileBanking app.\n"
              "HDFC Bank will never ask for your OTP, PIN or password.")
write("genuine_hdfc_statement.eml", m)

# 9. Genuine university notice, real thread
m = base('"Examination Cell, BPUT" <examcell@bput.ac.in>', "students@bput.ac.in", "RE: Mid-semester examination schedule",
         auth("pass", "pass", "pass", "bput.ac.in"), received_ip="14.139.206.5", in_reply_to="<notice-41@bput.ac.in>")
m.set_content("Dear students,\nThe mid-semester examinations will begin on 14 October. The detailed timetable is on the "
              "university website https://bput.ac.in/notices. Please carry your ID cards.\nExamination Cell")
write("genuine_university_notice.eml", m)

# 10. Genuine Amazon shipment
m = base('"Amazon.in" <shipment-tracking@amazon.in>', "ashis@example.com", "Your Amazon.in order has shipped",
         auth("pass", "pass", "pass", "amazon.in"), received_ip="54.240.48.11")
m.set_content("Hello Ashis,\nYour package with boAt Airdopes 141 has shipped and will arrive Thursday.\n"
              "Track your package: https://www.amazon.in/gp/your-account/order-details?orderID=408-1234567-1234567")
write("genuine_amazon_shipment.eml", m)
