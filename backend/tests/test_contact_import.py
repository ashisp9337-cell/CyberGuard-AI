"""(11 Nov) Import known contacts from a phone / Google / Outlook export. Made-up people only."""
import pytest

from app.services import contact_import as CI

VCF3 = ("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Mom\r\nN:Pal;Sunita;;;\r\nTEL;TYPE=CELL:+91 90000 00001\r\n"
        "EMAIL;TYPE=INTERNET:Sunita.Pal@Example.com\r\nEND:VCARD\r\n"
        "BEGIN:VCARD\r\nVERSION:3.0\r\nN:Nayak;S. K.;Dr;;\r\nitem1.EMAIL;TYPE=WORK:hod@college.example\r\n"
        "ADR:;;12 Long Street that is folded\r\n  onto a second line;Bhubaneswar\r\nNOTE:private note\r\nEND:VCARD\r\n"
        "BEGIN:VCARD\r\nVERSION:3.0\r\nTEL:+91 90000 00009\r\nEND:VCARD\r\n"
        "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Mom\r\nEMAIL:sunita.pal@example.com\r\nEND:VCARD\r\n")
VCF21 = ("BEGIN:VCARD\nVERSION:2.1\nN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:;=E0=A4=AE=E0=A4=BE=E0=A4=81;;;\n"
         "FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E0=A4=AE=E0=A4=\n=BE=E0=A4=81\nTEL;CELL:9000000002\nEND:VCARD\n")
GOOGLE = ("First Name,Middle Name,Last Name,Phone 1 - Value,E-mail 1 - Label,E-mail 1 - Value,E-mail 2 - Value\n"
          "Rakesh,,Sahoo,+91 90000 00003,* Work,rakesh@company.example,\n"
          "\"Das, Priya\",,,,,not-an-email,priya@example.org\n"
          ",,,+91 90000 00004,,,\n")
OUTLOOK = "First Name;Last Name;E-mail Address;Mobile Phone\nAnita;Roy;anita@example.net;9000000005\n"


def test_vcard_names_and_first_email_only_never_phones():
    kind, found, no_name = CI.parse(VCF3.encode())
    assert kind == "vCard" and no_name == 1
    assert found == [{"name": "Mom", "email": "sunita.pal@example.com"},
                     {"name": "S. K. Dr Nayak", "email": "hod@college.example"}]          # the 2nd "Mom" is a duplicate
    assert "9000" not in str(found) and "private" not in str(found) and "Street" not in str(found)


def test_old_android_vcard_with_quoted_printable_hindi_name():
    _, found, _ = CI.parse(VCF21.encode())
    assert found == [{"name": "माँ", "email": ""}]


def test_google_and_outlook_csv():
    kind, found, no_name = CI.parse(GOOGLE.encode("utf-8-sig"))
    assert kind == "CSV" and no_name == 0
    assert found == [{"name": "Rakesh Sahoo", "email": "rakesh@company.example"},
                     {"name": "Das, Priya", "email": "priya@example.org"}]
    assert CI.parse(OUTLOOK.encode())[1] == [{"name": "Anita Roy", "email": "anita@example.net"}]


@pytest.mark.parametrize("raw, words", [
    (b"x" * (CI.MAX_BYTES + 1), "larger than 2 MB"),
    (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "not a contacts file"),
    (b"Phone,City\n9000000006,Cuttack\n", "no name column"),
    (b"", "No contacts"),
])
def test_wrong_files_are_refused_with_a_clear_message(raw, words):
    with pytest.raises(CI.ImportError_, match=words):
        CI.parse(raw)


def test_formula_and_control_characters_in_names_are_plain_text():
    _, found, _ = CI.parse(b"BEGIN:VCARD\nFN:=cmd|' /C calc'!A0\x07\nEND:VCARD\n")
    assert found[0]["name"] == "=cmd|' /C calc'!A0"          # stored as text; React escapes it, CSV export guards it


def test_import_endpoint_adds_skips_duplicates_and_is_per_user(auth_client, client):
    auth_client.post("/api/contacts", json={"displayName": "mom", "authorizedEmail": ""})
    r = auth_client.post("/api/contacts/import", files={"file": ("contacts.vcf", VCF3.encode(), "text/vcard")})
    assert r.status_code == 200, r.text
    assert r.json() | {"total": 0} == {"format": "vCard", "imported": 2, "duplicates": 0, "withoutName": 1,
                                       "overLimit": 0, "total": 0}
    again = auth_client.post("/api/contacts/import", files={"file": ("contacts.vcf", VCF3.encode(), "text/vcard")}).json()
    assert again["imported"] == 0 and again["duplicates"] == 2
    rows = auth_client.get("/api/contacts").json()
    assert sorted(c["displayName"] for c in rows) == ["Mom", "S. K. Dr Nayak", "mom"]
    hod = next(c for c in rows if "Nayak" in c["displayName"])
    assert hod["authorizedEmail"] == "hod@college.example" and hod["authorizedDomain"] == "college.example"
    assert "9000" not in str(rows)                                              # no phone number anywhere
    bad = auth_client.post("/api/contacts/import", files={"file": ("x.png", b"\x89PNG\x00\x00", "image/png")})
    assert bad.status_code == 400 and bad.json()["error"]["code"] == "CONTACT_IMPORT_FAILED"
    from fastapi.testclient import TestClient
    from app.main import app
    stranger = TestClient(app)                                                  # not signed in
    assert stranger.post("/api/contacts/import", files={"file": ("c.vcf", VCF3.encode())}).status_code in (401, 403)
    assert stranger.delete("/api/contacts").status_code in (401, 403)
    assert auth_client.delete("/api/contacts").json() == {"removed": 3}
    assert auth_client.get("/api/contacts").json() == []


def test_imported_contact_is_used_by_the_impersonation_check(auth_client):
    import json
    def scan():
        return auth_client.post("/api/analysis/scan", data={
            "moduleId": "impersonation", "subtopicId": "contact-impersonation",
            "subtopicTitle": "Friend / Relative / Known Contact Impersonation",
            "textInput": "Hi, I lost my phone, this is my new number. Send Rs 15,000 to this UPI now, don't call.",
            "extraFieldValues": json.dumps({"claimedSenderName": "S. K. Dr Nayak", "senderEmail": "hod@collegee-exam.top"})}).json()
    before = [i["label"] for i in scan()["indicators"] if i["triggered"]]
    assert "Sender not in your saved contacts" in before
    auth_client.post("/api/contacts/import", files={"file": ("contacts.vcf", VCF3.encode(), "text/vcard")})
    after = scan()
    labels = [i["label"] for i in after["indicators"] if i["triggered"]]
    assert "Sender not in your saved contacts" not in labels
    assert any("domain" in i["label"].lower() and "college.example" in i["description"] for i in after["indicators"]
               if i["triggered"]), labels
