import unittest

from sentinelscan.checks import dns_email


def make_lookup(records: dict, timeouts=()):
    """records: {(name, rdtype): [strings]}. timeouts: set of rdtypes that raise."""
    def lookup(name, rdtype):
        if rdtype in timeouts:
            raise TimeoutError("simulated")
        return records.get((name, rdtype), [])
    return lookup


def ids(hits):
    return [h.id for h in hits]


class SpfDmarc(unittest.TestCase):
    def test_fully_protected_domain_is_clean(self):
        rec = {
            ("example.com", "MX"): ["mail.example.com"],
            ("example.com", "TXT"): ["v=spf1 include:_spf.google.com -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@example.com"],
            ("example.com", "CAA"): ["0 issue \"letsencrypt.org\""],
            ("example.com", "DNSKEY"): ["256 3 13 abc..."],
        }
        info, hits, ran = dns_email.analyze("example.com", make_lookup(rec))
        self.assertEqual(hits, [])
        self.assertTrue(all(ran.values()))
        self.assertTrue(info["has_mx"])

    def test_unprotected_mail_domain(self):
        rec = {("example.com", "MX"): ["mail.example.com"]}
        _, hits, _ = dns_email.analyze("example.com", make_lookup(rec))
        found = ids(hits)
        self.assertIn("spf_missing", found)
        self.assertIn("dmarc_missing", found)
        self.assertIn("caa_missing", found)
        self.assertIn("dnssec_missing", found)
        spf = next(h for h in hits if h.id == "spf_missing")
        self.assertEqual(spf.severity, "medium")  # has MX -> medium

    def test_no_mx_lowers_spf_severity(self):
        _, hits, _ = dns_email.analyze("example.com", make_lookup({}))
        spf = next(h for h in hits if h.id == "spf_missing")
        self.assertEqual(spf.severity, "low")

    def test_spf_all_pass_is_high(self):
        rec = {("x.com", "TXT"): ["v=spf1 +all"]}
        _, hits, _ = dns_email.analyze("x.com", make_lookup(rec))
        self.assertIn("spf_all_pass", ids(hits))

    def test_spf_bare_all_is_high(self):
        rec = {("x.com", "TXT"): ["v=spf1 mx all"]}
        _, hits, _ = dns_email.analyze("x.com", make_lookup(rec))
        self.assertIn("spf_all_pass", ids(hits))

    def test_spf_neutral(self):
        rec = {("x.com", "TXT"): ["v=spf1 include:a ?all"]}
        _, hits, _ = dns_email.analyze("x.com", make_lookup(rec))
        self.assertIn("spf_neutral", ids(hits))

    def test_spf_hardfail_is_clean(self):
        rec = {("x.com", "TXT"): ["v=spf1 -all"], ("x.com", "DNSKEY"): ["k"],
               ("x.com", "CAA"): ["0 issue \"x\""], ("_dmarc.x.com", "TXT"): ["v=DMARC1; p=reject"]}
        _, hits, _ = dns_email.analyze("x.com", make_lookup(rec))
        self.assertEqual(hits, [])

    def test_multiple_spf(self):
        rec = {("x.com", "TXT"): ["v=spf1 -all", "v=spf1 include:b -all"]}
        _, hits, _ = dns_email.analyze("x.com", make_lookup(rec))
        self.assertIn("spf_multiple", ids(hits))

    def test_dmarc_policy_none(self):
        rec = {("x.com", "TXT"): ["v=spf1 -all"],
               ("_dmarc.x.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:a@x.com"]}
        _, hits, _ = dns_email.analyze("x.com", make_lookup(rec))
        self.assertIn("dmarc_policy_none", ids(hits))
        self.assertNotIn("dmarc_missing", ids(hits))

    def test_txt_ignores_unrelated_records(self):
        rec = {("x.com", "TXT"): ["google-site-verification=abc", "v=spf1 -all"]}
        _, hits, _ = dns_email.analyze("x.com", make_lookup(rec))
        self.assertNotIn("spf_missing", ids(hits))

    def test_timeout_marks_check_not_run(self):
        _, hits, ran = dns_email.analyze("x.com", make_lookup({}, timeouts={"TXT"}))
        self.assertFalse(ran["spf"])
        self.assertNotIn("spf_missing", ids(hits))


if __name__ == "__main__":
    unittest.main()
