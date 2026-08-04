import gzip
import tempfile
import unittest
import zipfile
from pathlib import Path

from dmarc_parser import discover_files, parse_files, parse_xml


SAMPLE = b'''<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>Mail Co</org_name><report_id>abc-1</report_id><date_range><begin>1704067200</begin><end>1704153600</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><p>reject</p></policy_published>
  <record><row><source_ip>192.0.2.10</source_ip><count>42</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><dkim><domain>example.com</domain><result>pass</result></dkim><spf><domain>bounce.test</domain><result>fail</result></spf></auth_results></record>
</feedback>'''


class ParserTests(unittest.TestCase):
    def test_parse_xml(self):
        rows = parse_xml(SAMPLE, "sample.xml")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].count, 42)
        self.assertTrue(rows[0].aligned)
        self.assertEqual(rows[0].domain, "example.com")

    def test_batch_formats(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "one.xml").write_bytes(SAMPLE)
            with gzip.open(folder / "two.xml.gz", "wb") as stream:
                stream.write(SAMPLE)
            with zipfile.ZipFile(folder / "three.zip", "w") as archive:
                archive.writestr("nested/report.xml", SAMPLE)
            result = parse_files(discover_files(folder))
            self.assertEqual(result.reports_parsed, 3)
            self.assertEqual(len(result.rows), 3)
            self.assertFalse(result.issues)

    def test_rejects_entity_declarations(self):
        with self.assertRaisesRegex(ValueError, "not allowed"):
            parse_xml(b'<!DOCTYPE foo [<!ENTITY x "bad">]><feedback/>', "bad.xml")


if __name__ == "__main__":
    unittest.main()
