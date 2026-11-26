import unittest
from ja3print.fingerprints import HelloData, build_ja3, build_ja4, is_grease

class FingerprintTests(unittest.TestCase):
    def test_grease_detection(self):
        self.assertTrue(is_grease(0x0A0A))
        self.assertTrue(is_grease(0x2A2A))
        self.assertFalse(is_grease(0x1301))

    def test_ja3_shape_and_md5(self):
        sample = HelloData(legacy_version=771, ciphers=[0x1301, 0x0A0A, 0x1302], extensions=[0, 10, 11, 0x1A1A], supported_groups=[29, 23], point_formats=[0])
        raw, digest = build_ja3(sample)
        self.assertEqual(raw, "771,4865-4866,0-10-11,29-23,0")
        self.assertEqual(len(digest), 32)
        self.assertEqual(digest, digest.lower())

    def test_ja4_shape(self):
        sample = HelloData(legacy_version=771, supported_versions=[0x0304], ciphers=[0x1301, 0x1302], extensions=[0, 16, 43, 13, 10], signature_algorithms=[0x0403, 0x0804], alpn_protocols=["h2"], sni="example.test")
        result = build_ja4(sample)
        self.assertTrue(result.startswith("t13d0205h2_"))
        self.assertEqual(len(result.split("_")), 3)
        self.assertEqual(len(result.split("_")[1]), 12)
        self.assertEqual(len(result.split("_")[2]), 12)

    def test_empty_ja4_hashes(self):
        result = build_ja4(HelloData(legacy_version=771))
        self.assertEqual(result, "t12i000000_000000000000_000000000000")

if __name__ == "__main__":
    unittest.main()
