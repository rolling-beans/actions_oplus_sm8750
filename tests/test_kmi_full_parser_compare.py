"""Full kernel variant must be independently linked and its differences reported."""
import unittest
from scripts.kmi_full_parser_compare import compare_config, compare_exports

NET = "config BPF_STREAM_PARSER\n\tbool\n\tselect STREAM_PARSER\n\nconfig OTHER\n\tbool\n"
BASE = "CONFIG_BPF_STREAM_PARSER=y\nCONFIG_STREAM_PARSER=y\nCONFIG_IP_SET=y\nCONFIG_CGROUP_BPF=y\n"
ALT = "# CONFIG_BPF_STREAM_PARSER is not set\n# CONFIG_STREAM_PARSER is not set\nCONFIG_IP_SET=y\nCONFIG_CGROUP_BPF=y\n"
STG = ('elf_symbol {\n name: "sk_filter_trim_cap"\n is_defined: true\n crc: 0x553e24af\n}\n'
       'elf_symbol {\n name: "icc_put"\n is_defined: true\n crc: 0x00000012\n}\n')
CONTROL = ('0x43eebd89\tsk_filter_trim_cap\tvmlinux\tEXPORT_SYMBOL\n'
           '0x00000012\ticc_put\tvmlinux\tEXPORT_SYMBOL\n')
VARIANT = ('0x553e24af\tsk_filter_trim_cap\tvmlinux\tEXPORT_SYMBOL\n'
           '0x00000012\ticc_put\tvmlinux\tEXPORT_SYMBOL\n')
SWEEP = {'comparator': {'results': [
    {'symbol': 'sk_filter_trim_cap', 'reference_stg_crc': '0x553e24af',
     'compiled_kernel_crc': '0x43eebd89'}]}}


class FullKMIExperimentTests(unittest.TestCase):
    def test_only_parser_and_derived_select_change(self):
        d = compare_config(BASE, ALT, NET)
        self.assertEqual(d["status"], "COMPLETE")
        self.assertEqual(len(d["differences"]), 2)
        self.assertTrue(d["derived_stream_parser_disabled"])

    def test_unrelated_feature_change_blocks_comparison(self):
        d = compare_config(BASE, ALT.replace("CONFIG_IP_SET=y", "# CONFIG_IP_SET is not set"), NET)
        self.assertEqual(d["status"], "CONFOUNDED")

    def test_unproven_select_blocks_comparison(self):
        self.assertEqual(compare_config(BASE, ALT, "config BPF_STREAM_PARSER\n bool\n")["status"],
                         "CONFOUNDED")

    def test_full_symvers_restoration_and_missing_modules_explicit(self):
        d = compare_exports(STG, CONTROL, VARIANT, SWEEP)
        self.assertEqual(d["status"], "COMPLETE")
        self.assertEqual(d["changed_crc_count"], 1)
        self.assertEqual(d["known_sweep_restored"], ["sk_filter_trim_cap"])
        self.assertEqual(d["stg_control"]["mismatched"], 1)
        self.assertEqual(d["stg_variant"]["mismatched"], 0)
        self.assertEqual(d["private_593_module_imports"]["status"], "UNVERIFIED")
        self.assertFalse(d["android_boot_tested"])

    def test_export_addition_and_removal_not_silent(self):
        variant = VARIANT.splitlines()[0] + "\n0x00000000\tnew_export\tvmlinux\tEXPORT_SYMBOL\n"
        d = compare_exports(STG, CONTROL, variant, SWEEP)
        self.assertEqual(d["added_exports"], ["new_export"])
        self.assertEqual(d["removed_exports"], ["icc_put"])
        self.assertEqual(d["stg_missing_from_variant"], ["icc_put"])

    def test_existing_control_drift_is_exposed(self):
        alt_control = CONTROL.replace("43eebd89", "99999999")
        d = compare_exports(STG, alt_control, VARIANT, SWEEP)
        self.assertEqual(d["known_sweep_control_drift"], ["sk_filter_trim_cap"])


if __name__ == "__main__":
    unittest.main()
