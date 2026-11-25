#!/usr/bin/env python3
"""Host tests for the offline kallsyms parser.

The tests are hermetic: the main fixture is generated with the same layout
as scripts/kallsyms.c (base-relative offsets, 256-symbol markers, token
compression).  When the local 4.14 lab Image is present, an additional
test compares every decoded symbol against its System.map; that fixture is
private build output and is skipped on a clean checkout.

Run from the archive root:

    python3 -B root/src/kallsyms/test_kallsyms_parse.py -v

The optional lab cross-check uses LAB_IMAGE and LAB_SYSTEM_MAP if set;
otherwise it is skipped.
"""
from __future__ import annotations

import os
import random
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import kallsyms_parse as kp  # noqa: E402

LAB_IMAGE = Path(os.environ.get("LAB_IMAGE", HERE / "lab/Image"))
LAB_SYSTEM_MAP = Path(os.environ.get("LAB_SYSTEM_MAP", HERE / "lab/System.map"))

STATION_TEXT = 0xFFFFFF8009080000


def _pad_to(buf: bytearray, alignment: int) -> None:
    if len(buf) % alignment:
        buf.extend(b"\0" * (alignment - len(buf) % alignment))


def _token_table() -> tuple[list[str], dict[str, int]]:
    """A deterministic token table covering printable symbol characters."""
    tokens: list[str] = []
    char_to_index: dict[str, int] = {}
    for code in range(0x20, 0x7F):
        index = len(tokens)
        char = chr(code)
        tokens.append(char)
        char_to_index[char] = index
    while len(tokens) < 256:
        tokens.append("")
    return tokens, char_to_index


def _compress(expanded: str, char_to_index: dict[str, int]) -> bytes:
    try:
        return bytes(char_to_index[char] for char in expanded)
    except KeyError as exc:
        raise AssertionError("fixture symbol has an unencodable char: %r"
                             % str(exc)) from None


def build_fixture(
    symbols: list[tuple[str, int]],
    *,
    base: int = STATION_TEXT,
    alignment: int = 0x100,
    junk_prefix: int = 0,
    junk_suffix: int = 0,
    seed: int = 1,
) -> tuple[bytes, dict[str, int]]:
    """Build a validated table blob using the kernel generator layout."""
    ordered = sorted(symbols, key=lambda item: item[1])
    if ordered[0][1] != base:
        raise AssertionError("_text must be the lowest address")
    tokens, char_to_index = _token_table()

    names = bytearray()
    markers: list[int] = []
    for index, (name, _address) in enumerate(ordered):
        if index % 256 == 0:
            markers.append(len(names))
        expanded = "T" + name
        compressed = _compress(expanded, char_to_index)
        if not 1 <= len(compressed) <= kp.MAX_NAME_LEN:
            raise AssertionError("fixture name length out of range")
        names.append(len(compressed))
        names.extend(compressed)

    token_table = bytearray()
    token_starts: list[int] = []
    for token in tokens:
        token_starts.append(len(token_table))
        token_table.extend(token.encode("latin1"))
        token_table.append(0)

    offsets = [address - base for _name, address in ordered]

    table = bytearray()
    _pad_to(table, alignment)
    offsets_off = len(table)
    for value in offsets:
        table.extend(struct.pack("<I", value))
    _pad_to(table, alignment)
    relbase_off = len(table)
    table.extend(struct.pack("<Q", base))
    _pad_to(table, alignment)
    num_off = len(table)
    table.extend(struct.pack("<Q", len(ordered)))
    _pad_to(table, alignment)
    names_off = len(table)
    table.extend(names)
    _pad_to(table, alignment)
    markers_off = len(table)
    for value in markers:
        table.extend(struct.pack("<Q", value))
    _pad_to(table, alignment)
    token_table_off = len(table)
    table.extend(token_table)
    _pad_to(table, alignment)
    token_index_off = len(table)
    for value in token_starts:
        table.extend(struct.pack("<H", value))
    _pad_to(table, alignment)

    rng = random.Random(seed)
    prefix = bytes(rng.randrange(256) for _ in range(junk_prefix))
    suffix = bytes(rng.randrange(256) for _ in range(junk_suffix))
    blob = prefix + bytes(table) + suffix

    expected: dict[str, int] = {}
    for name, address in ordered:
        expected.setdefault(name, address)
    expected.update({
        "_fixture_offsets_off": offsets_off + junk_prefix,
        "_fixture_relbase_off": relbase_off + junk_prefix,
        "_fixture_num_off": num_off + junk_prefix,
        "_fixture_names_off": names_off + junk_prefix,
        "_fixture_markers_off": markers_off + junk_prefix,
        "_fixture_token_table_off": token_table_off + junk_prefix,
        "_fixture_token_index_off": token_index_off + junk_prefix,
    })
    return blob, expected


def station_symbols(count: int = 11) -> list[tuple[str, int]]:
    symbols = [
        ("_text", STATION_TEXT),
        ("_stext", STATION_TEXT + 0x1000),
        ("selinux_enforcing", STATION_TEXT + 0x1A3C4C4),
        ("init_task", STATION_TEXT + 0x162B080),
        ("init_cred", STATION_TEXT + 0x163C460),
        ("_etext", STATION_TEXT + 0x1C00000),
        ("_end", STATION_TEXT + 0x2600000),
    ]
    for index in range(count):
        symbols.append(("fixture_symbol_%04d" % index,
                        STATION_TEXT + 0x200000 + 0x40 * index))
    return sorted(symbols, key=lambda item: item[1])


class FixtureTests(unittest.TestCase):
    def assert_symbols(self, ks: kp.Kallsyms, expected: dict[str, int]) -> None:
        for name, address in expected.items():
            if name.startswith("_fixture_"):
                continue
            self.assertIn(name, ks._first)
            self.assertEqual(ks.resolve(name), address, name)

    def test_small_fixture_exact(self) -> None:
        symbols = station_symbols(4)
        blob, expected = build_fixture(symbols)
        ks = kp.Kallsyms.from_blob(blob, kimage_vaddr=0xFFFFFF8008000000)
        self.assert_symbols(ks, expected)
        tables = ks.tables
        self.assertEqual(tables.relative_base, STATION_TEXT)
        self.assertEqual(tables.num_syms, len(symbols))
        self.assertEqual(tables.markers_count, 1)
        self.assertEqual(tables.alignment, 0x100)
        self.assertEqual(tables.offsets_off,
                         expected["_fixture_offsets_off"])
        self.assertEqual(tables.relbase_off,
                         expected["_fixture_relbase_off"])
        self.assertEqual(tables.num_off, expected["_fixture_num_off"])
        self.assertEqual(tables.names_off, expected["_fixture_names_off"])
        self.assertEqual(tables.markers_off,
                         expected["_fixture_markers_off"])
        self.assertEqual(tables.token_table_off,
                         expected["_fixture_token_table_off"])
        self.assertEqual(tables.token_index_off,
                         expected["_fixture_token_index_off"])

    def test_multi_marker_and_duplicate_names(self) -> None:
        symbols = station_symbols(620)
        # Duplicate names are aliases in real kallsyms; first occurrence wins.
        symbols.append(("init_task", STATION_TEXT + 0x2500000))
        symbols.sort(key=lambda item: item[1])
        blob, expected = build_fixture(symbols)
        ks = kp.Kallsyms.from_blob(blob, kimage_vaddr=0xFFFFFF8008000000)
        self.assertEqual(ks.tables.markers_count, (len(symbols) + 255) // 256)
        self.assertEqual(ks.tables.markers_count, 3)
        self.assertEqual(len(ks.all_addresses("init_task")), 2)
        self.assertEqual(ks.resolve("init_task"), expected["init_task"])

    def test_alignment_8(self) -> None:
        symbols = station_symbols(300)
        blob, expected = build_fixture(symbols, alignment=8)
        ks = kp.Kallsyms.from_blob(blob, kimage_vaddr=0xFFFFFF8008000000)
        self.assert_symbols(ks, expected)
        self.assertEqual(ks.tables.alignment, 8)

    def test_junk_prefix_and_suffix(self) -> None:
        symbols = station_symbols(30)
        blob, expected = build_fixture(
            symbols, junk_prefix=256, junk_suffix=77, seed=7
        )
        ks = kp.Kallsyms.from_blob(blob, kimage_vaddr=0xFFFFFF8008000000)
        self.assert_symbols(ks, expected)
        self.assertEqual(ks.tables.offsets_off,
                         expected["_fixture_offsets_off"])

    def test_random_data_rejected(self) -> None:
        rng = random.Random(99)
        blob = bytes(rng.randrange(256) for _ in range(200_000))
        with self.assertRaises(kp.KallsymsError):
            kp.Kallsyms.from_blob(blob)

    def test_truncated_table_rejected(self) -> None:
        blob, _expected = build_fixture(station_symbols(11))
        with self.assertRaises(kp.KallsymsError):
            kp.Kallsyms.from_blob(blob[:-100])

    def test_selinux_value_and_pa(self) -> None:
        symbols = [
            ("_text", STATION_TEXT),
            ("_stext", STATION_TEXT + 0x1000),
            ("init_task", STATION_TEXT + 0x4000),
            ("init_cred", STATION_TEXT + 0x5000),
            ("selinux_enforcing", STATION_TEXT + 0x8000),
            ("fixture_symbol_0000", STATION_TEXT + 0x9000),
            ("_etext", STATION_TEXT + 0x10000),
            ("_end", STATION_TEXT + 0x20000),
        ]
        blob, expected = build_fixture(symbols)
        # Put the table blob at file offset 0x1000 of a synthetic image
        # whose first byte corresponds to _text.  selinux_enforcing is at
        # base+0x8000, so its live value can be planted there.
        image = bytearray(b"\0" * 0x20000)
        image[0x1000:0x1000 + len(blob)] = blob
        struct.pack_into("<I", image, 0x8000, 1)
        ks = kp.Kallsyms.from_blob(
            bytes(image), kimage_vaddr=0xFFFFFF8008000000
        )
        self.assertEqual(ks.resolve("selinux_enforcing"),
                         expected["selinux_enforcing"])
        self.assertEqual(ks.read_u32(expected["selinux_enforcing"],
                                     dump_va=STATION_TEXT), 1)
        self.assertEqual(
            ks.pa(expected["selinux_enforcing"],
                  dump_pa=0x1080000, dump_va=STATION_TEXT),
            0x1080000 + 0x8000,
        )
        report = ks.self_check(
            kimage_vaddr=0xFFFFFF8008000000,
            required=("_text", "init_task", "init_cred",
                      "selinux_enforcing"),
            selinux_value=1,
            dump_pa=0x1080000,
            dump_va=STATION_TEXT,
        )
        self.assertTrue(report.ok, kp._format_report(report))

    def test_expected_address_mismatch_fails(self) -> None:
        blob, expected = build_fixture(station_symbols(11))
        ks = kp.Kallsyms.from_blob(blob, kimage_vaddr=0xFFFFFF8008000000)
        report = ks.self_check(
            expected={"init_task": expected["init_task"] + 4},
        )
        self.assertFalse(report.ok)
        self.assertTrue(any(check.name == "expected_init_task"
                            and not check.ok for check in report.checks))

    def test_missing_required_symbol_fails(self) -> None:
        blob, _expected = build_fixture(station_symbols(11))
        ks = kp.Kallsyms.from_blob(blob, kimage_vaddr=0xFFFFFF8008000000)
        report = ks.self_check(required=("not_a_real_symbol",))
        self.assertFalse(report.ok)


@unittest.skipUnless(LAB_IMAGE.exists() and LAB_SYSTEM_MAP.exists(),
                     "local 4.14 lab Image/System.map not present")
class RealLabImageTests(unittest.TestCase):
    def test_every_common_symbol_matches_system_map(self) -> None:
        data = LAB_IMAGE.read_bytes()
        ks = kp.Kallsyms.from_blob(
            data, kimage_vaddr=0xFFFF000008000000
        )
        system_map: dict[str, int] = {}
        for line in LAB_SYSTEM_MAP.read_text().splitlines():
            fields = line.split()
            if len(fields) >= 3:
                system_map.setdefault(fields[2], int(fields[0], 16))
        common = set(system_map) & set(ks._first)
        self.assertGreater(len(common), 80_000)
        mismatches = [
            (name, ks.resolve(name), system_map[name])
            for name in common
            if ks.resolve(name) != system_map[name]
        ]
        self.assertEqual(mismatches[:5], [])
        self.assertEqual(ks.resolve("_text"), 0xFFFF000008080000)
        self.assertEqual(ks.resolve("init_task"), 0xFFFF0000095A3080)
        self.assertEqual(ks.resolve("init_cred"), 0xFFFF0000095B4460)
        report = ks.self_check(
            kimage_vaddr=0xFFFF000008000000,
            required=("_text", "init_task", "init_cred"),
            check_structs=True,
        )
        self.assertTrue(report.ok, kp._format_report(report))


if __name__ == "__main__":
    unittest.main()
