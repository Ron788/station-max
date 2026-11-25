#!/usr/bin/env python3
"""Locate and decode the in-kernel kallsyms tables of a raw arm64 Image.

The kernel does not expose /proc/kallsyms on the station (kptr_restrict=2,
SELinux open-deny), so the symbol table has to be recovered from the live
image.  The Linux build emits the tables with scripts/kallsyms.c:

    kallsyms_offsets[]        u32 relative offsets (CONFIG_KALLSYMS_BASE_RELATIVE)
    kallsyms_relative_base    u64 absolute base (normally _text)
    kallsyms_num_syms         u64 symbol count
    kallsyms_names[]          u8 length + token ids, one entry per symbol
    kallsyms_markers[]        u64 name-stream offset every 256 symbols
    kallsyms_token_table[]    256 NUL-terminated token strings
    kallsyms_token_index[]    256 u16 offsets into token_table

Every label is emitted with ALGN (.align 8).  On AArch64 GNU as/as-style
assemblers ``.align 8`` means 2**8 = 256 bytes, so each table starts on a
256-byte boundary and may be followed by up to 255 bytes of zero padding.
This parser accepts both 256-byte and 8-byte alignment, which also makes it
usable on host fixtures and on other toolchains.

The parser deliberately does not trust a single signature.  A candidate is
accepted only after all of these agree: the names stream walks to exactly
num_syms entries, every marker equals the recorded 256-symbol offset, the
token table expands to the token index byte-for-byte, and the relative
offsets decode to a sorted address range.

Usage (offline; no device access):

    python3 -B root/kallsyms/kallsyms_parse.py IMAGE \
        --kimage-vaddr 0xffffff8008000000 \
        --require _text --require init_task --require init_cred \
        --require selinux_enforcing --selinux-value 1

For a live dump that starts at the image load address, also pass
``--dump-pa 0x1080000`` (the physical address of the first dumped byte);
the tool then prints the physical address of each requested symbol, which
is what the write primitive needs.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import struct
import sys
from pathlib import Path
from typing import Iterable, Optional, Sequence

ALIGN_CANDIDATES = (0x100, 8)
KERNEL_VA_TOP = 0xFFFF
KERNEL_VA_MASK = 0xFFFF_0000_0000_0000
MIN_SYMS = 8
MAX_SYMS = 1_000_000
MAX_IMAGE_SPAN = 0x4000_0000  # 1 GiB: generous upper bound for validation
ARM64_IMAGE_MAGIC = 0x644D5241  # "ARM\x64" at file offset 0x38
MAX_NAME_LEN = 127
MAX_TOKEN_LEN = 255
MAX_TOKEN_TABLE = 0x10000


class KallsymsError(Exception):
    """The image does not contain a fully validated kallsyms table set."""


@dataclasses.dataclass(frozen=True)
class ImageHeader:
    text_offset: int
    image_size: int


@dataclasses.dataclass
class Tables:
    relative_base: int
    num_syms: int
    offsets_off: int
    relbase_off: int
    num_off: int
    names_off: int
    names_end: int
    markers_off: int
    markers_count: int
    token_table_off: int
    token_table_end: int
    token_index_off: int
    token_index_end: int
    alignment: int
    tokens: list[str]
    offsets: list[int]

    @property
    def addresses(self) -> list[int]:
        return [self.relative_base + value for value in self.offsets]

    def summary(self) -> str:
        return (
            "tables: offsets=0x%x relative_base=0x%x num_syms=%d "
            "names=0x%x..0x%x markers=0x%x(%d) "
            "token_table=0x%x..0x%x token_index=0x%x..0x%x align=%d"
            % (
                self.offsets_off,
                self.relative_base,
                self.num_syms,
                self.names_off,
                self.names_end,
                self.markers_off,
                self.markers_count,
                self.token_table_off,
                self.token_table_end,
                self.token_index_off,
                self.token_index_end,
                self.alignment,
            )
        )


@dataclasses.dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    critical: bool = True


@dataclasses.dataclass
class Report:
    checks: list[Check]

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks if check.critical)

    @property
    def failures(self) -> list[Check]:
        return [check for check in self.checks if not check.ok and check.critical]


@dataclasses.dataclass
class Symbol:
    name: str
    address: int
    index: int


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _zero_padding(data: bytes, start: int, end: int) -> bool:
    return not any(data[start:end])


def _is_kernel_va(value: int) -> bool:
    return (value & KERNEL_VA_MASK) == KERNEL_VA_MASK


def read_image_header(data: bytes) -> Optional[ImageHeader]:
    """Return the arm64 Image header fields, or None for a non-Image blob."""
    if len(data) < 0x40:
        return None
    if _u32(data, 0x38) != ARM64_IMAGE_MAGIC:
        return None
    text_offset = _u64(data, 0x08)
    image_size = _u64(data, 0x10)
    if text_offset > 0x4000_0000 or image_size < 0x1000:
        return None
    if image_size > MAX_IMAGE_SPAN:
        return None
    return ImageHeader(text_offset=text_offset, image_size=image_size)


def _walk_names(
    data: bytes, names_off: int, num_syms: int
) -> Optional[tuple[int, dict[int, int]]]:
    """Walk the compressed names stream and return (end, marker offsets)."""
    limit = len(data)
    off = names_off
    markers: dict[int, int] = {}
    first_offsets: list[int] = []
    for index in range(num_syms):
        if off >= limit:
            return None
        length = data[off]
        if length == 0 or length > MAX_NAME_LEN:
            return None
        if off + 1 + length > limit:
            return None
        if index & 0xFF == 0:
            markers[index] = off - names_off
        if index < 8:
            first_offsets.append(data[off + 1])
        off += 1 + length
    if off <= names_off:
        return None
    return off, markers


def _parse_token_table(
    data: bytes, offset: int
) -> Optional[tuple[list[int], int, list[str]]]:
    """Parse 256 NUL-terminated printable token strings at ``offset``."""
    limit = len(data)
    pos = offset
    starts: list[int] = []
    tokens: list[str] = []
    for _ in range(256):
        if pos >= limit:
            return None
        starts.append(pos - offset)
        end = data.find(b"\0", pos, min(limit, pos + MAX_TOKEN_LEN + 1))
        if end < 0:
            return None
        raw = data[pos:end]
        if any(byte < 0x20 or byte > 0x7E for byte in raw):
            return None
        tokens.append(raw.decode("latin1"))
        pos = end + 1
        if pos - offset > MAX_TOKEN_TABLE:
            return None
    return starts, pos, tokens


def _candidate_bases(
    data: bytes,
    *,
    kimage_vaddr: Optional[int],
    image_size: Optional[int],
) -> Iterable[int]:
    """Yield 8-aligned offsets that can hold kallsyms_relative_base.

    The quick top-byte filter keeps the full scan cheap on a 26 MB image;
    all semantic validation happens after a candidate is found.
    """
    limit = len(data) - 16
    max_va = None
    if kimage_vaddr is not None:
        span = max(image_size or 0, MAX_IMAGE_SPAN)
        max_va = kimage_vaddr + span
    for offset in range(0, limit, 8):
        if data[offset + 7] != 0xFF:
            continue
        base = _u64(data, offset)
        if not _is_kernel_va(base):
            continue
        if kimage_vaddr is not None and max_va is not None:
            if base < kimage_vaddr or base >= max_va:
                continue
        yield offset


def find_tables(
    data: bytes,
    *,
    kimage_vaddr: Optional[int] = None,
    image_size: Optional[int] = None,
    min_syms: int = MIN_SYMS,
    max_syms: int = MAX_SYMS,
) -> Tables:
    """Find and fully validate the kallsyms table set in ``data``.

    ``kimage_vaddr`` optionally narrows plausible relative-base values to
    the mapped image; it is never required for the structural checks.
    """
    if not data:
        raise KallsymsError("empty image")

    for relbase_off in _candidate_bases(
        data, kimage_vaddr=kimage_vaddr, image_size=image_size
    ):
        base = _u64(data, relbase_off)
        for num_align in ALIGN_CANDIDATES:
            num_off = _align_up(relbase_off + 8, num_align)
            if num_off + 8 > len(data):
                continue
            if not _zero_padding(data, relbase_off + 8, num_off):
                continue
            num_syms = _u64(data, num_off)
            if num_syms < min_syms or num_syms > max_syms:
                continue

            for names_align in ALIGN_CANDIDATES:
                names_off = _align_up(num_off + 8, names_align)
                if names_off >= len(data):
                    continue
                if not _zero_padding(data, num_off + 8, names_off):
                    continue
                if not 1 <= data[names_off] <= MAX_NAME_LEN:
                    continue
                walked = _walk_names(data, names_off, num_syms)
                if walked is None:
                    continue
                names_end, marker_offsets = walked

                for markers_align in ALIGN_CANDIDATES:
                    markers_off = _align_up(names_end, markers_align)
                    if not _zero_padding(data, names_end, markers_off):
                        continue
                    markers_count = (num_syms + 255) // 256
                    markers_end = markers_off + 8 * markers_count
                    if markers_end > len(data):
                        continue
                    markers = [_u64(data, markers_off + 8 * i)
                               for i in range(markers_count)]
                    if markers[0] != 0:
                        continue
                    if any(markers[i] >= markers[i + 1]
                           for i in range(markers_count - 1)):
                        continue
                    if markers[-1] >= names_end - names_off:
                        continue
                    if any(markers[i] != marker_offsets[i * 256]
                           for i in range(markers_count)):
                        continue

                    for tt_align in ALIGN_CANDIDATES:
                        token_table_off = _align_up(markers_end, tt_align)
                        if not _zero_padding(data, markers_end,
                                             token_table_off):
                            continue
                        token_table = _parse_token_table(data, token_table_off)
                        if token_table is None:
                            continue
                        starts, token_table_end, tokens = token_table

                        for ti_align in ALIGN_CANDIDATES:
                            token_index_off = _align_up(token_table_end,
                                                        ti_align)
                            if not _zero_padding(data, token_table_end,
                                                 token_index_off):
                                continue
                            if token_index_off + 512 > len(data):
                                continue
                            index = [_u16(data, token_index_off + 2 * i)
                                     for i in range(256)]
                            if index[0] != 0:
                                continue
                            if any(index[i] >= index[i + 1]
                                   for i in range(255)):
                                continue
                            if index != starts:
                                continue

                            for offsets_align in ALIGN_CANDIDATES:
                                offsets_span = _align_up(4 * num_syms,
                                                         offsets_align)
                                offsets_off = relbase_off - offsets_span
                                if offsets_off < 0:
                                    continue
                                if not _zero_padding(
                                    data, offsets_off + 4 * num_syms,
                                    relbase_off
                                ):
                                    continue
                                offsets = [
                                    _u32(data, offsets_off + 4 * i)
                                    for i in range(num_syms)
                                ]
                                addresses = [base + value for value in offsets]
                                if addresses[0] < base:
                                    continue
                                upper = base + max(
                                    image_size or 0, MAX_IMAGE_SPAN
                                )
                                if addresses[-1] > upper:
                                    continue
                                if any(addresses[i] > addresses[i + 1]
                                       for i in range(num_syms - 1)):
                                    continue
                                # The first offset is normally zero, but
                                # aliases/absolute percpu symbols are not
                                # needed on this kernel.  Require the
                                # structural facts above to be enough.
                                return Tables(
                                    relative_base=base,
                                    num_syms=num_syms,
                                    offsets_off=offsets_off,
                                    relbase_off=relbase_off,
                                    num_off=num_off,
                                    names_off=names_off,
                                    names_end=names_end,
                                    markers_off=markers_off,
                                    markers_count=markers_count,
                                    token_table_off=token_table_off,
                                    token_table_end=token_table_end,
                                    token_index_off=token_index_off,
                                    token_index_end=token_index_off + 512,
                                    alignment=offsets_align,
                                    tokens=tokens,
                                    offsets=offsets,
                                )
    raise KallsymsError(
        "no validated kallsyms tables found (image may be encrypted, "
        "truncated, or built without CONFIG_KALLSYMS_ALL)"
    )


def decode_names(data: bytes, tables: Tables) -> list[Symbol]:
    """Expand the compressed names stream into indexed symbols."""
    addresses = tables.addresses
    tokens = tables.tokens
    symbols: list[Symbol] = []
    off = tables.names_off
    for index in range(tables.num_syms):
        length = data[off]
        compressed = data[off + 1:off + 1 + length]
        off += 1 + length
        expanded = "".join(tokens[item] for item in compressed)
        if not expanded:
            continue
        # The first expanded character is the symbol type (T/t/D/...).
        name = expanded[1:]
        if not name:
            continue
        symbols.append(Symbol(name=name, address=addresses[index],
                              index=index))
    return symbols


class Kallsyms:
    """A validated symbol table plus lookup/self-check helpers."""

    def __init__(self, data: bytes, tables: Tables, symbols: Sequence[Symbol]):
        self.data = data
        self.tables = tables
        self.symbols = list(symbols)
        self._first: dict[str, Symbol] = {}
        self._all: dict[str, list[Symbol]] = {}
        for symbol in self.symbols:
            self._all.setdefault(symbol.name, []).append(symbol)
            self._first.setdefault(symbol.name, symbol)

    @classmethod
    def from_blob(
        cls,
        data: bytes,
        *,
        kimage_vaddr: Optional[int] = None,
        image_size: Optional[int] = None,
    ) -> "Kallsyms":
        tables = find_tables(
            data, kimage_vaddr=kimage_vaddr, image_size=image_size
        )
        return cls(data, tables, decode_names(data, tables))

    def resolve(self, name: str) -> Optional[int]:
        symbol = self._first.get(name)
        return symbol.address if symbol else None

    def all_addresses(self, name: str) -> list[int]:
        return [symbol.address for symbol in self._all.get(name, [])]

    def symbol(self, name: str) -> Optional[Symbol]:
        return self._first.get(name)

    def text_address(self) -> Optional[int]:
        for candidate in ("_text", "_stext"):
            address = self.resolve(candidate)
            if address is not None:
                return address
        return None

    def dump_offset(self, address: int, dump_va: Optional[int]) -> Optional[int]:
        start_va = dump_va if dump_va is not None else self.text_address()
        if start_va is None:
            return None
        offset = address - start_va
        if offset < 0 or offset >= len(self.data):
            return None
        return offset

    def pa(self, address: int, *, dump_pa: Optional[int],
           dump_va: Optional[int]) -> Optional[int]:
        if dump_pa is None:
            return None
        offset = self.dump_offset(address, dump_va)
        return None if offset is None else dump_pa + offset

    def read_u32(self, address: int, *, dump_va: Optional[int]) -> Optional[int]:
        offset = self.dump_offset(address, dump_va)
        if offset is None or offset + 4 > len(self.data):
            return None
        return _u32(self.data, offset)

    def self_check(
        self,
        *,
        kimage_vaddr: Optional[int] = None,
        image_size: Optional[int] = None,
        required: Sequence[str] = (),
        expected: Optional[dict[str, int]] = None,
        selinux_value: Optional[int] = None,
        dump_pa: Optional[int] = None,
        dump_va: Optional[int] = None,
        check_structs: bool = False,
    ) -> Report:
        checks: list[Check] = []
        tables = self.tables

        checks.append(Check(
            "tables_validated", True,
            "offsets/names/markers/token table all agree",
        ))
        checks.append(Check(
            "num_syms", MIN_SYMS <= tables.num_syms <= MAX_SYMS,
            "num_syms=%d" % tables.num_syms,
        ))
        addresses = tables.addresses
        checks.append(Check(
            "addresses_sorted",
            all(addresses[i] <= addresses[i + 1]
                for i in range(len(addresses) - 1)),
            "first=0x%x last=0x%x" % (addresses[0], addresses[-1]),
        ))
        checks.append(Check(
            "addresses_in_range",
            addresses[-1] <= tables.relative_base + max(
                image_size or 0, MAX_IMAGE_SPAN
            ),
            "relative_base=0x%x last=0x%x"
            % (tables.relative_base, addresses[-1]),
        ))

        text = self.resolve("_text")
        if text is None:
            checks.append(Check("_text_present", False, "symbol _text missing"))
        else:
            checks.append(Check(
                "_text_present", True, "_text=0x%x" % text,
            ))
            delta = text - tables.relative_base
            checks.append(Check(
                "_text_matches_relative_base", -0x1000 <= delta <= 0x1000,
                "relative_base=0x%x _text=0x%x delta=%+d"
                % (tables.relative_base, text, delta),
            ))
            if kimage_vaddr is not None:
                header = read_image_header(self.data)
                if header is not None:
                    expected_text = kimage_vaddr + header.text_offset
                    checks.append(Check(
                        "_text_matches_image_header",
                        text == expected_text,
                        "image_header=0x%x decoded=0x%x"
                        % (expected_text, text),
                    ))
                else:
                    checks.append(Check(
                        "_text_matches_image_header",
                        kimage_vaddr <= text < kimage_vaddr + MAX_IMAGE_SPAN,
                        "kimage_vaddr=0x%x decoded=0x%x"
                        % (kimage_vaddr, text),
                    ))

        for anchor in ("init_task", "init_cred"):
            address = self.resolve(anchor)
            checks.append(Check(
                "%s_present" % anchor, address is not None,
                "%s=%s" % (anchor, "0x%x" % address if address is not None
                           else "missing"),
            ))

        if required:
            for name in required:
                address = self.resolve(name)
                checks.append(Check(
                    "required_%s" % name, address is not None,
                    "%s=%s" % (name, "0x%x" % address if address is not None
                               else "missing"),
                ))

        if expected:
            for name, wanted in expected.items():
                got = self.resolve(name)
                checks.append(Check(
                    "expected_%s" % name, got == wanted,
                    "%s got=%s want=0x%x"
                    % (name, "0x%x" % got if got is not None else "missing",
                       wanted),
                ))

        selinux = self.resolve("selinux_enforcing")
        if selinux is not None:
            value = self.read_u32(selinux, dump_va=dump_va)
            if value is None:
                checks.append(Check(
                    "selinux_enforcing_value", False,
                    "address=0x%x is outside the dumped bytes" % selinux,
                    critical=selinux_value is not None,
                ))
            else:
                ok = value in (0, 1)
                criteria = "value=%d" % value
                if selinux_value is not None:
                    ok = value == selinux_value
                    criteria += " want=%d" % selinux_value
                checks.append(Check(
                    "selinux_enforcing_value", ok,
                    "address=0x%x %s" % (selinux, criteria),
                ))
            pa = self.pa(selinux, dump_pa=dump_pa, dump_va=dump_va)
            checks.append(Check(
                "selinux_enforcing_pa",
                pa is None or pa >= 0,
                "pa=%s" % ("0x%x" % pa if pa is not None else "unknown"),
                critical=False,
            ))

        if check_structs:
            checks.extend(self._check_kernel_structs(dump_va=dump_va))

        return Report(checks)

    def _check_kernel_structs(self, *, dump_va: Optional[int]) -> list[Check]:
        checks: list[Check] = []
        init_task = self.resolve("init_task")
        if init_task is None:
            checks.append(Check("init_task_comm", False, "init_task missing"))
        else:
            offset = self.dump_offset(init_task, dump_va)
            if offset is None:
                checks.append(Check(
                    "init_task_comm", False,
                    "init_task outside the dumped bytes",
                ))
            else:
                start = max(0, offset - 0x1000)
                end = min(len(self.data), offset + 0x1000)
                window = self.data[start:end]
                found = b"swapper" in window
                checks.append(Check(
                    "init_task_comm", found,
                    "init_task=0x%x file_off=0x%x swapper=%s"
                    % (init_task, offset, "yes" if found else "no"),
                ))

        init_cred = self.resolve("init_cred")
        if init_cred is None:
            checks.append(Check("init_cred_ids", False, "init_cred missing"))
        else:
            offset = self.dump_offset(init_cred, dump_va)
            if offset is None or offset + 0x24 > len(self.data):
                checks.append(Check(
                    "init_cred_ids", False, "init_cred outside dumped bytes",
                ))
            else:
                usage = _u32(self.data, offset)
                ids = [_u32(self.data, offset + 4 + 4 * i)
                       for i in range(8)]
                checks.append(Check(
                    "init_cred_ids",
                    0 < usage <= 0x10000 and all(value == 0 for value in ids),
                    "init_cred=0x%x usage=%d ids=%s"
                    % (init_cred, usage, ",".join(str(v) for v in ids)),
                ))
        return checks


def _parse_expected(values: Optional[Sequence[str]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values or ():
        if "=" not in value:
            raise argparse.ArgumentTypeError(
                "--expect requires NAME=0xVALUE, got %r" % value
            )
        name, raw = value.split("=", 1)
        result[name] = int(raw, 0)
    return result


def _format_report(report: Report) -> str:
    lines = []
    for check in report.checks:
        mark = "PASS" if check.ok else ("FAIL" if check.critical else "WARN")
        line = "%-4s %s" % (mark, check.name)
        if check.detail:
            line += ": " + check.detail
        lines.append(line)
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Locate and decode kernel kallsyms tables in a raw "
                    "arm64 Image or live-memory dump."
    )
    parser.add_argument("image", type=Path, help="raw Image / memory dump")
    parser.add_argument(
        "--kimage-vaddr", type=lambda s: int(s, 0), default=None,
        help="KIMAGE_VADDR used for image-header cross-checks "
             "(station: 0xffffff8008000000)",
    )
    parser.add_argument(
        "--dump-pa", type=lambda s: int(s, 0), default=None,
        help="physical address of the first byte in the dump",
    )
    parser.add_argument(
        "--dump-va", type=lambda s: int(s, 0), default=None,
        help="virtual address of the first byte in the dump "
             "(default: decoded _text)",
    )
    parser.add_argument(
        "--require", action="append", default=[],
        metavar="SYMBOL", help="require this symbol to be present",
    )
    parser.add_argument(
        "--expect", action="append", default=[],
        metavar="NAME=0xVALUE", help="require an exact symbol address",
    )
    parser.add_argument(
        "--selinux-value", type=lambda s: int(s, 0), default=None,
        help="require selinux_enforcing to hold this value in the dump",
    )
    parser.add_argument(
        "--max-syms", type=lambda s: int(s, 0), default=MAX_SYMS,
        help="upper bound for num_syms candidates (default: %d)" % MAX_SYMS,
    )
    parser.add_argument(
        "--check-structs", action="store_true",
        help="also sanity-check init_task comm and init_cred ids",
    )
    parser.add_argument(
        "--json", type=Path, default=None,
        help="write a machine-readable report to this path",
    )
    parser.add_argument(
        "--print-symbols", action="store_true",
        help="print every decoded symbol (large)",
    )
    args = parser.parse_args(argv)

    try:
        data = args.image.read_bytes()
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    header = read_image_header(data)
    if header is not None:
        print("image: header text_offset=0x%x image_size=0x%x"
              % (header.text_offset, header.image_size))
    else:
        print("image: no arm64 Image header (raw dump or fixture)")

    try:
        ks = Kallsyms.from_blob(
            data,
            kimage_vaddr=args.kimage_vaddr,
            image_size=header.image_size if header is not None else None,
        )
    except KallsymsError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1

    tables = ks.tables
    print(tables.summary())
    print("symbols: decoded=%d unique=%d"
          % (len(ks.symbols), len(ks._first)))
    print("relative_base=0x%x" % tables.relative_base)

    for name in ("_text", "_stext", "init_task", "init_cred",
                 "selinux_enforcing"):
        address = ks.resolve(name)
        if address is None:
            print("%s: missing" % name)
            continue
        pa = ks.pa(address, dump_pa=args.dump_pa, dump_va=args.dump_va)
        extra = ""
        if pa is not None:
            extra += " pa=0x%x" % pa
        if name == "selinux_enforcing":
            value = ks.read_u32(address, dump_va=args.dump_va)
            if value is not None:
                extra += " u32=%d" % value
        print("%s=0x%x%s" % (name, address, extra))

    expected = _parse_expected(args.expect)
    report = ks.self_check(
        kimage_vaddr=args.kimage_vaddr,
        image_size=header.image_size if header is not None else None,
        required=args.require,
        expected=expected,
        selinux_value=args.selinux_value,
        dump_pa=args.dump_pa,
        dump_va=args.dump_va,
        check_structs=args.check_structs,
    )
    print(_format_report(report))

    if args.print_symbols:
        for symbol in ks.symbols:
            print("0x%016x %s" % (symbol.address, symbol.name))

    if args.json is not None:
        payload = {
            "image": str(args.image),
            "size": len(data),
            "header": dataclasses.asdict(header) if header else None,
            "tables": {
                "offsets_off": tables.offsets_off,
                "relative_base": tables.relative_base,
                "num_syms": tables.num_syms,
                "names_off": tables.names_off,
                "names_end": tables.names_end,
                "markers_off": tables.markers_off,
                "markers_count": tables.markers_count,
                "token_table_off": tables.token_table_off,
                "token_table_end": tables.token_table_end,
                "token_index_off": tables.token_index_off,
                "token_index_end": tables.token_index_end,
                "alignment": tables.alignment,
            },
            "anchors": {
                name: ks.resolve(name)
                for name in ("_text", "_stext", "init_task", "init_cred",
                             "selinux_enforcing")
            },
            "selinux_enforcing_pa": ks.pa(
                ks.resolve("selinux_enforcing") or 0,
                dump_pa=args.dump_pa, dump_va=args.dump_va,
            ) if ks.resolve("selinux_enforcing") is not None else None,
            "checks": [
                dataclasses.asdict(check) for check in report.checks
            ],
            "ok": report.ok,
        }
        args.json.write_text(json.dumps(payload, indent=2) + "\n")

    print("RESULT: %s" % ("PASS" if report.ok else "FAIL"))
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
