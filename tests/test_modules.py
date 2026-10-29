#!/usr/bin/env python3
"""
parse_evtx.py 的模块级测试套件（macOS / Linux）。

覆盖六类：功能、边界、数据质量、多通道、性能、交叉验证。
不依赖 pytest，直接运行：

    python3 tests/test_modules.py            # 自动寻找 ../*.zip 或 *.evtx 作为样本
    WLF_CASE=/path/to/case.evtx python3 tests/test_modules.py
    python3 tests/test_modules.py -v         # 逐条显示

多通道样本（System / TerminalServices）会在首次运行时从
github.com/omerbenamram/evtx 的 samples 目录下载到 tests/.cache/；
无网络时相关用例标记为 SKIP，不影响其余用例。
"""

import csv
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCRIPT = ROOT / "scripts" / "parse_evtx.py"
CACHE = HERE / ".cache"

SAMPLE_BASE = "https://raw.githubusercontent.com/omerbenamram/evtx/master/samples/"
SAMPLES = {
    "system": "2-vss_7-System.evtx",
    "termsvc": (
        "2-vss_0-Microsoft-Windows-TerminalServices-"
        "RemoteConnectionManager%254Operational.evtx"
    ),
}

# 由 Windows 版 PowerShell 脚本独立解析得到的基准值（见 README「实测」）
CASE_TOTAL = 9707
CASE_4624 = 273
CASE_4625 = 12
CASE_LOGON_ROWS = CASE_4624 + CASE_4625
CASE_NETLOGON_ROWS = 88
CASE_DUMP_4624_4648 = 360
CASE_ACCOUNT_EVENTS = 9
CASE_TASK_EVENTS = 2

RUN_TIMEOUT = 600


def run(args, timeout=RUN_TIMEOUT):
    started = time.time()
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)] + [str(a) for a in args],
        capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr, time.time() - started


def download(name, filename):
    CACHE.mkdir(parents=True, exist_ok=True)
    target = CACHE / (name + ".evtx")
    if target.exists() and target.stat().st_size > 0:
        return target
    try:
        urllib.request.urlretrieve(SAMPLE_BASE + filename, target)
    except Exception:
        if target.exists():
            target.unlink()
        return None
    return target


def locate_case():
    env = os.environ.get("WLF_CASE")
    if env and Path(env).exists():
        return Path(env)
    for base in (ROOT.parent, Path.cwd(), Path.cwd().parent):
        for candidate in sorted(base.glob("*.evtx")):
            return candidate
        for archive in sorted(base.glob("*.zip")):
            target_dir = CACHE / "case"
            if target_dir.exists():
                for candidate in sorted(target_dir.glob("*.evtx")):
                    return candidate
            target_dir.mkdir(parents=True, exist_ok=True)
            try:
                with zipfile.ZipFile(archive) as zf:
                    for info in zf.infolist():
                        if info.filename.lower().endswith(".evtx"):
                            zf.extract(info, target_dir)
                            return target_dir / info.filename
            except Exception:
                continue
    return None


def has_traceback(stderr):
    return "Traceback (most recent call last)" in stderr


def count_headers(stdout):
    return sum(1 for line in stdout.splitlines() if line.startswith("=========="))


def stable_lines(stdout):
    """剔除带耗时的行，用于比较不同进程间的输出一致性。"""
    return [line for line in stdout.splitlines()
            if not line.startswith("[*] parsed")]


class Base(unittest.TestCase):
    case = None
    system_sample = None
    termsvc_sample = None
    tmp = None

    @classmethod
    def setUpClass(cls):
        cls.case = locate_case()
        cls.system_sample = download("system", SAMPLES["system"])
        cls.termsvc_sample = download("termsvc", SAMPLES["termsvc"])
        cls.tmp = Path(tempfile.mkdtemp(prefix="wlf-test-"))

    @classmethod
    def tearDownClass(cls):
        if cls.tmp and cls.tmp.exists():
            shutil.rmtree(cls.tmp, ignore_errors=True)

    def require_case(self):
        if not self.case:
            self.skipTest("未找到样本 .evtx / .zip，请设置 WLF_CASE")

    def require_system(self):
        if not self.system_sample:
            self.skipTest("无法获取 System 通道样本（离线？）")

    def require_termsvc(self):
        if not self.termsvc_sample:
            self.skipTest("无法获取 TerminalServices 通道样本（离线？）")

    def tmpdir(self, name):
        path = self.tmp / name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def copy_case(self, name):
        target = self.tmp / name
        shutil.copyfile(self.case, target)
        return target


class TestFunctional(Base):
    """功能：七种模式的实际输出。"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.out_all = None
        cls.out_logons = None
        cls.results = {}
        if not cls.case:
            return
        cls.results["summary"] = run(["-Path", cls.case, "-Mode", "summary"])
        cls.results["logons"] = run(["-Path", cls.case, "-Mode", "logons"])
        cls.results["netlogons"] = run(["-Path", cls.case, "-Mode", "netlogons"])
        cls.results["accounts"] = run(["-Path", cls.case, "-Mode", "accounts"])
        cls.results["tasks"] = run(["-Path", cls.case, "-Mode", "tasks"])
        cls.results["dump"] = run(["-Path", cls.case, "-Mode", "dump",
                                   "-Ids", "4624,4648"])

    def test_01_summary_totals(self):
        self.require_case()
        rc, out, err, _ = self.results["summary"]
        self.assertEqual(rc, 0, err)
        self.assertIn("Events      : %d" % CASE_TOTAL, out)
        self.assertIn("5270", out)  # 5159 事件数量最多的 ID
        self.assertNotIn("Traceback", err)

    def test_02_summary_host_and_channel(self):
        self.require_case()
        _, out, _, _ = self.results["summary"]
        self.assertIn("Host        : WIN-WH8G5MDPHE5.ADoflmb.com", out)
        self.assertIn("Security", out)

    def test_03_logons_rows(self):
        self.require_case()
        rc, out, _, _ = self.results["logons"]
        self.assertEqual(rc, 0)
        self.assertIn("=== LOGONS (%d rows) ===" % CASE_LOGON_ROWS, out)
        self.assertIn("4625", out)

    def test_04_netlogons_count_and_loopback(self):
        self.require_case()
        rc, out, _, _ = self.results["netlogons"]
        self.assertEqual(rc, 0)
        self.assertIn("=== REMOTE LOGONS (%d rows, excluding loopback) ==="
                      % CASE_NETLOGON_ROWS, out)
        self.assertNotIn("127.0.0.1", out)
        self.assertNotIn(" ::1 ", out)

    def test_05_netlogons_attacker_ip(self):
        self.require_case()
        _, out, _, _ = self.results["netlogons"]
        self.assertIn("192.168.222.200", out)
        line = [l for l in out.splitlines() if "192.168.222.200" in l
                and "attack$" in l]
        self.assertTrue(line, "应聚合出 .200 的 RDP 成功登录")
        self.assertIn("2020-07-22 10:52:06", line[0])

    def test_06_accounts_backdoor_user(self):
        self.require_case()
        rc, out, _, _ = self.results["accounts"]
        self.assertEqual(rc, 0)
        self.assertIn("=== ACCOUNT EVENTS (%d) ===" % CASE_ACCOUNT_EVENTS, out)
        self.assertIn("ID=4720", out)
        self.assertIn("TargetUserName = attack$", out)
        self.assertIn("S-1-5-32-544", out)
        self.assertIn("member=-", out)

    def test_07_tasks_parsed_xml(self):
        self.require_case()
        rc, out, _, _ = self.results["tasks"]
        self.assertEqual(rc, 0)
        self.assertIn("=== TASK / SERVICE EVENTS (%d) ===" % CASE_TASK_EVENTS, out)
        self.assertIn("TaskName = \\callback", out)
        self.assertIn("Command : c:\\windows\\system32\\windows_attack.exe", out)
        self.assertIn("interval=PT1M", out)
        self.assertIn("RunAs   : ADOFLMB\\WIN-WH8G5MDPHE5$", out)
        self.assertIn("VaiGekem", out)

    def test_08_dump_selected_ids(self):
        self.require_case()
        rc, out, _, _ = self.results["dump"]
        self.assertEqual(rc, 0)
        self.assertEqual(count_headers(out), CASE_DUMP_4624_4648)
        self.assertIn("ID=4648", out)
        self.assertIn("TargetUserName = attack$", out)

    def test_09_dump_single_id(self):
        self.require_case()
        rc, out, _, _ = run(["-Path", self.case, "-Mode", "dump", "-Ids", "4698"])
        self.assertEqual(rc, 0)
        self.assertEqual(count_headers(out), 1)
        self.assertIn("TaskName = \\callback", out)

    def test_10_all_mode_artifacts(self):
        self.require_case()
        out_dir = self.tmpdir("all_out")
        rc, out, err, elapsed = run(["-Path", self.case, "-Mode", "all",
                                     "-Out", out_dir])
        self.assertEqual(rc, 0, err)
        self.assertIn("all artifacts in", out)
        for name in ("logons.csv", "netlogons.csv", "accounts.txt",
                     "tasks.txt", "dump_4624-4625-4648-4672-4688-1102.txt"):
            path = out_dir / name
            self.assertTrue(path.exists(), "%s 未生成" % name)
            self.assertGreater(path.stat().st_size, 0)
        self.assertLess(elapsed, 120, "all 模式耗时 %.1fs" % elapsed)


class TestBoundary(Base):
    """边界：坏输入、损坏日志、参数异常。"""

    def test_01_missing_path(self):
        rc, _, err, _ = run(["-Path", self.tmp / "nope.evtx", "-Mode", "summary"])
        self.assertEqual(rc, 1)
        self.assertIn("No .evtx found", err)

    def test_02_empty_directory(self):
        rc, _, err, _ = run(["-Path", self.tmpdir("empty"), "-Mode", "summary"])
        self.assertEqual(rc, 1)
        self.assertIn("No .evtx found", err)

    def test_03_garbage_file(self):
        path = self.tmp / "garbage.evtx"
        path.write_text("this is not an evtx file\n" * 10)
        rc, _, err, _ = run(["-Path", path, "-Mode", "summary"])
        self.assertEqual(rc, 2)
        self.assertFalse(has_traceback(err))
        self.assertIn("No events parsed", err)

    def test_04_zero_byte_file(self):
        path = self.tmp / "zero.evtx"
        path.write_bytes(b"")
        rc, _, err, _ = run(["-Path", path, "-Mode", "summary"])
        self.assertEqual(rc, 2)
        self.assertFalse(has_traceback(err))

    def test_05_truncated_header(self):
        self.require_case()
        data = Path(self.case).read_bytes()
        path = self.tmp / "truncated.evtx"
        path.write_bytes(data[:4096])
        rc, _, err, _ = run(["-Path", path, "-Mode", "summary"])
        self.assertEqual(rc, 2)
        self.assertFalse(has_traceback(err))

    def test_06_mid_truncation_is_partial(self):
        self.require_case()
        data = Path(self.case).read_bytes()
        path = self.tmp / "mid_cut.evtx"
        path.write_bytes(data[: int(len(data) * 0.6)])
        rc, out, err, _ = run(["-Path", path, "-Mode", "summary"])
        self.assertFalse(has_traceback(err))
        self.assertEqual(rc, 0, "截断文件仍应输出已读到的部分结果")
        self.assertIn("PARTIAL", err)
        self.assertNotIn("Events      : 0", out)

    def test_06b_byte_corruption_does_not_crash(self):
        self.require_system()
        data = bytearray(self.system_sample.read_bytes())
        start = int(len(data) * 0.55)
        for i in range(start, min(start + 8192, len(data))):
            data[i] ^= 0xFF
        path = self.tmp / "flipped.evtx"
        path.write_bytes(bytes(data))
        rc, _, err, _ = run(["-Path", path, "-Mode", "summary"])
        self.assertFalse(has_traceback(err))
        self.assertIn(rc, (0, 2))

    def test_07_max_events(self):
        self.require_case()
        rc, out, _, _ = run(["-Path", self.case, "-Mode", "summary",
                             "-MaxEvents", "100"])
        self.assertEqual(rc, 0)
        self.assertIn("Events      : 100", out)

    def test_08_max_events_negative_is_unlimited(self):
        self.require_system()
        rc, out, _, _ = run(["-Path", self.system_sample, "-Mode", "summary",
                             "-MaxEvents", "-5"])
        self.assertEqual(rc, 0)
        self.assertIn("Events      : 457", out)

    def test_09_directory_batch_with_garbage(self):
        self.require_system()
        batch = self.tmpdir("batch")
        shutil.copyfile(self.system_sample, batch / "a.evtx")
        shutil.copyfile(self.system_sample, batch / "b.evtx")
        (batch / "junk.evtx").write_text("junk")
        rc, out, err, _ = run(["-Path", batch, "-Mode", "summary"])
        self.assertEqual(rc, 0)
        self.assertIn("input: 3 file(s)", out)
        self.assertIn("Events      : 914", out)
        self.assertTrue("cannot open" in err or "read aborted" in err,
                        "损坏文件应产生告警")

    def test_10_uppercase_extension(self):
        self.require_system()
        batch = self.tmpdir("upper")
        shutil.copyfile(self.system_sample, batch / "SHOUT.EVTX")
        rc, out, _, _ = run(["-Path", batch, "-Mode", "summary"])
        self.assertEqual(rc, 0)
        self.assertIn("Events      : 457", out)

    def test_11_chinese_path(self):
        self.require_system()
        folder = self.tmpdir("中文 目录")
        target = folder / "系统日志.evtx"
        shutil.copyfile(self.system_sample, target)
        rc, out, _, _ = run(["-Path", target, "-Mode", "summary"])
        self.assertEqual(rc, 0)
        self.assertIn("Events      : 457", out)

    def test_12_nested_out_dir(self):
        self.require_system()
        target = self.tmp / "deep" / "a" / "b"
        rc, _, err, _ = run(["-Path", self.system_sample, "-Mode", "logons",
                             "-Out", target])
        self.assertEqual(rc, 0, err)
        self.assertTrue((target / "logons.csv").exists())

    def test_13_invalid_mode(self):
        rc, _, err, _ = run(["-Path", self.tmp, "-Mode", "bogus"])
        self.assertEqual(rc, 2)
        self.assertIn("invalid choice", err)
        self.assertFalse(has_traceback(err))

    def test_14_dump_without_ids(self):
        rc, _, err, _ = run(["-Path", self.tmp, "-Mode", "dump"])
        self.assertEqual(rc, 2)
        self.assertIn("-Mode dump needs -Ids", err)

    def test_15_invalid_event_id_warns(self):
        self.require_system()
        rc, out, err, _ = run(["-Path", self.system_sample, "-Mode", "dump",
                               "-Ids", "7045,abc,999999"])
        self.assertEqual(rc, 0)
        self.assertIn("ignoring invalid EventID: abc", err)
        self.assertEqual(count_headers(out), 7)

    def test_16_deterministic_output(self):
        self.require_system()
        first = run(["-Path", self.system_sample, "-Mode", "summary"])
        second = run(["-Path", self.system_sample, "-Mode", "summary"])
        self.assertEqual(stable_lines(first[1]), stable_lines(second[1]))

    def test_17_ids_space_separated(self):
        self.require_system()
        comma = run(["-Path", self.system_sample, "-Mode", "dump", "-Ids", "7045,7040"])
        space = run(["-Path", self.system_sample, "-Mode", "dump", "-Ids", "7045 7040"])
        self.assertEqual(stable_lines(comma[1]), stable_lines(space[1]))

    def test_18_direct_file_no_extension(self):
        self.require_system()
        target = self.tmp / "renamed_log"
        shutil.copyfile(self.system_sample, target)
        rc, out, _, _ = run(["-Path", target, "-Mode", "summary"])
        self.assertEqual(rc, 0)
        self.assertIn("Events      : 457", out)

    def test_19_max_events_zero(self):
        self.require_system()
        rc, out, _, _ = run(["-Path", self.system_sample, "-Mode", "summary",
                             "-MaxEvents", "0"])
        self.assertEqual(rc, 0)
        self.assertIn("Events      : 457", out)


class TestDataQuality(Base):
    """数据质量：CSV 结构、编码、正文完整性。"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.out = None
        if cls.case:
            cls.out = Path(tempfile.mkdtemp(prefix="wlf-csv-"))
            run(["-Path", cls.case, "-Mode", "logons", "-Out", cls.out])
            run(["-Path", cls.case, "-Mode", "netlogons", "-Out", cls.out])
            run(["-Path", cls.case, "-Mode", "accounts", "-Out", cls.out])
            run(["-Path", cls.case, "-Mode", "tasks", "-Out", cls.out])

    @classmethod
    def tearDownClass(cls):
        if cls.out and cls.out.exists():
            shutil.rmtree(cls.out, ignore_errors=True)
        super().tearDownClass()

    def test_01_csv_bom(self):
        self.require_case()
        raw = (self.out / "logons.csv").read_bytes()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), "CSV 应带 UTF-8 BOM")

    def test_02_csv_header_order(self):
        self.require_case()
        with open(self.out / "logons.csv", encoding="utf-8-sig", newline="") as fh:
            header = next(csv.reader(fh))
        self.assertEqual(header, [
            "Time", "EventId", "RecordId", "TargetUserName", "TargetDomainName",
            "LogonType", "IpAddress", "IpPort", "WorkstationName", "ProcessName",
            "AuthenticationPackageName", "Status", "SubStatus", "TargetLogonId"])

    def test_03_csv_row_count(self):
        self.require_case()
        with open(self.out / "logons.csv", encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), CASE_LOGON_ROWS)
        self.assertTrue(all(r["EventId"] in ("4624", "4625") for r in rows))

    def test_04_netlogons_csv_no_loopback(self):
        self.require_case()
        with open(self.out / "netlogons.csv", encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), CASE_NETLOGON_ROWS)
        self.assertNotIn("127.0.0.1", {r["IpAddress"] for r in rows})
        self.assertNotIn("::1", {r["IpAddress"] for r in rows})
        self.assertIn("192.168.222.200", {r["IpAddress"] for r in rows})

    def test_05_accounts_txt_integrity(self):
        self.require_case()
        text = (self.out / "accounts.txt").read_text(encoding="utf-8")
        self.assertEqual(text.count("========== ID="), CASE_ACCOUNT_EVENTS)
        self.assertEqual(text.count("[fields]"), CASE_ACCOUNT_EVENTS)
        self.assertIn("subject=ADOFLMB\\WIN-WH8G5MDPHE5$", text)
        self.assertIn("target=ADOFLMB\\attack$", text)
        self.assertIn("target=Builtin\\Administrators", text)
        self.assertIn("S-1-5-32-544", text)
        self.assertIn("MemberSid = S-1-5-21-867333373-202576419-2389709931-1103", text)

    def test_06_tasks_txt_integrity(self):
        self.require_case()
        text = (self.out / "tasks.txt").read_text(encoding="utf-8")
        self.assertEqual(text.count("========== ID="), CASE_TASK_EVENTS)
        self.assertIn("Command : c:\\windows\\system32\\windows_attack.exe", text)
        self.assertIn("Trigger : 2020-07-22T10:51:00  interval=PT1M", text)
        self.assertIn("Author  : SYSTEM", text)

    def test_07_task_xml_parse_failure_is_graceful(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import parse_evtx
        self.assertIsNone(parse_evtx.parse_task_xml("<Task><broken>"))
        info = parse_evtx.parse_task_xml(
            '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<RegistrationInfo><Author>SYSTEM</Author></RegistrationInfo>'
            '<Actions><Exec><Command>a.exe</Command><Arguments>-x</Arguments>'
            '</Exec></Actions></Task>')
        self.assertEqual(info["commands"], [("a.exe", "-x")])
        self.assertEqual(info["author"], "SYSTEM")

    def test_08_console_table_not_truncated_csv(self):
        self.require_case()
        with open(self.out / "logons.csv", encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
        longest = max(len(r["ProcessName"]) for r in rows)
        self.assertGreater(longest, 20, "CSV 应保留完整进程路径")


class TestMultiChannel(Base):
    """多通道：System 7045、TerminalServices、无账户事件通道。"""

    def test_01_system_summary(self):
        self.require_system()
        rc, out, _, _ = run(["-Path", self.system_sample, "-Mode", "summary"])
        self.assertEqual(rc, 0)
        self.assertIn("Events      : 457", out)
        self.assertIn("System", out)

    def test_02_system_7045_service(self):
        self.require_system()
        rc, out, _, _ = run(["-Path", self.system_sample, "-Mode", "tasks"])
        self.assertEqual(rc, 0)
        self.assertIn("=== TASK / SERVICE EVENTS (7) ===", out)
        self.assertIn("ID=7045", out)
        self.assertIn("ImagePath = \\SystemRoot\\System32\\drivers\\netkvm.sys", out)
        self.assertIn("ServiceName = Google Update Service (gupdate)", out)

    def test_03_termsvc_channel(self):
        self.require_termsvc()
        rc, out, _, _ = run(["-Path", self.termsvc_sample, "-Mode", "summary"])
        self.assertEqual(rc, 0)
        self.assertIn("1774", out)
        self.assertIn("Microsoft-Windows-TerminalServices-RemoteConnect", out)
        self.assertIn("1149", out)

    def test_04_non_security_channel_has_no_accounts(self):
        self.require_termsvc()
        rc, out, _, _ = run(["-Path", self.termsvc_sample, "-Mode", "accounts"])
        self.assertEqual(rc, 0)
        self.assertIn("=== ACCOUNT EVENTS (0) ===", out)

    def test_05_directory_mixed_channels(self):
        self.require_system()
        self.require_termsvc()
        mixed = self.tmpdir("mixed")
        shutil.copyfile(self.system_sample, mixed / "System.evtx")
        shutil.copyfile(self.termsvc_sample, mixed / "Rdp.evtx")
        rc, out, _, _ = run(["-Path", mixed, "-Mode", "summary"])
        self.assertEqual(rc, 0)
        self.assertIn("input: 2 file(s)", out)
        self.assertIn("Events      : 2231", out)


class TestPerformance(Base):
    """性能：大体量解析与全量导出耗时。"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.summary_time = None
        if cls.case:
            rc, _out, _err, elapsed = run(
                ["-Path", cls.case, "-Mode", "summary"])
            cls.summary_time = elapsed if rc == 0 else None

    def test_01_summary_under_30s(self):
        self.require_case()
        self.assertIsNotNone(self.summary_time)
        print("\n    [perf] summary %d events: %.2fs"
              % (CASE_TOTAL, self.summary_time))
        self.assertLess(self.summary_time, 30)

    def test_02_all_under_120s(self):
        self.require_case()
        out_dir = self.tmpdir("perf_all")
        rc, _, _, elapsed = run(["-Path", self.case, "-Mode", "all",
                                 "-Out", out_dir])
        print("    [perf] all mode: %.2fs" % elapsed)
        self.assertEqual(rc, 0)
        self.assertLess(elapsed, 120)


class TestCrossValidation(Base):
    """交叉验证：与独立解析器 / Windows 版基准值比对。"""

    def test_01_record_count_vs_chunk_headers(self):
        """绕过 python-evtx，直接从 chunk 头的首/末记录号统计条数。"""
        self.require_case()
        data = Path(self.case).read_bytes()
        self.assertEqual(data[:8], b"ElfFile\x00")
        total = 0
        offset = 4096
        while offset + 512 <= len(data):
            if data[offset:offset + 8] != b"ElfChnk\x00":
                break
            first, last = struct.unpack_from("<QQ", data, offset + 8)
            total += last - first + 1
            offset += 65536
        self.assertEqual(total, CASE_TOTAL)

    def test_02_counts_match_windows_baseline(self):
        self.require_case()
        _rc, out, _, _ = run(["-Path", self.case, "-Mode", "dump",
                              "-Ids", "4624,4625"])
        self.assertEqual(count_headers(out), CASE_LOGON_ROWS)

    def test_03_summary_matches_dump_count(self):
        self.require_case()
        rc, out, _, _ = run(["-Path", self.case, "-Mode", "summary"])
        self.assertEqual(rc, 0)
        line = [l for l in out.splitlines() if l.startswith("Events      :")]
        self.assertEqual(int(line[0].split(":")[1]), CASE_TOTAL)


def main():
    if not SCRIPT.exists():
        sys.exit("找不到 %s" % SCRIPT)
    if locate_case() is None:
        print("WARN: 未找到样本文件，功能/性能/交叉验证用例将 SKIP\n")
    unittest.main(verbosity=2)


if __name__ == "__main__":
    main()
