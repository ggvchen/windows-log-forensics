#!/usr/bin/env python3
"""
Windows EVTX forensic parser for Security / System / Sysmon / TerminalServices logs.

macOS / Linux port of scripts/parse_evtx.ps1. Same CLI, same seven modes, same
output artifacts; the only intended difference is that event prose comes from the
Windows message DLLs, which do not exist off-Windows, so full messages are rendered
as structured field blocks instead.

Modes:
  summary    Event volume, time range, host, EventID histogram
  logons     Structured 4624/4625 table (LogonType, user, source IP, port, process)
  netlogons  Only logons carrying a real remote IP, grouped by IP/type/user
  accounts   Account lifecycle events with all fields (4720/4722/4732/4738/...)
  tasks      4698/4697/4702/7045 scheduled tasks and service installs, parsed task XML
  dump       All fields of any EventIDs given via -Ids
  all        summary + logons.csv + accounts.txt + tasks.txt + netlogons.csv into -Out

Requires: Python 3.8+ and `python3 -m pip install python-evtx`
"""

import argparse
import csv
import os
import re
import sys
import time
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

try:
    from Evtx.Evtx import Evtx
except ImportError:  # pragma: no cover - dependency guard
    sys.stderr.write(
        "ERROR: python-evtx is required. Install it with:\n"
        "  python3 -m pip install --user python-evtx\n"
    )
    sys.exit(2)

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

ACCOUNT_IDS = (4720, 4721, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732,
               4733, 4734, 4735, 4738, 4740, 4756, 4757, 4767, 4780, 4781)
TASK_IDS = (4698, 4699, 4700, 4702, 4697, 7045, 7000, 7009, 106, 200, 201)
LOGON_IDS = (4624, 4625)

LOGON_CSV_FIELDS = [
    "TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "IpPort",
    "WorkstationName", "ProcessName", "AuthenticationPackageName",
    "Status", "SubStatus", "TargetLogonId",
]

_EPOCH = datetime.min.replace(tzinfo=timezone.utc)
UTC = False


def warn(msg):
    sys.stderr.write("WARNING: %s\n" % msg)


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def parse_time(raw):
    """Parse SystemTime (UTC) and convert to the local timezone."""
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone()


def fmt_time(ev, use_utc=False):
    dt = ev["time"]
    if dt is None:
        return ""
    if use_utc:
        dt = ev["_utc"]
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def flatten_userdata(root):
    out = {}
    for node in root.iter():
        if node is root:
            continue
        if not list(node):
            text = (node.text or "").strip()
            if text:
                out[local_name(node.tag)] = text
    return out


def event_from_record(rec):
    root = ET.fromstring(rec.xml())
    system = root.find(NS + "System")
    if system is None:
        raise ValueError("no <System> section")
    eid_text = system.findtext(NS + "EventID")
    if eid_text is None:
        raise ValueError("no EventID")
    created = system.find(NS + "TimeCreated")
    raw_time = created.get("SystemTime") if created is not None else None
    provider = system.find(NS + "Provider")
    data = {}
    for node in root.findall(".//" + NS + "EventData/" + NS + "Data"):
        name = node.get("Name")
        if name:
            data[name] = (node.text or "").strip()
    if not data:
        userdata = root.find(NS + "UserData")
        if userdata is not None:
            data = flatten_userdata(userdata)
    dt = parse_time(raw_time)
    return {
        "id": int(eid_text),
        "record_id": system.findtext(NS + "EventRecordID") or "",
        "time": dt,
        "_utc": dt.astimezone(timezone.utc) if dt else None,
        "channel": system.findtext(NS + "Channel") or "",
        "computer": system.findtext(NS + "Computer") or "",
        "provider": provider.get("Name") if provider is not None else "",
        "data": data,
    }


def collect_files(path):
    if os.path.isdir(path):
        names = [n for n in sorted(os.listdir(path)) if n.lower().endswith(".evtx")]
        return [os.path.join(path, n) for n in names
                if os.path.isfile(os.path.join(path, n))]
    return [path] if os.path.isfile(path) else []


def structural_damage(path):
    """A complete .evtx is 4096-byte file header + N whole 64 KiB chunks.

    Sizes that do not fit that shape mean the file was truncated or partially
    dumped; results are then partial even if the parser never raises.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    return size >= 4096 and (size - 4096) % 65536 != 0


def read_events(files, cap=0):
    events = []
    damaged = []
    for path in files:
        short = structural_damage(path)
        try:
            fh = Evtx(path)
            fh.__enter__()
        except Exception as exc:
            warn("cannot open %s: %s" % (path, exc))
            damaged.append(path)
            continue
        n = 0
        broken = False
        try:
            iterator = fh.records()
            while True:
                try:
                    rec = next(iterator)
                except StopIteration:
                    break
                except Exception as exc:
                    warn("%s: read aborted after %d events - %s" % (path, n, exc))
                    broken = True
                    break
                n += 1
                if cap > 0 and n > cap:
                    break
                try:
                    events.append(event_from_record(rec))
                except ET.ParseError as exc:
                    warn("%s: unreadable XML at record #%d - %s" % (path, n, exc))
                    broken = True
                    break
                except Exception as exc:
                    warn("%s: skipped record #%d - %s" % (path, n, exc))
                    continue
        finally:
            try:
                fh.__exit__(None, None, None)
            except Exception:
                pass
        if short:
            warn("%s: PARTIAL results, log file is truncated or damaged" % path)
            damaged.append(path)
        elif broken:
            warn("%s: PARTIAL results, log file is damaged" % path)
            damaged.append(path)
    events.sort(key=lambda e: e["time"] or _EPOCH)
    return events, damaged


def make_table(headers, rows, max_col=48):
    cells = [[str(h) for h in headers]]
    for row in rows:
        cells.append([("" if v is None else str(v))[:max_col] for v in row])
    widths = [max(len(r[i]) for r in cells) for i in range(len(headers))]
    lines = ["  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip()
             for r in cells]
    sep = "  ".join("-" * w for w in widths)
    return "\n".join([lines[0], sep] + lines[1:])


def field_block(ev, skip=()):
    lines = []
    for key, value in ev["data"].items():
        if value and key not in skip:
            lines.append("  %s = %s" % (key, value))
    return "\n".join(lines)


def parse_task_xml(xml_text):
    try:
        root = ET.fromstring(xml_text.strip())
    except ET.ParseError:
        return None
    info = {"commands": [], "triggers": [], "author": "", "runas": ""}
    for node in root.iter():
        name = local_name(node.tag)
        parent = None
        if name == "Exec":
            cmd = args = ""
            for child in node:
                if local_name(child.tag) == "Command":
                    cmd = (child.text or "").strip()
                elif local_name(child.tag) == "Arguments":
                    args = (child.text or "").strip()
            info["commands"].append((cmd, args))
        elif name == "TimeTrigger":
            start = interval = ""
            for child in node.iter():
                if local_name(child.tag) == "StartBoundary":
                    start = (child.text or "").strip()
                elif local_name(child.tag) == "Interval":
                    interval = (child.text or "").strip()
            info["triggers"].append((start, interval))
        elif name == "Author" and not info["author"]:
            info["author"] = (node.text or "").strip()
        elif name == "UserId" and not info["runas"]:
            info["runas"] = (node.text or "").strip()
    return info


# ---------------------------------------------------------------- modes

def show_summary(events, out):
    print("")
    print("=== SUMMARY ===")
    print("Events      : %d" % len(events))
    if events:
        print("First       : %s" % fmt_time(events[0], UTC))
        print("Last        : %s" % fmt_time(events[-1], UTC))
    hosts = {}
    for ev in events:
        hosts[ev["computer"]] = hosts.get(ev["computer"], 0) + 1
    if hosts:
        top = sorted(hosts.items(), key=lambda kv: -kv[1])[0]
        print("Host        : %s  (%d events)" % (top[0] or "-", top[1]))
    print("")
    print("--- EventID histogram (top 40) ---")
    ids = {}
    for ev in events:
        ids[ev["id"]] = ids.get(ev["id"], 0) + 1
    rows = [(c, i) for i, c in sorted(ids.items(), key=lambda kv: -kv[1])[:40]]
    print(make_table(["Count", "EventId"], rows))
    print("--- Channel histogram ---")
    chans = {}
    for ev in events:
        chans[ev["channel"]] = chans.get(ev["channel"], 0) + 1
    rows = [(c, ch) for ch, c in sorted(chans.items(), key=lambda kv: -kv[1])]
    print(make_table(["Count", "Name"], rows))


def logon_rows(events):
    rows = []
    for ev in events:
        if ev["id"] not in LOGON_IDS:
            continue
        row = {"Time": fmt_time(ev, UTC), "EventId": ev["id"],
               "RecordId": ev["record_id"]}
        for field in LOGON_CSV_FIELDS:
            row[field] = ev["data"].get(field, "") or ""
        rows.append(row)
    return rows


def csv_header():
    return ["Time", "EventId", "RecordId"] + LOGON_CSV_FIELDS


def write_csv(path, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
        writer.writerow(csv_header())
        for row in rows:
            writer.writerow([row.get(h, "") for h in csv_header()])
    print("[+] wrote %s" % path)


def show_logons(events, out_dir):
    rows = logon_rows(events)
    print("")
    print("=== LOGONS (%d rows) ===" % len(rows))
    table = [(r["Time"], r["EventId"], r["LogonType"], r["TargetUserName"],
              r["IpAddress"], r["IpPort"], r["ProcessName"]) for r in rows]
    print(make_table(["Time", "EventId", "LogonType", "TargetUserName",
                      "IpAddress", "IpPort", "ProcessName"], table))
    if out_dir:
        write_csv(os.path.join(out_dir, "logons.csv"), rows)


def show_netlogons(events, out_dir):
    rows = [r for r in logon_rows(events)
            if r["IpAddress"] and r["IpAddress"] not in ("-", "::1", "127.0.0.1")]
    print("")
    print("=== REMOTE LOGONS (%d rows, excluding loopback) ===" % len(rows))
    groups = {}
    for row in rows:
        key = (row["IpAddress"], row["EventId"], row["LogonType"],
               row["TargetUserName"])
        groups.setdefault(key, []).append(row)
    summary = []
    for key, group in groups.items():
        group.sort(key=lambda r: r["Time"])
        summary.append((len(group), key[0], key[1], key[2], key[3],
                        group[0]["TargetDomainName"], group[0]["Time"],
                        group[-1]["Time"]))
    summary.sort(key=lambda r: (r[7], r[0]), reverse=True)
    print(make_table(["Count", "Ip", "EventId", "LogonType", "User", "Domain",
                      "First", "Last"], summary))
    if out_dir:
        write_csv(os.path.join(out_dir, "netlogons.csv"), rows)


def write_text(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("[+] wrote %s" % path)


def show_accounts(events, out_dir):
    buf = []
    n = 0
    for ev in events:
        if ev["id"] not in ACCOUNT_IDS:
            continue
        n += 1
        buf.append("========== ID=%d  Time=%s  RecordId=%s =========="
                   % (ev["id"], fmt_time(ev, UTC), ev["record_id"]))
        buf.append(field_block(ev))
        d = ev["data"]
        buf.append("  [fields] subject=%s\\%s target=%s\\%s member=%s group=%s"
                   % (d.get("SubjectDomainName", ""), d.get("SubjectUserName", ""),
                      d.get("TargetDomainName", ""), d.get("TargetUserName", ""),
                      d.get("MemberName", ""), d.get("GroupName", "")))
        buf.append("")
    print("")
    print("=== ACCOUNT EVENTS (%d) ===" % n)
    print("\n".join(buf))
    if out_dir:
        write_text(os.path.join(out_dir, "accounts.txt"), "\n".join(buf))


def show_tasks(events, out_dir):
    buf = []
    n = 0
    for ev in events:
        if ev["id"] not in TASK_IDS:
            continue
        n += 1
        buf.append("========== ID=%d  Time=%s  Channel=%s  RecordId=%s =========="
                   % (ev["id"], fmt_time(ev, UTC), ev["channel"], ev["record_id"]))
        buf.append(field_block(ev, {"TaskContent"}))
        content = ev["data"].get("TaskContent")
        if content:
            buf.append("  --- parsed TaskContent ---")
            info = parse_task_xml(content)
            if info is None:
                buf.append("  (task XML parse failed)")
            else:
                for cmd, args in info["commands"]:
                    buf.append("  Command : %s %s" % (cmd, args))
                for start, interval in info["triggers"]:
                    buf.append("  Trigger : %s  interval=%s" % (start, interval))
                buf.append("  Author  : %s" % info["author"])
                buf.append("  RunAs   : %s" % info["runas"])
        buf.append("")
    print("")
    print("=== TASK / SERVICE EVENTS (%d) ===" % n)
    print("\n".join(buf))
    if out_dir:
        write_text(os.path.join(out_dir, "tasks.txt"), "\n".join(buf))


def show_dump(events, wanted, out_dir):
    buf = []
    n = 0
    for ev in events:
        if ev["id"] not in wanted:
            continue
        n += 1
        buf.append("========== ID=%d  Time=%s  RecordId=%s  Channel=%s =========="
                   % (ev["id"], fmt_time(ev, UTC), ev["record_id"], ev["channel"]))
        buf.append(field_block(ev))
        buf.append("")
    print("")
    print("=== DUMP ids [%s] -> %d events ==="
          % (",".join(str(i) for i in wanted), n))
    print("\n".join(buf))
    if out_dir:
        write_text(os.path.join(out_dir, "dump_%s.txt"
                                 % "-".join(str(i) for i in wanted)), "\n".join(buf))


# ---------------------------------------------------------------- main

def split_ids(raw):
    wanted, bad = [], []
    for item in raw:
        for part in re.split(r"[,\s]+", str(item)):
            part = part.strip()
            if not part:
                continue
            try:
                wanted.append(int(part))
            except ValueError:
                bad.append(part)
    for item in bad:
        warn("ignoring invalid EventID: %s" % item)
    return wanted


def main(argv=None):
    global UTC
    parser = argparse.ArgumentParser(
        description="Windows EVTX forensic parser (macOS/Linux port)")
    parser.add_argument("-Path", "--path", required=True,
                        help="a .evtx file, or a directory containing .evtx files")
    parser.add_argument("-Mode", "--mode", default="summary",
                        choices=["summary", "logons", "netlogons", "accounts",
                                 "tasks", "dump", "all"])
    parser.add_argument("-Ids", "--ids", action="append", default=[],
                        help="comma or space separated EventIDs for -Mode dump")
    parser.add_argument("-Out", "--out", default="",
                        help="output directory, default <log dir>/analysis_out")
    parser.add_argument("-MaxEvents", "--max-events", type=int, default=0,
                        help="per-file event cap for quick triage")
    parser.add_argument("-Utc", "--utc", action="store_true",
                        help="print timestamps in UTC instead of local time")
    args = parser.parse_args(argv)
    UTC = args.utc

    wanted = split_ids(args.ids)
    if args.mode == "dump" and not wanted:
        parser.error("-Mode dump needs -Ids (e.g. -Ids 4624,4648)")

    files = collect_files(args.path)
    if not files:
        sys.stderr.write("ERROR: No .evtx found at %s\n" % args.path)
        return 1
    print("[*] input: %d file(s)" % len(files))

    started = time.time()
    events, _damaged = read_events(files, args.max_events)
    print("[*] parsed: %d events in %.2fs" % (len(events), time.time() - started))
    if not events:
        warn("No events parsed. Check that the file is a valid .evtx (unzip first).")
        return 2

    if args.mode == "all":
        out_dir = args.out
        if not out_dir:
            out_dir = os.path.join(os.path.dirname(os.path.abspath(files[0])),
                                   "analysis_out")
        os.makedirs(out_dir, exist_ok=True)
        out_dir = os.path.abspath(out_dir)
        show_summary(events, out_dir)
        show_netlogons(events, out_dir)
        show_logons(events, out_dir)
        show_accounts(events, out_dir)
        show_tasks(events, out_dir)
        show_dump(events, [4624, 4625, 4648, 4672, 4688, 1102], out_dir)
        print("")
        print("[*] all artifacts in %s" % out_dir)
        return 0

    out_dir = ""
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        out_dir = os.path.abspath(args.out)

    if args.mode == "summary":
        show_summary(events, out_dir)
    elif args.mode == "logons":
        show_logons(events, out_dir)
    elif args.mode == "netlogons":
        show_netlogons(events, out_dir)
    elif args.mode == "accounts":
        show_accounts(events, out_dir)
    elif args.mode == "tasks":
        show_tasks(events, out_dir)
    elif args.mode == "dump":
        show_dump(events, wanted, out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
