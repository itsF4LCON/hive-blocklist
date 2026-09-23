#!/usr/bin/env python3
import argparse
import datetime as dt
import ipaddress
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

EXPORT_URL = "https://hive.xivlabs.tech/export"
MAX_AGE_SECS = 3 * 3600
REPO = "itsF4LCON/hive-blocklist"
RAW = f"https://raw.githubusercontent.com/{REPO}/main"


def fetch(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "User-Agent": "hive-blocklist"})
    with urllib.request.urlopen(req, timeout=30) as res:
        return json.load(res)


def fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def pct(now, before):
    if not before:
        return None
    return round((now - before) / before * 100, 1)


def clean_entries(raw):
    out, seen = [], set()
    for e in raw:
        try:
            ip = ipaddress.ip_address(str(e["ip"]).strip())
        except (KeyError, ValueError):
            continue
        if not ip.is_global or str(ip) in seen:
            continue
        seen.add(str(ip))
        out.append({"ip": str(ip), "ssh": int(e.get("ssh", 0)), "http": int(e.get("http", 0)),
                    "last_seen": int(e.get("last_seen", 0))})
    out.sort(key=lambda e: (-(e["ssh"] + e["http"]), e["ip"]))
    return out


def header(week, generated, count):
    stamp = dt.datetime.fromtimestamp(generated, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (f"# hive blocklist, {week}, generated {stamp}\n"
            f"# {count} addresses seen attacking the hive honeypot in the last 7 days.\n"
            f"# https://github.com/{REPO}\n")


def write_lists(out, week, generated, entries):
    v4 = [e["ip"] for e in entries if ":" not in e["ip"]]
    v6 = [e["ip"] for e in entries if ":" in e["ip"]]
    h = header(week, generated, len(entries))
    lists = out / "lists"
    write(lists / "ips.txt", h + "".join(f"{e['ip']}\n" for e in entries))
    write(lists / "ipv4.txt", h + "".join(f"{ip}\n" for ip in v4))
    write(lists / "ipv6.txt", h + "".join(f"{ip}\n" for ip in v6))
    write(lists / "ips.json", json.dumps({"week": week, "generated_at": generated, "entries": entries}, indent=1) + "\n")
    write(lists / "nginx-deny.conf", h + "".join(f"deny {e['ip']};\n" for e in entries))
    write(lists / "ipset.txt",
          "create hive-blocklist hash:ip family inet maxelem 65536 -exist\nflush hive-blocklist\n"
          + "".join(f"add hive-blocklist {ip}\n" for ip in v4)
          + "create hive-blocklist6 hash:ip family inet6 maxelem 65536 -exist\nflush hive-blocklist6\n"
          + "".join(f"add hive-blocklist6 {ip}\n" for ip in v6))
    write(out / "archive" / f"{week}.txt", h + "".join(f"{e['ip']}\n" for e in entries))
    return len(v4), len(v6)


def read_archive(out, week):
    if not week:
        return set()
    path = out / "archive" / f"{week}.txt"
    if not path.exists():
        return set()
    return {l.strip() for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")}


def top(stats, key):
    return [{"k": t.get("k"), "n": t.get("n", 0)} for t in stats.get(key, []) if t.get("k")]


def fmt(n):
    return f"{n:,}"


def highlights(r, prev):
    out = []
    t = r["totals"]
    if prev:
        c = r["change"]["events"]
        if c is not None:
            word = "up" if c >= 0 else "down"
            out.append(f"Attacks were {word} {abs(c)}% from {prev['week']} ({fmt(prev['totals']['events'])} then).")
        out.append(f"{fmt(r['ips']['new'])} addresses are new this week, {fmt(r['ips']['returning'])} came back "
                   f"and {fmt(r['ips']['dropped'])} dropped off the list.")
    else:
        out.append("This is the first weekly report, so there's nothing to compare with yet.")
    if r["top_ips"]:
        b = r["top_ips"][0]
        out.append(f"The busiest address, {b['ip']}, made {fmt(b['ssh'] + b['http'])} attempts.")
    if r["top"]["passwords"]:
        p = r["top"]["passwords"][0]
        out.append(f"The most tried password was \"{p['k']}\" ({fmt(p['n'])} times).")
    if r["top"]["usernames"]:
        u = r["top"]["usernames"][0]
        out.append(f"The most tried username was \"{u['k']}\".")
    if r["top"]["paths"]:
        p = r["top"]["paths"][0]
        out.append(f"The most probed web path was {p['k']} ({fmt(p['n'])} requests).")
    if r["top"]["countries"]:
        c = r["top"]["countries"][0]
        share = round(c["n"] / t["events"] * 100) if t["events"] else 0
        out.append(f"{c['k']} was the top source country, with {share}% of all events.")
    return out


def main():
    ap = argparse.ArgumentParser(description="Build the hive blocklist and weekly report.")
    ap.add_argument("--from", dest="src", help="read an export JSON file instead of fetching")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--allow-stale", action="store_true")
    args = ap.parse_args()

    if args.src:
        data = json.loads(Path(args.src).read_text())
    else:
        token = os.environ.get("HIVE_EXPORT_TOKEN") or fail("HIVE_EXPORT_TOKEN is not set")
        data = fetch(os.environ.get("HIVE_EXPORT_URL", EXPORT_URL), token)

    generated = int(data.get("generated_at") or time.time())
    updated = data.get("blocklist_updated_at")
    stats = data.get("stats") or {}
    if not args.allow_stale:
        if not updated or generated - updated > MAX_AGE_SECS:
            fail("the blocklist hasn't been updated in the last 3 hours; is the sensor running?")
        if generated - stats.get("generated_at", 0) > MAX_AGE_SECS:
            fail("the stats snapshot is more than 3 hours old; is the sensor running?")

    entries = clean_entries(data.get("blocklist") or [])
    end = dt.datetime.fromtimestamp(generated, dt.timezone.utc)
    iso = (end - dt.timedelta(days=1)).isocalendar()
    week = f"{iso.year}-W{iso.week:02d}"
    start = end - dt.timedelta(days=7)

    out = Path(args.out)
    index_path = out / "reports" / "index.json"
    index = [w for w in load_json(index_path, []) if w.get("week") != week]
    older = sorted((w["week"] for w in index if w["week"] < week), reverse=True)
    prev = load_json(out / "reports" / f"{older[0]}.json", None) if older else None

    prev_ips = read_archive(out, prev and prev["week"])
    v4, v6 = write_lists(out, week, generated, entries)
    ips = {e["ip"] for e in entries}

    report = {
        "week": week,
        "period_start": start.strftime("%Y-%m-%d"),
        "period_end": end.strftime("%Y-%m-%d"),
        "generated_at": generated,
        "totals": {"events": stats.get("total_7d", 0), "ips": len(entries), "ipv4": v4, "ipv6": v6,
                   "ssh_ips": sum(1 for e in entries if e["ssh"]), "http_ips": sum(1 for e in entries if e["http"])},
        "change": {"events": pct(stats.get("total_7d", 0), prev and prev["totals"]["events"]),
                   "ips": pct(len(entries), prev and prev["totals"]["ips"])},
        "ips": {"new": len(ips - prev_ips) if prev else len(ips), "returning": len(ips & prev_ips),
                "dropped": len(prev_ips - ips)},
        "previous": prev and prev["week"],
        "top": {k: top(stats, f"top_{k}") for k in ("usernames", "passwords", "paths", "countries", "user_agents")},
        "top_ips": entries[:10],
        "lists": {name: f"{RAW}/lists/{name}" for name in
                  ("ips.txt", "ipv4.txt", "ipv6.txt", "ips.json", "nginx-deny.conf", "ipset.txt")},
    }
    report["highlights"] = highlights(report, prev)
    report["title"] = f"{week}: {fmt(report['totals']['events'])} attacks from {fmt(len(entries))} addresses"
    write(out / "reports" / f"{week}.json", json.dumps(report, indent=1) + "\n")

    index.insert(0, {"week": week, "title": report["title"], "period_start": report["period_start"],
                     "period_end": report["period_end"], "events": report["totals"]["events"],
                     "ips": len(entries), "summary": report["highlights"][0]})
    index.sort(key=lambda w: w["week"], reverse=True)
    write(index_path, json.dumps(index, indent=1) + "\n")
    print(f"{week}: {len(entries)} addresses ({v4} IPv4, {v6} IPv6), {report['totals']['events']} events")


if __name__ == "__main__":
    main()
