# hive-blocklist

IP addresses that attacked the [hive](https://github.com/itsF4LCON/hive) honeypot in the last 7 days, updated every
Monday. hive is a low-interaction honeypot that pretends to be an SSH server and a forgotten nginx box. It has no
real users and advertises nothing, so every connection to it is unsolicited.

Weekly write-ups are at [xivlabs.tech/reports](https://xivlabs.tech/reports.html).

## What's on the list

- An address is listed when it made **3 or more** SSH login attempts or web probes in the last 7 days.
- Private, reserved and documentation ranges are never listed.
- **Entries expire on their own.** Each update is a fresh 7-day window, so an address drops off a week after it
  stops attacking. That keeps dynamic and reassigned IPs from staying blocked forever.
- At most 5,000 addresses, busiest first.

## Lists

| File | Format |
|---|---|
| [`lists/ips.txt`](lists/ips.txt) | One address per line, IPv4 and IPv6, `#` comments at the top |
| [`lists/ipv4.txt`](lists/ipv4.txt) / [`lists/ipv6.txt`](lists/ipv6.txt) | The same, split by family |
| [`lists/ips.json`](lists/ips.json) | Each address with SSH and HTTP hit counts and when it was last seen |
| [`lists/nginx-deny.conf`](lists/nginx-deny.conf) | `deny` lines for nginx |
| [`lists/ipset.txt`](lists/ipset.txt) | `ipset restore` input for sets `hive-blocklist` and `hive-blocklist6` |

Raw URL: `https://raw.githubusercontent.com/itsF4LCON/hive-blocklist/main/lists/ips.txt`

`archive/` keeps each week's list and `reports/` keeps the numbers behind each weekly post.

## Usage

**iptables with ipset**
```bash
curl -fsSL https://raw.githubusercontent.com/itsF4LCON/hive-blocklist/main/lists/ipset.txt | sudo ipset restore
sudo iptables  -I INPUT -m set --match-set hive-blocklist  src -j DROP
sudo ip6tables -I INPUT -m set --match-set hive-blocklist6 src -j DROP
```
Run the first line weekly (cron or a systemd timer) to refresh the sets. The rules only need adding once.

**nginx**
```bash
sudo curl -fsSL -o /etc/nginx/hive-deny.conf https://raw.githubusercontent.com/itsF4LCON/hive-blocklist/main/lists/nginx-deny.conf
# add `include /etc/nginx/hive-deny.conf;` inside your server block, then:
sudo nginx -t && sudo systemctl reload nginx
```

**Firewalls and other tools**: pfSense/OPNsense URL table aliases, MikroTik address lists and CrowdSec can all
read `lists/ips.txt` directly.

## Caveats

Use it at your own risk. These addresses attacked one honeypot, and some of them are shared, hijacked or
reassigned machines. Test the list before you block production traffic with it.

If you think your address is listed by mistake, [open an issue](https://github.com/itsF4LCON/hive-blocklist/issues).
Entries also expire by themselves 7 days after the last attack.

## How it's built

The hive sensor counts attempts per address on its VM and sends the list to the hive Worker once an hour.
[`weekly.yml`](.github/workflows/weekly.yml) runs every Monday at 00:30 UTC: it fetches `/export`, runs
[`scripts/build.py`](scripts/build.py) and commits the result. The build fails instead of publishing when the
data is more than 3 hours old.

```bash
python3 scripts/build.py --from scripts/fixtures/export.json --out /tmp/hive-blocklist   # try it locally
```

## License

The lists, reports and scripts are released into the public domain under [CC0 1.0](LICENSE). Use them however you
like; no credit needed.
