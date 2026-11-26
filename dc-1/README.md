# DC-1: Drupalgeddon2 (CVE-2018-7600), from exploit to detection

I first rooted DC-1 with Metasploit's Drupalgeddon2 module. This time I went back and did it from both sides: I wrote my own exploit, captured what it looks like on the wire, and built detections that catch it on the network and in the web server logs. Then I tested those detections against my own earlier attacks, which were still sitting in DC-1's Apache log.

| | |
|---|---|
| **Target** | DC-1 (VulnHub), Drupal 7, `10.0.2.4` |
| **Attacker** | Kali, `10.0.2.3` |
| **Vulnerability** | CVE-2018-7600 (Drupal SA-CORE-2018-002), unauthenticated RCE |
| **Detections** | 3 Suricata rules, 1 Sigma rule |
| **Network result** | Both exploit stages detected, 0 false positives on normal traffic |
| **Log result** | 108 / 108 attack requests detected, 0 false positives on 14 normal requests |

> Everything here was run against my own isolated VirtualBox lab. Drupalgeddon2 has been public since 2018; the point of this write-up is the detection work.

---

## Why Drupalgeddon2 works

Drupal builds every form as a **render array**: a nested PHP array where keys starting with `#` are properties of an element (`#type`, `#markup`, `#post_render`) and keys without `#` are child elements.

Before 7.58, Drupal merged request parameters into these arrays **without stripping keys that start with `#`**. That means an attacker can inject properties, not just values.

The dangerous one is `#post_render`: a list of PHP callbacks Drupal runs on an element's rendered output, as `callback($markup, $element)`. So if I send

```
name[#post_render][]=passthru
name[#markup]=id
```

then rendering the `name` element calls `passthru("id")`, and I have code execution.

On Drupal 7 this takes two requests:

1. **Plant.** POST to `?q=user/password` (the password reset form) with the injected `name[...]` properties. Drupal caches the poisoned form and returns a `form_build_id`.
2. **Trigger.** POST to `?q=file/ajax/name/#value/<form_build_id>`. The file module's AJAX handler reloads a cached form and renders whichever element the path names, which is my poisoned `name`.

The fix in 7.58 was a request sanitiser that strips any parameter key starting with `#`. That told me exactly what to detect: **render-array properties arriving in a request**, plus the `file/ajax ... #value` trigger.

## Recon

`CHANGELOG.txt` returned a 404 because the box author removed it to block the easy version check. The generator meta tag still gave away the major version, which is all the exploit path depends on:

```
curl -s http://10.0.2.4/ | grep -i generator
<meta name="Generator" content="Drupal 7 (http://drupal.org)" />
```

## Writing my own PoC

[`drupalgeddon2.py`](drupalgeddon2.py) does the two stages with `requests`. Stage 1 sends the injected properties in the query string and the normal form fields in the body, then scrapes `form_build_id` out of the response. Stage 2 asks `file/ajax` to render `name` from that cached form. The command output comes back ahead of Drupal's JSON, so I split the response there.

```
python3 drupalgeddon2.py http://10.0.2.4/ id
[+] Stage 1: payload cached, form_build_id = form-zf8rUlNK1s_jh-G5m4zONrEvZPNGBJ1_9jEPmVzT_Jc
[+] Stage 2: command output:

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Capturing the attack

I started a capture before running the exploit:

```
sudo tcpdump -i eth0 -s 0 -w drupalgeddon2.pcap host 10.0.2.4 and tcp port 80
```

21 packets. Both requests used the same source port, so `requests.Session()` sent them over **one keep-alive connection**. Reading the payloads back with `tcpdump -A` showed how they actually look on the wire:

```
POST /?q=user%2Fpassword&name%5B%23post_render%5D%5B%5D=passthru&name%5B%23type%5D=markup&name%5B%23markup%5D=id HTTP/1.1
POST /?q=file%2Fajax%2Fname%2F%23value%2Fform-zf8rUlNK1s_jh-G5m4zONrEvZPNGBJ1_9jEPmVzT_Jc HTTP/1.1
```

Everything is URL-encoded: `#` as `%23`, brackets as `%5B`/`%5D`, and slashes as `%2F`. A rule that matched those raw strings would be easy to dodge with different casing or encoding, so I didn't write one.

## Network detection: Suricata

[`drupalgeddon2.rules`](drupalgeddon2.rules), tested on Suricata 8.0.8:

| SID | Catches | Key logic |
|---|---|---|
| 1000001 | Stage 1, injection in the URI | `http.uri.raw; url_decode; content:"[#post_render]"; nocase;` |
| 1000002 | Stage 1, injection in the body (Drupal 8 style variants) | same, on `http.request_body` |
| 1000003 | Stage 2 trigger | `file/ajax/` followed by `/#value/` in the decoded URI |

Why it's built this way:

- **`url_decode` on the raw URI** decodes once, the same way PHP does. `%5B%23post_render%5D`, `%5b%23post_render%5d` and `[#post_render]` all become the same string, so encoding tricks don't help. Double encoding (`%2523`) isn't a bypass either, because PHP would never see a `#`.
- **`[#post_render]` instead of just `post_render`.** The bracket plus `#` means a render-array property is being set through a request parameter, which legitimate traffic never does. PHP array syntax forces the brackets, so it stays specific without being fragile.
- **Stage 2 stands on its own.** Real Drupal uploads hit `file/ajax/<field>/<delta>/<form_build_id>`, never `#value`, so the trigger is a strong signal even if stage 1 was missed.

Replaying the capture offline (`-k none` because the capture was taken on the sending host, where checksums are offloaded to the NIC):

```
suricata -r drupalgeddon2.pcap -S drupalgeddon2.rules -l suricata-out -k none
[1:1000001:1] LOCAL Drupalgeddon2 CVE-2018-7600 - #post_render injection in URI ... 10.0.2.3:60638 -> 10.0.2.4:80
[1:1000003:1] LOCAL Drupalgeddon2 D7 stage 2 - file/ajax #value trigger ... 10.0.2.3:60638 -> 10.0.2.4:80
```

Both stages alerted on the same flow. 1000002 stayed silent, which is correct because my PoC never puts the payload in the body.

### False-positive test

A rule that fires on every password reset is useless to a SOC, so I captured normal traffic too: the homepage, a content page, the login page, the password reset page, and a **real password reset submission** to the exact URL and form ID that stage 1 abuses.

```
alerts: 0
http transactions seen: 5
```

The second number matters. Zero alerts on its own proves nothing if Suricata failed to parse the traffic. Zero alerts with five parsed HTTP transactions proves it inspected the requests and correctly left them alone.

## Host detection: a Sigma retro-hunt

Network detection needs a sensor on the wire. To catch the attack without one, I wanted a rule for Apache's access log, and to test it properly I needed DC-1's real log. `/var/log/apache2/access.log` is root-only, and my shell was www-data. But DC-1's privilege escalation path is a SUID `find`, so I chained it through my own PoC:

```
python3 drupalgeddon2.py http://10.0.2.4/ "find /etc/passwd -exec grep '26/Nov/2026' /var/log/apache2/access.log \;"
```

The log held every attack ever made against this box, including mine from earlier:

| Date | Activity |
|---|---|
| 14 Sep 2026 | My original Metasploit root of DC-1 |
| 7 Oct 2026 | My pre-exam rerun |
| 26 Nov 2026 | This project: my PoC plus the normal traffic from the false-positive test |

That turned the log into a test set, and it taught me three things about what a rule should **not** rely on:

- **User agent.** Metasploit rotated through six fake browser user agents. Only my PoC said `python-requests`.
- **The callback.** Metasploit used `assert` 27 times and `passthru` 28 times, with payloads ranging from a base64 PHP dropper written to `/tmp` to an `eval(hex2bin(...))` reverse shell back to `10.0.2.3:4444`.
- **Casing.** Metasploit encodes lowercase (`%5b%23`), Python uppercase (`%5B%23`).

### The encoding trap

My first attempt at pulling the log used `grep 'post_render|file/ajax|user/password'`. It returned the stage 1 lines but **none of my own stage 2 requests**. `requests` encodes slashes, Apache logs the raw URI without decoding it, so my stage 2 was recorded as `file%2Fajax%2Fname%2F%23value`, and a search for `file/ajax` walked straight past it.

A Sigma rule matching only the literal `file/ajax` makes the same mistake: on today's traffic it catches **0 of 2** stage 2 requests. Pulling the log by date instead of by attack string is what exposed this.

### The rule

[`drupalgeddon2_webserver.yml`](drupalgeddon2_webserver.yml):

- **Stage 1:** `cs-uri-query` contains `%23post_render`. A raw `#` can't appear in a logged URL, because clients treat it as the start of a fragment and never send it, so in a log it is always `%23`. Sigma's `contains` is case-insensitive, which covers both encoding styles.
- **Stage 2:** the query contains `file/ajax/` **or** `file%2fajax%2f`, together with `%23value`.
- **Clean URLs:** a separate branch for `/file/ajax/ ... %23value` in the path, for sites that don't use `?q=`.
- Tagged ATT&CK **T1190**, Exploit Public-Facing Application.

### Validation

[`tests/eval_sigma.py`](tests/eval_sigma.py) applies the rule's conditions to [`tests/dc1_access.log`](tests/dc1_access.log), field by field, and compares them with a naive version that only matches the literal `file/ajax`. Every line carrying an exploit marker comes from a known run (the two Metasploit sessions and my PoC); everything else is normal browsing.

```
python3 tests/eval_sigma.py tests/dc1_access.log
```

| | Requests | Sigma rule | Naive rule (literal `file/ajax` only) |
|---|---|---|---|
| Attack requests detected | 108 | **108** | 106 |
| Missed | | **0** | 2 (both of my encoded stage 2 requests) |
| False positives on normal requests | 14 | **0** | 0 |

Metasploit never encodes the slashes, which is why the naive rule looks almost fine on the historical data and only fails on my PoC. One tool's habits are not a safe baseline.

## Results

| Layer | Rule | True positives | False positives |
|---|---|---|---|
| Network (Suricata) | 1000001 + 1000003 | 2 / 2 stages | 0 on 5 normal requests |
| Host (Sigma, Apache log) | stage 1 + stage 2, encoded and literal | 108 / 108 | 0 on 14 normal requests |

Covered across Metasploit (lowercase encoding, rotating user agents, `assert` and `passthru`), my own PoC (uppercase encoding, encoded slashes) and legitimate password reset traffic.

## A free hunting heuristic: response size

Stage 2 returns the command output, and it shows in the response size. The `id` run came back at **2,195 bytes**; the run that dumped the access log came back at **130,090 bytes**. A `file/ajax` POST returning over 100 KB is data leaving the box, which is worth alerting on even if someone finds a way around the string matches.

## Limitations

- **Apache doesn't log POST bodies.** The Drupal 8 style variant that injects through the body is visible only to Suricata rule 1000002, and I haven't tested that rule with a body-based PoC yet.
- **Percent-encoded letters.** `%70ost_render` would slip past the Sigma string match, because PHP decodes it but the log doesn't. Suricata's `url_decode` catches it.
- **Other render properties.** Variants using `#pre_render`, `#lazy_builder` or `#access_callback` aren't covered; these rules focus on `#post_render`.
- **The Sigma rule was validated by replaying its conditions in Python**, not by converting it and running it in a SIEM.
- **HTTPS.** In a real deployment Suricata needs to see decrypted traffic (TLS termination or a sensor behind the load balancer).

## What I learned

- **Test what your grep assumes.** The encoding trap only showed up because I pulled the log by date instead of searching for what I expected the attack to look like.
- **"0 alerts" means nothing without proof of inspection.** Always check that the engine actually parsed the traffic.
- **Don't key on what the attacker controls.** User agent, callback name and casing all changed between tools. The render-array syntax didn't, because the exploit can't work without it.

## Reproduce it

No lab needed for the detection side; the captures and the log are in this folder.

```
# Network rules against the attack and against normal traffic
mkdir -p suricata-out suricata-benign
suricata -r drupalgeddon2.pcap -S drupalgeddon2.rules -l suricata-out -k none && cat suricata-out/fast.log
suricata -r benign.pcap -S drupalgeddon2.rules -l suricata-benign -k none && wc -l < suricata-benign/fast.log

# Sigma rule against DC-1's access log
python3 tests/eval_sigma.py tests/dc1_access.log

# The exploit itself (own lab only)
python3 drupalgeddon2.py http://10.0.2.4/ id
```

## Files

| File | What it is |
|---|---|
| `drupalgeddon2.py` | My Drupal 7 Drupalgeddon2 PoC (lab use only) |
| `drupalgeddon2.rules` | Suricata rules 1000001 to 1000003 |
| `drupalgeddon2_webserver.yml` | Sigma rule for web server access logs |
| `drupalgeddon2.pcap` | Capture of the exploit |
| `benign.pcap` | Capture of normal traffic for the false-positive test |
| `tests/eval_sigma.py` | Applies the Sigma conditions to a log and reports hits, misses and false positives |
| `tests/dc1_access.log` | Excerpt of DC-1's Apache access log: every Drupalgeddon2-related request made against the box, plus all traffic from this project |
