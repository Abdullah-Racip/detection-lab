# detection-lab

Exploit-to-detection: for each machine I've rooted, I go back and work both sides of the attack.

1. **Understand why the bug works**, down to the code path the exploit abuses.
2. **Write my own PoC** instead of relying on a Metasploit module.
3. **Capture the attack** in my lab, on the wire and in the target's own logs.
4. **Write detections**: Suricata for the network, Sigma for the logs.
5. **Prove them.** True positives against my exploit and against real attack tools, false positives against normal traffic, and an honest list of what they miss.

The offensive side of these machines (full recon to root walkthroughs) lives in [offensive-security-walkthroughs](https://github.com/Abdullah-Racip/offensive-security-walkthroughs). This repo is the defensive side.

## Write-ups

| Machine | Vulnerability | Detections | Result | Status |
|---|---|---|---|---|
| [DC-1](dc-1/) | Drupalgeddon2, CVE-2018-7600 (Drupal 7 RCE) | 3 Suricata, 1 Sigma | Network: both stages, 0 FP. Logs: 108 / 108, 0 FP | ✅ Done |
| DC-2 onwards | | | | Planned |

## How each write-up is built

- **One folder per machine**, with the PoC, the rules, the captures and the test data side by side.
- **Rules are tested, not just written.** Every rule is replayed against a capture of the attack and a capture of normal traffic, and the numbers are in the write-up.
- **Real attacker variety.** Where the target's logs still hold earlier attacks (including my original Metasploit runs), I use them as a test set, because real tools vary user agents, encodings and payloads in ways a single PoC doesn't.
- **Limitations are written down.** Every write-up ends with what the rules don't catch.

## Tooling

Kali Linux, Python 3 (`requests`), tcpdump, Suricata 8, Sigma. Targets run in an isolated VirtualBox NAT network.

## Disclaimer

Everything here was run against intentionally vulnerable machines in my own isolated lab. The PoCs are for vulnerabilities that have been public and patched for years and are published to support the detection work. Don't run them against systems you don't own or have written permission to test.
