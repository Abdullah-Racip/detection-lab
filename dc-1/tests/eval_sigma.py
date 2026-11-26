#!/usr/bin/env python3
"""
Evaluate the Drupalgeddon2 Sigma rule (../drupalgeddon2_webserver.yml) against
an Apache access log, without needing a SIEM.

It applies the rule's conditions field by field (Sigma 'contains' is
case-insensitive), compares them with a naive rule that only matches the
literal 'file/ajax', and reports hits, misses and false positives.

Ground truth: in DC-1's log, every request carrying a render-array injection
or the file/ajax '#value' trigger comes from a known exploit run (two
Metasploit sessions and my own PoC). Everything else is normal browsing.

Usage: python3 eval_sigma.py dc1_access.log [--verbose]
"""
import argparse
import re

REQUEST = re.compile(r'"(\S+) (\S+) [^"]*"')


def contains(value, *needles):
    value = value.lower()
    return any(n.lower() in value for n in needles)


def sigma_rule(stem, query):
    """Mirrors drupalgeddon2_webserver.yml."""
    stage1 = contains(query, "%23post_render")
    stage2_query = contains(query, "file/ajax/", "file%2fajax%2f") and contains(query, "%23value")
    stage2_clean_url = contains(stem, "/file/ajax/") and contains(stem, "%23value")
    return stage1 or stage2_query or stage2_clean_url


def naive_rule(stem, query):
    """What a rule that ignores URL encoding of slashes would look like."""
    return contains(query, "%23post_render") or (contains(stem + query, "file/ajax/") and contains(stem + query, "%23value"))


def is_attack(uri):
    u = uri.lower()
    return "post_render" in u or ("ajax" in u and "%23value" in u)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", help="Apache access log (combined format)")
    ap.add_argument("--verbose", action="store_true", help="print every normal request and its verdict")
    args = ap.parse_args()

    rows = []
    with open(args.log, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = REQUEST.search(line)
            if not m:
                continue
            method, uri = m.groups()
            stem, _, query = uri.partition("?")
            rows.append({
                "method": method,
                "uri": uri,
                "attack": is_attack(uri),
                "sigma": sigma_rule(stem, query),
                "naive": naive_rule(stem, query),
            })

    attacks = [r for r in rows if r["attack"]]
    normal = [r for r in rows if not r["attack"]]

    def score(key):
        hits = sum(r[key] for r in attacks)
        fps = sum(r[key] for r in normal)
        return hits, fps

    print(f"requests parsed : {len(rows)}")
    print(f"attack requests : {len(attacks)}")
    print(f"normal requests : {len(normal)}\n")
    for key, label in (("sigma", "Sigma rule"), ("naive", "Naive rule (literal file/ajax only)")):
        hits, fps = score(key)
        print(f"{label}")
        print(f"  detected        : {hits} / {len(attacks)}")
        print(f"  missed          : {len(attacks) - hits}")
        print(f"  false positives : {fps} / {len(normal)}\n")

    missed = [r for r in attacks if not r["sigma"]]
    if missed:
        print("Missed by the Sigma rule:")
        for r in missed:
            print(f"  {r['method']} {r['uri'][:100]}")

    if args.verbose:
        print("Normal requests:")
        for r in normal:
            print(f"  {'ALERT' if r['sigma'] else 'ok   '} {r['method']} {r['uri'][:100]}")


if __name__ == "__main__":
    main()
