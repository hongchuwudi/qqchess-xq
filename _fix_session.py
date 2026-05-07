"""
Retroactively extract session_key from saved proxy sessions.

Uses the same parse pipeline as xq_ws_proxy.py to correctly navigate
the 3-layer JCE nesting: TPackage → stMsg → vecMsgBody → TResponseLogin

Usage: python _fix_session.py qqchess_ws_raw_20260506_174656.json
"""

import json, base64, struct, sys, os, re

# Add parent dir for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xq_ws_proxy import (
    JceIn, parse_pkg, _parse_tmsg, parse_login, derive_session_key,
    tea_cbc_decrypt, unwrap_ws
)


def main():
    session_path = sys.argv[1]
    base = os.path.basename(session_path)
    dir_name = os.path.dirname(session_path) or '.'

    ts_match = re.search(r'(\d{8}_\d{6})', base)
    if not ts_match:
        print("[!] Cannot parse timestamp from filename")
        sys.exit(1)
    ts = ts_match.group(1)

    raw_path = os.path.join(dir_name, f'qqchess_ws_raw_{ts}.json')
    decoded_path = os.path.join(dir_name, f'qqchess_ws_decoded_{ts}.json')
    summary_path = os.path.join(dir_name, f'qqchess_summary_{ts}.json')

    for p in [raw_path, decoded_path, summary_path]:
        if not os.path.exists(p):
            print(f"[!] Missing: {p}")
            sys.exit(1)

    with open(raw_path, 'r', encoding='utf-8') as f:
        raw = json.load(f)
    with open(decoded_path, 'r', encoding='utf-8') as f:
        decoded = json.load(f)
    with open(summary_path, 'r', encoding='utf-8') as f:
        summary = json.load(f)

    # ---- Find 85001 RECV and parse through TPackage → stMsg → TResponseLogin ----
    login_info = None

    for d in decoded:
        if d.get('msgID') != 85001 or d.get('direction') != 'RECV':
            continue
        seq = d['seq']
        for rm in raw:
            if rm.get('seq') != seq:
                continue
            data = base64.b64decode(rm['base64'])
            print(f"85001 RECV raw: {len(data)} bytes")

            # Strip WS framing → JCE body
            direction, jce_data = unwrap_ws(data)
            if not jce_data:
                print("[!] unwrap_ws failed")
                break
            print(f"JCE body: {len(jce_data)} bytes")

            pkg = parse_pkg(jce_data)
            print(f"TPackage parsed:")
            print(f"  iClientVer    = {pkg.get('iClientVer')}")
            print(f"  uUin          = {pkg.get('uUin')}")
            print(f"  iFlag         = {pkg.get('iFlag')}")
            print(f"  iRoomID       = {pkg.get('iRoomID')}")
            stmsg = pkg.get('stMsg')
            if stmsg:
                print(f"  stMsg.head    = {stmsg.get('head')}")
                print(f"  stMsg.body    = {len(stmsg.get('body', b''))} bytes")
                # Parse login response from vecMsgBody
                login = parse_login(stmsg['body'])
                print(f"  Login response:")
                print(f"    iResultID   = {login.get('iResultID')}")
                print(f"    uUin        = {login.get('uUin')}")
                ssec = login.get('sSecKey', '')
                print(f"    sSecKey     = {ssec[:60] + '...' if len(ssec) > 60 else ssec}")
                if ssec and login.get('uUin'):
                    login_info = login
            break
        break

    if not login_info or not login_info.get('sSecKey'):
        print("\n[!] Could not extract sSecKey — login body may be encrypted or malformed")
        sys.exit(1)

    uin = login_info['uUin']
    ssec = login_info['sSecKey']

    session_key = derive_session_key(ssec, uin)
    print(f"\nsession_key  = {session_key.hex()}")

    # Update summary
    summary['session_key'] = session_key.hex()
    summary['uin'] = uin
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"[OK] Updated {os.path.basename(summary_path)}")

    # ---- Decrypt test on first battle message ----
    tested = 0
    for d in decoded:
        if d.get('msgID') in (86004, 86005, 86006) and d.get('encrypted', False):
            seq = d['seq']
            for rm in raw:
                if rm.get('seq') != seq:
                    continue
                data = base64.b64decode(rm['base64'])
                _, jce_data = unwrap_ws(data)
                try:
                    pkg = parse_pkg(jce_data)
                except Exception:
                    continue
                inner_body = pkg.get('stMsg', {}).get('body', b'')
                if not inner_body:
                    continue

                dec = tea_cbc_decrypt(inner_body, session_key)
                print(f"\n--- Decrypt test: msgID={d['msgID']} seq={seq} inner={len(inner_body)}B -> {len(dec)}B ---")
                print(f"  hex: {dec[:120].hex(' ')}")

                # Try to find FEN / chess data
                readable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in dec[:300])
                print(f"  readable: {readable[:200]}")

                # Search for FEN pattern
                fen_match = re.search(rb'[rnbakcpRNBAKCP1-9/]{20,}', dec)
                if fen_match:
                    print(f"  *** FEN FOUND: {fen_match.group().decode('ascii', errors='replace')}")

                tested += 1
                if tested >= 3:
                    break
            if tested >= 3:
                break
        if tested >= 3:
            break

    print(f"\nDone. Run: python xq_analyzer.py --session {raw_path}")


if __name__ == '__main__':
    main()
