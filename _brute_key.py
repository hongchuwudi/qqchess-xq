"""
Brute-force: try every string in the 85001 login body as sSecKey,
verify by attempting to decrypt and looking for FEN / chess patterns.
"""

import json, base64, struct, re, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xq_ws_proxy import unwrap_ws, parse_pkg, tea_cbc_decrypt

session = sys.argv[1] if len(sys.argv) > 1 else 'data/sessions/qqchess_ws_raw_20260506_174656.json'

with open(session, 'r', encoding='utf-8') as f:
    raw = json.load(f)
decoded_path = session.replace('_raw_', '_decoded_')
with open(decoded_path, 'r', encoding='utf-8') as f:
    decoded = json.load(f)

# ---- Build index ----
raw_by_seq = {m['seq']: m for m in raw}

# ---- Find 85001 RECV and extract ALL strings ----
login_body = None
uUin_outer = None
for d in decoded:
    if d.get('msgID') == 85001 and d.get('direction') == 'RECV':
        rm = raw_by_seq.get(d['seq'])
        if not rm:
            continue
        data = base64.b64decode(rm['base64'])
        _, jce = unwrap_ws(data)
        pkg = parse_pkg(jce)
        uUin_outer = pkg.get('uUin')
        login_body = pkg['stMsg']['body']
        break

if not login_body:
    print('[!] No login body found')
    sys.exit(1)

print(f'uUin = {uUin_outer}')
print(f'Login body: {len(login_body)} bytes\n')

# Extract ALL strings
candidates = []
for i in range(len(login_body) - 2):
    b = login_body[i]
    field_id = b >> 4
    jce_type = b & 0xf
    if field_id == 15:
        if i + 1 >= len(login_body):
            continue
        field_id = login_body[i + 1]
    if jce_type not in (6, 7):
        continue
    offset = i + 1 + (1 if field_id == 15 else 0)
    try:
        if jce_type == 6:
            slen = login_body[offset]
            if offset + 1 + slen > len(login_body):
                continue
            val = login_body[offset + 1:offset + 1 + slen]
        else:
            slen = struct.unpack('>I', login_body[offset:offset + 4])[0]
            if slen > 2000 or offset + 4 + slen > len(login_body):
                continue
            val = login_body[offset + 4:offset + 4 + slen]
        candidates.append((i, field_id, jce_type, slen, val))
    except:
        continue

print(f'Found {len(candidates)} string fields:\n')
for i, fid, jt, slen, val in candidates:
    try:
        preview = val[:60].decode('ascii')
        if all(c in '0123456789abcdefABCDEF' for c in preview[:16]):
            pass  # hex-like, fine
    except:
        preview = val[:30].hex()
    # Filter non-printable for terminal safety
    try:
        print(f'  offset={i:5d} field={fid:3d} type=STR{jt} len={slen:5d} | {preview}')
    except UnicodeEncodeError:
        print(f'  offset={i:5d} field={fid:3d} type=STR{jt} len={slen:5d} | <binary {slen}B>')

# ---- Test each candidate as sSecKey against a battle message ----
# Get first encrypted battle message
test_body = None
test_msgid = None
for d in decoded:
    if d.get('msgID') not in (86004, 86005) or not d.get('encrypted'):
        continue
    rm = raw_by_seq.get(d['seq'])
    if not rm:
        continue
    data = base64.b64decode(rm['base64'])
    _, jce = unwrap_ws(data)
    try:
        test_pkg = parse_pkg(jce)
        test_body = test_pkg['stMsg']['body']
        test_msgid = d['msgID']
    except:
        continue
    if test_body and len(test_body) >= 16:
        break

print(f'\n--- Testing decryption on msgID={test_msgid} {len(test_body)}B body ---')

for i, fid, jt, slen, val in candidates:
    if slen < 16:
        continue
    # Try as both raw binary and hex string
    keys_to_try = []
    # As-raw: use bytes directly as TEA key
    if slen >= 16:
        # Use first 16 bytes as key directly
        keys_to_try.append(('raw16', val[:16]))
        # Derive: TEA_decrypt(val, pad16(uin))
        tk = str(uUin_outer).encode().ljust(16, b'\x00')
        try:
            sk = tea_cbc_decrypt(val, tk)
            if sk:
                pl = sk[-1]
                if 1 <= pl <= 8:
                    sk = sk[:-pl]
            keys_to_try.append(('derive', sk[:16]))
        except:
            pass
        # Derive with hex
        try:
            hex_str = val.decode('ascii')
            if all(c in '0123456789abcdefABCDEF' for c in hex_str):
                sk = tea_cbc_decrypt(bytes.fromhex(hex_str), tk)
                if sk:
                    pl = sk[-1]
                    if 1 <= pl <= 8:
                        sk = sk[:-pl]
                keys_to_try.append(('hex_derive', sk[:16]))
        except:
            pass

    for method, key in keys_to_try:
        if len(key) < 16:
            continue
        dec = tea_cbc_decrypt(test_body, key[:16])
        # Check for FEN pattern
        fen = re.search(rb'[rnbakcpRNBAKCP1-9/]{15,}', dec)
        # Check for structured JCE (starts with valid tag bytes)
        valid_tags = sum(1 for b in dec[:20] if (b >> 4) in (0, 1, 2, 3, 6, 7, 10, 12) or ((b & 0xf) in (0, 1, 2, 3, 6, 7, 10, 12)))
        if fen or valid_tags >= 5:
            print(f'\n*** CANDIDATE: field={fid} offset={i} method={method} ***')
            print(f'  key={key[:16].hex()}')
            print(f'  dec hex: {dec[:60].hex()}')
