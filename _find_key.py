"""Fix: extract sSecKey from 85001 RECV using correct JCE encoding.

QQ Chess JCE: upper 4 bits = field_id (15=extended), lower 4 bits = type.
sSecKey is at field 10, type STRING1(6) → tag byte = 0xA6
"""

import json, base64, struct, sys

session = sys.argv[1] if len(sys.argv) > 1 else 'data/sessions/qqchess_ws_raw_20260506_174656.json'

with open(session, 'r', encoding='utf-8') as f:
    raw = json.load(f)
decoded_path = session.replace('_raw_', '_decoded_')
with open(decoded_path, 'r', encoding='utf-8') as f:
    decoded = json.load(f)

for d in decoded:
    if d['msgID'] == 85001 and d['direction'] == 'RECV':
        for rm in raw:
            if rm['seq'] != d['seq']:
                continue
            data = base64.b64decode(rm['base64'])
            print(f'85001 RECV: {len(data)} bytes')

            # Find STING1 field 10 tag: 0xA6 = (10<<4)|6
            # Find STRING4 field 10 tag: 0xA7 = (10<<4)|7
            # Or extended: 0xF6 followed by field_id byte = 10

            # Scan for all sSecKey candidates
            candidates = []
            for i in range(len(data) - 3):
                b = data[i]
                field_id = b >> 4
                jce_type = b & 0xf

                actual_field = field_id
                if field_id == 15:
                    if i + 1 < len(data):
                        actual_field = data[i + 1]
                    else:
                        continue

                if actual_field == 10 and jce_type in (6, 7):
                    if jce_type == 6:
                        if i + 2 >= len(data):
                            continue
                        slen = data[i + 1 + (1 if field_id == 15 else 0)]
                        start = i + 2 + (1 if field_id == 15 else 0)
                        if start + slen <= len(data):
                            val = data[start:start+slen]
                            candidates.append((i, 'STR1', slen, val))
                    else:  # STRING4
                        offset = i + 1 + (1 if field_id == 15 else 0)
                        if offset + 4 > len(data):
                            continue
                        slen = struct.unpack('>I', data[offset:offset+4])[0]
                        if slen > 0 and slen < 10000:
                            start = offset + 4
                            if start + slen <= len(data):
                                val = data[start:start+slen]
                                candidates.append((i, 'STR4', slen, val))

            print(f'\nFound {len(candidates)} field=10 candidates:\n')
            for offset, stype, slen, val in candidates:
                try:
                    text = val.decode('ascii')
                except:
                    text = val.hex()
                print(f'  offset={offset:5d} {stype} len={slen} | {text[:120]}')

            # Also find uUin at field 1
            print('\nField 1 (uUin) candidates:')
            for i in range(min(200, len(data))):
                b = data[i]
                field_id = b >> 4
                jce_type = b & 0xf
                actual_field = field_id
                if field_id == 15 and i + 1 < len(data):
                    actual_field = data[i + 1]
                if actual_field == 1 and jce_type in (2, 3):  # INT32 or INT64
                    if jce_type == 2 and i + 1 + (1 if field_id==15 else 0) + 4 <= len(data):
                        val = struct.unpack('>I', data[i+1+(1 if field_id==15 else 0):i+1+(1 if field_id==15 else 0)+4])[0]
                    elif jce_type == 3 and i + 1 + (1 if field_id==15 else 0) + 8 <= len(data):
                        val = struct.unpack('>Q', data[i+1+(1 if field_id==15 else 0):i+1+(1 if field_id==15 else 0)+8])[0]
                    else:
                        continue
                    ext = f' (extended, actual_field={actual_field})' if field_id == 15 else ''
                    print(f'  offset={i} type=INT{"32" if jce_type==2 else "64"} field=1{ext} value={val}')
            break
        break
