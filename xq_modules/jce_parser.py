"""JCE binary parser — Tencent proprietary tagged-field format."""

import struct

# ============================================================
# JCE 解析器 (精简, 仅处理本协议需要的类型)
# ============================================================

class JceIn:
    """JCE 输入流 — 按 tag 升序读取字段"""

    def __init__(self, data, pos=0):
        self.d = data
        self.p = pos

    # ---- 底层 ----

    def _peek(self):
        """peek 下一字段的(tag, type), 不移动指针"""
        if self.p >= len(self.d):
            return None, None
        b = self.d[self.p]
        tag, typ = b >> 4, b & 0xf
        if tag == 15:
            if self.p + 1 >= len(self.d):
                return None, None
            tag = self.d[self.p + 1]
            return tag, typ
        return tag, typ

    def _read_head(self):
        """读取字段头 (tag, type), 移动指针"""
        tag, typ = self._peek()
        self.p += 1
        if tag is not None and (self.d[self.p - 1] >> 4) == 15:
            self.p += 1  # skip extended tag byte
        return tag, typ

    def _skip_val(self, typ):
        if typ == 0:   self.p += 1       # INT8
        elif typ == 1: self.p += 2       # INT16
        elif typ == 2: self.p += 4       # INT32
        elif typ == 3: self.p += 8       # INT64
        elif typ == 4: self.p += 4       # FLOAT
        elif typ == 5: self.p += 8       # DOUBLE
        elif typ == 6:                   # STR1
            self.p += 1 + self.d[self.p]
        elif typ == 7:                   # STR4
            n = struct.unpack('>I', self.d[self.p:self.p + 4])[0]
            self.p += 4 + n
        elif typ == 8:                   # MAP
            self.p += 1  # count=0 (we only handle empty maps)
        elif typ == 9:                   # LIST
            self.p += 1  # count=0
        elif typ == 10:                  # STRUCT_BEGIN → skip nested
            self._skip_struct()
        elif typ == 12: pass             # ZERO
        elif typ == 13:                  # BYTES
            self._read_head()            # inner tag=0 type=INT8
            n = self._read_int_len()     # variable-length int
            self.p += n
        # typ 11 (STRUCT_END) handled by caller

    def _skip_struct(self):
        """跳过整个结构体直到 STRUCT_END (嵌套安全)"""
        depth = 1
        while self.p < len(self.d) and depth > 0:
            tag, typ = self._read_head()
            if typ == 10:
                depth += 1
            elif typ == 11:
                depth -= 1
            else:
                self._skip_val(typ)

    def _skip_to(self, want_tag):
        """跳过 tag < want_tag 的字段, 返回是否找到 want_tag"""
        while self.p < len(self.d):
            tag, typ = self._peek()
            if typ == 11:        # STRUCT_END
                return False
            if tag >= want_tag:
                return tag == want_tag
            self._read_head()
            self._skip_val(typ)
        return False

    # ---- 读取变长整数 (用于 BYTES 内部长度) ----
    def _read_int_len(self):
        """读取 JCE 变长整数 (0/1/2/3 类型)"""
        tag, typ = self._read_head()
        if typ == 12: return 0        # ZERO
        if typ == 0:                  # INT8
            v = self.d[self.p]
            self.p += 1
            return v
        if typ == 1:                  # INT16
            v = struct.unpack('>h', self.d[self.p:self.p + 2])[0]
            self.p += 2
            return v
        if typ == 2:                  # INT32
            v = struct.unpack('>i', self.d[self.p:self.p + 4])[0]
            self.p += 4
            return v
        return 0

    # ---- 公开读取 API ----

    def read_int32(self, tag, default=0):
        if not self._skip_to(tag):
            return default
        _, typ = self._read_head()
        if typ == 12: return 0
        if typ == 0:
            v = struct.unpack('b', self.d[self.p:self.p + 1])[0]
            self.p += 1
            return v
        if typ == 1:
            v = struct.unpack('>h', self.d[self.p:self.p + 2])[0]
            self.p += 2
            return v
        if typ == 2:
            v = struct.unpack('>i', self.d[self.p:self.p + 4])[0]
            self.p += 4
            return v
        return default

    def read_uint32(self, tag, default=0):
        """UInt32 — 注意大值会用 INT64 编码"""
        if not self._skip_to(tag):
            return default
        _, typ = self._read_head()
        if typ == 12: return 0
        if typ == 0:
            v = self.d[self.p]; self.p += 1; return v
        if typ == 1:
            v = struct.unpack('>H', self.d[self.p:self.p + 2])[0]
            self.p += 2; return v
        if typ == 2:
            v = struct.unpack('>I', self.d[self.p:self.p + 4])[0]
            self.p += 4; return v
        if typ == 3:  # INT64 for large uUin
            lo = struct.unpack('>I', self.d[self.p + 4:self.p + 8])[0]
            self.p += 8; return lo
        return default

    def read_int64(self, tag, default=0):
        if not self._skip_to(tag):
            return default
        _, typ = self._read_head()
        if typ == 12: return 0
        if typ in (0, 1, 2):
            return self.read_int32(tag, default)  # reuse already consumed head? no.
        if typ == 3:
            hi = struct.unpack('>I', self.d[self.p:self.p + 4])[0]
            lo = struct.unpack('>I', self.d[self.p + 4:self.p + 8])[0]
            self.p += 8
            return (hi << 32) | lo
        return default

    def read_int16(self, tag, default=0):
        if not self._skip_to(tag):
            return default
        _, typ = self._read_head()
        if typ == 12: return 0
        if typ == 0:
            v = struct.unpack('b', self.d[self.p:self.p + 1])[0]
            self.p += 1; return v
        if typ == 1:
            v = struct.unpack('>h', self.d[self.p:self.p + 2])[0]
            self.p += 2; return v
        return default

    def read_string(self, tag, default=''):
        if not self._skip_to(tag):
            return default
        _, typ = self._read_head()
        if typ == 6:
            n = self.d[self.p]; self.p += 1
            v = self.d[self.p:self.p + n].decode('utf-8', errors='replace')
            self.p += n; return v
        if typ == 7:
            n = struct.unpack('>I', self.d[self.p:self.p + 4])[0]
            self.p += 4
            if n > 100000: return default
            v = self.d[self.p:self.p + n].decode('utf-8', errors='replace')
            self.p += n; return v
        return default

    def read_bytes(self, tag, default=b''):
        if not self._skip_to(tag):
            return default
        self._read_head()           # outer: tag, type=13
        self._read_head()           # inner: tag=0, type=INT8
        n = self._read_int_len()    # variable-length int
        if n < 0 or n > 10 * 1024 * 1024:
            return default
        v = self.d[self.p:self.p + n]
        self.p += n
        return v

    def read_struct_begin(self, tag):
        """读取 STRUCT_BEGIN, 返回 True 如果找到"""
        if not self._skip_to(tag):
            return False
        tag2, typ = self._read_head()
        return typ == 10

    def read_struct_end(self):
        """跳过剩余字段直到 STRUCT_END (嵌套安全版本)"""
        depth = 1
        while self.p < len(self.d) and depth > 0:
            tag, typ = self._read_head()
            if typ == 10:   # STRUCT_BEGIN
                depth += 1
            elif typ == 11: # STRUCT_END
                depth -= 1
            else:
                self._skip_val(typ)

