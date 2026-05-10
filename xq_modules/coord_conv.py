"""Raw UCI -> FEN coordinate conversion with format locking."""

# ============================================================
# 坐标转换：协议走子 → FEN 坐标
# ============================================================

def game_to_fen(uci, mover_camp, fmt):
    """将 raw UCI 转换为 FEN 坐标。fmt 首步锁定后整局不变，过河不受影响。

    fmt='A'(fr≤4): 玩家视角 — 红翻行 / 黑镜像列
    fmt='B'(fr>4): 行=FEN列=raw — 红镜像列 / 黑翻行
    """
    if not mover_camp or not fmt or len(uci) != 4:
        return uci

    cols = 'abcdefghi'
    try:
        fc = cols.index(uci[0])
        fr = int(uci[1])
        tc = cols.index(uci[2])
        tr = int(uci[3])
    except (ValueError, IndexError):
        return uci

    if fmt == 'A':
        if mover_camp == 'red':
            return f"{uci[0]}{9 - fr}{uci[2]}{9 - tr}"     # 翻行
        else:
            return f"{cols[8 - fc]}{uci[1]}{cols[8 - tc]}{uci[3]}"  # 镜像列
    else:  # 'B'
        if mover_camp == 'red':
            return f"{cols[8 - fc]}{uci[1]}{cols[8 - tc]}{uci[3]}"   # 镜像列
        else:
            return f"{uci[0]}{9 - fr}{uci[2]}{9 - tr}"     # 翻行


def detect_format(first_uci):
    """首步检测 raw UCI 格式。返回 'A'(fr≤4) 或 'B'(fr>4)。"""
    if not first_uci or len(first_uci) != 4:
        return None
    try:
        return 'A' if int(first_uci[1]) <= 4 else 'B'
    except ValueError:
        return None
    if not first_uci or len(first_uci) != 4:
        return False
    try:
        from_row = int(first_uci[1])
    except ValueError:
        return False
    # 首步永远是红方，红方应在 rows 5-9
    return from_row <= 4

