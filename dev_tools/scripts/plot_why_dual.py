"""'왜 이중방어' 그림: 두 분포(같은출처·독립셋)에서 공격을 누가 잡았나(둘다/AI만/WAF만/놓침).

분포마다 'OO만' 조각이 뒤집힘(같은출처=AI만 큼, 독립셋=WAF만 큼) → 한 층은 혼자 부족, 합쳐야(OR) 놓침만 남는다.
출력: docs/images/experiments/t1-7-why-dual.{png,svg}
"""
import glob
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.patches import Rectangle

OUT = Path(__file__).resolve().parents[2] / "docs/images/experiments"


def pick_font():
    for p in glob.glob("/mnt/c/Windows/Fonts/malgun*.ttf"):
        font_manager.fontManager.addfont(p)
    inst = {f.name for f in font_manager.fontManager.ttflist}
    for n in ("Malgun Gothic", "Noto Sans KR", "NanumGothic", "AppleGothic"):
        if n in inst:
            return n
    return "DejaVu Sans"


plt.rcParams.update({"font.family": pick_font(), "axes.unicode_minus": False, "svg.fonttype": "none", "font.size": 11})
INK, INK2, MUTED, SURFACE = "#0b0b0b", "#52514e", "#898781", "#ffffff"
WAF, AI, BOTH, NEITHER = "#2a78d6", "#eb6834", "#1baf7a", "#c6c5bc"   # 파랑·주황·초록·회색(repo 토큰)

DATA = [
    ("같은출처\n(변종 섞임)", {"both": 18974, "ai": 26379, "waf": 2244, "neither": 5288}),   # 52,885
    ("독립 공개셋\n(전형 공격)", {"both": 21807, "ai": 1074, "waf": 6578, "neither": 8175}),   # 37,634
]
SEGS = [("둘 다 탐지", "both", BOTH), ("AI만 탐지", "ai", AI), ("WAF만 탐지", "waf", WAF), ("둘 다 놓침", "neither", NEITHER)]


def main():
    fig = plt.figure(figsize=(10.8, 5.0))
    ax = fig.add_axes([0.12, 0.20, 0.60, 0.48])
    fig.text(0.012, 0.965, "한 층은 혼자서 부족하다 — 분포가 바뀌면 다른 층이 메운다",
             ha="left", va="top", fontsize=15, fontweight="bold", color=INK)
    fig.text(0.012, 0.905, "공격을 누가 탐지했나 (WAF=ModSecurity PL1 · AI=앙상블) · 공격 52,885(같은출처)·37,634(독립) · "
             "'OO만' 조각이 뒤집힌다", ha="left", va="top", fontsize=10.3, color=INK2)

    ys, H = [1.0, 0.0], 0.42
    for y, (name, d) in zip(ys, DATA):
        tot = sum(d.values()); x = 0.0
        for label, key, color in SEGS:
            w = 100 * d[key] / tot
            ax.add_patch(Rectangle((x + 0.15, y - H / 2), max(w - 0.3, 0), H, fc=color, ec="none"))
            if w >= 4:
                tc = "#ffffff" if key in ("waf", "ai", "both") else INK2
                ax.text(x + w / 2, y, f"{w:.1f}%", ha="center", va="center", fontsize=10,
                        color=tc, fontweight="bold" if key in ("ai", "waf") else "normal")
            x += w
        ax.text(-2.5, y, name, ha="right", va="center", fontsize=10.5, color=INK)
        wo = 100 * (d["both"] + d["waf"]) / tot; ao = 100 * (d["both"] + d["ai"]) / tot; o = 100 * (tot - d["neither"]) / tot
        ax.text(103, y + 0.1, f"WAF 단독 {wo:.0f}%", ha="left", va="center", fontsize=9.2, color=WAF)
        ax.text(103, y - 0.04, f"AI 단독 {ao:.0f}%", ha="left", va="center", fontsize=9.2, color="#b4480c")
        ax.text(103, y - 0.18, f"→ OR {o:.0f}%", ha="left", va="center", fontsize=9.6, color=INK, fontweight="bold")

    ax.set_xlim(0, 100); ax.set_ylim(-0.85, 1.85)
    ax.set_yticks([]); ax.set_xticks([0, 20, 40, 60, 80, 100], [f"{v}%" for v in (0, 20, 40, 60, 80, 100)])
    ax.tick_params(axis="x", colors=MUTED, labelsize=9)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_xlabel("공격 중 비율", color=INK2, fontsize=10, labelpad=3)

    ax.text(40, 1.0 + H / 2 + 0.22, "AI만 49.9% — AI가 WAF 사각을 메움", ha="center", va="bottom",
            fontsize=9.6, color=AI, fontweight="bold")
    ax.text(68, 0.0 - H / 2 - 0.22, "WAF만 17.5% — WAF가 AI 사각을 메움", ha="center", va="top",
            fontsize=9.6, color=WAF, fontweight="bold")

    hx = 0.12
    for label, key, color in SEGS:
        fig.patches.append(plt.Rectangle((hx, 0.05), 0.015, 0.028, transform=fig.transFigure, fc=color, ec="none"))
        fig.text(hx + 0.02, 0.064, label, fontsize=9.3, color=INK, va="center")
        hx += 0.02 + 0.0115 * len(label) + 0.025

    fig.text(0.012, 0.008, "보완성: 같은출처는 AI가 WAF 미탐의 83.3%(26,379건)를 회수, 독립셋은 WAF가 AI 공백을 메움. "
             "OR 최악 78% > 단독 최악(WAF 40%·AI 61%) — 이중방어가 탐지 '바닥'을 올린다.", fontsize=8.6, color=MUTED)

    OUT.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "svg"):
        fig.savefig(OUT / f"t1-7-why-dual.{ext}", dpi=300, facecolor=SURFACE)
    plt.close(fig)
    print("저장:", OUT / "t1-7-why-dual.png")


if __name__ == "__main__":
    main()
