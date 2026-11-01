"""전수 ROC/AUC 그림: AI 앙상블 곡선(연속 점수) + WAF PL 운영점.

입력:
  dev_tools/datasets/roc-auc/scores.jsonl   (요청별 label·logit·rule_hit — eval_roc_auc.py)
  dev_tools/datasets/roc-auc/roc.json       (AUC·운영점 교차검증용)
  dev_tools/datasets/roc-auc/waf-pl{1..4}.json (WAF PL 전수 운영점 — waf_pl_point.py)
출력: docs/images/experiments/t1-5-roc-auc.{png,svg}

실행(한글폰트·matplotlib 있는 환경):
  python dev_tools/scripts/plot_roc_auc.py
"""
import glob
import json
import sys
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager

ROOT = Path(__file__).resolve().parents[2]
D = ROOT / "dev_tools/datasets/roc-auc"
OUT = ROOT / "docs/images/experiments"


def pick_korean_font():
    for path in glob.glob("/mnt/c/Windows/Fonts/malgun*.ttf") + glob.glob("C:/Windows/Fonts/malgun*.ttf"):
        font_manager.fontManager.addfont(path)
    installed = {f.name for f in font_manager.fontManager.ttflist}
    for name in ("Malgun Gothic", "Noto Sans KR", "Noto Sans CJK KR", "NanumGothic", "AppleGothic"):
        if name in installed:
            return name
    return "DejaVu Sans"


plt.rcParams.update({
    "font.family": pick_korean_font(), "axes.unicode_minus": False, "svg.fonttype": "none",
    "font.size": 11, "axes.edgecolor": "#c3c2b7", "axes.linewidth": 0.8,
    "xtick.color": "#898781", "ytick.color": "#898781", "xtick.labelcolor": "#52514e", "ytick.labelcolor": "#52514e",
    "xtick.major.size": 0, "ytick.major.size": 0, "axes.titlelocation": "left",
})
INK, INK2, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#ffffff"
AI, AI2 = "#eb6834", "#b4480c"                     # 3모델(주), +규칙게이트(보조, 점선)
PL_RAMP = ["#86b6ef", "#3987e5", "#1c5cab", "#0d366b"]   # PL1~4 파랑 순서형


def roc_from_scores(score, y):
    """정렬+누적으로 (fpr, tpr, auc). 동점 처리는 임계 경계에서만 점을 남겨 sklearn과 일치."""
    order = np.argsort(-score, kind="mergesort")
    s = score[order]
    ys = y[order].astype(float)
    P, N = ys.sum(), len(ys) - ys.sum()
    tp, fp = np.cumsum(ys), np.cumsum(1 - ys)
    distinct = np.r_[np.where(np.diff(s) != 0)[0], len(s) - 1]
    tpr = np.r_[0.0, tp[distinct] / P]
    fpr = np.r_[0.0, fp[distinct] / N]
    trapz = getattr(np, "trapezoid", None) or np.trapz
    return fpr, tpr, float(trapz(tpr, fpr))


def main(a):
    base = Path(a.dir) if Path(a.dir).is_absolute() else ROOT / a.dir
    XMIN = a.xmin
    meta = json.loads((base / "roc.json").read_text(encoding="utf-8"))
    rows = [json.loads(l) for l in open(base / a.scores, encoding="utf-8") if l.strip()]
    y = np.array([r["label"] for r in rows], dtype=np.int8)
    logit = np.array([r["logit"] for r in rows], dtype=np.float64)
    rule = np.array([r["rule_hit"] for r in rows], dtype=bool)

    fpr_m, tpr_m, auc_m = roc_from_scores(logit, y)
    gated = logit.copy(); gated[rule] = logit.max() + 1.0
    fpr_g, tpr_g, auc_g = roc_from_scores(gated, y)
    print(f"AUC 재계산 model={auc_m:.4f} (roc.json {meta['curves']['model_only']['auc']}), "
          f"gate={auc_g:.4f} (roc.json {meta['curves']['model_plus_rule_gate']['auc']})")

    op = meta["operating_point_0965"]

    # WAF PL 점 — 오탐은 정확히 detected_benign/benign (0이어도 축 왼쪽 끝 XMIN으로 찍음)
    wafs = []
    for f in sorted(glob.glob(str(base / "waf-pl*.json"))):
        d = json.loads(Path(f).read_text(encoding="utf-8"))
        if d.get("detection") is None:
            continue
        fp = (d["detected_benign"] / d["benign"]) if d.get("benign") else (d.get("fpr") or 0.0)
        wafs.append((int(d["pl"]), fp, d["detection"]))
    wafs.sort()
    print("WAF 점:", [(f"PL{p}", f"{fp:.5f}", round(tp, 3)) for p, fp, tp in wafs])

    fig = plt.figure(figsize=(9.6, 6.2))
    ax = fig.add_axes([0.082, 0.12, 0.70, 0.60])
    title = a.title or "AI 앙상블은 낮은 오탐에서도 높은 탐지 — WAF는 PL을 올려도 오탐만 급증"
    subtitle = a.subtitle or (f"ROC 곡선 (전수 {meta['n']:,}건: 공격 {meta['attack']:,}·정상 {meta['benign']:,}) · "
                              "가로축 로그 눈금 · WAF PL은 운영점(점)")
    fig.text(0.012, 0.975, title, ha="left", va="top", fontsize=14.5, fontweight="bold", color=INK)
    fig.text(0.012, 0.918, subtitle, ha="left", va="top", fontsize=10.3, color=INK2)

    ax.set_xscale("log")
    ax.set_xlim(XMIN, 1)
    ax.set_ylim(0, 100)
    for v in (0, 20, 40, 60, 80, 100):
        ax.axhline(v, color=GRID, lw=0.8, zorder=0)
    decades = [10.0 ** e for e in range(int(round(np.log10(XMIN))), 1)]
    for v in decades:
        ax.axvline(v, color=GRID, lw=0.8, zorder=0)
    ax.set_xticks(decades, [f"{100*v:g}%" for v in decades])
    ax.minorticks_off()
    ax.set_yticks([0, 20, 40, 60, 80, 100], [f"{v}%" for v in (0, 20, 40, 60, 80, 100)])
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_xlabel("오탐률 (정상을 공격으로 판정, 로그 눈금)", color=INK2, fontsize=10.3, labelpad=6)
    ax.text(XMIN, 103, "탐지율 (공격을 공격으로 판정)", ha="left", va="bottom", fontsize=10.3, color=INK2)
    ax.tick_params(axis="x", pad=6)

    # AI 곡선 (fpr=0 점은 로그축에서 제외)
    def plot_curve(fpr, tpr, color, ls, lw, label):
        m = fpr > 0
        ax.plot(fpr[m], 100 * tpr[m], color=color, lw=lw, ls=ls, solid_capstyle="round", zorder=4, label=label)

    plot_curve(fpr_g, tpr_g, AI2, "--", 1.8, f"AI 3모델+규칙게이트 (AUC {auc_g:.3f})")
    plot_curve(fpr_m, tpr_m, AI, "-", 2.4, f"AI 3모델 (AUC {auc_m:.3f})")

    # 운영점 ★
    opx = max(op["fpr"], XMIN)
    ax.plot(opx, 100 * op["detection"], marker="*", ms=17, color=AI, mec=SURFACE, mew=1.3, zorder=6)
    _left = opx <= XMIN * 3  # 운영점이 축 왼쪽 끝이면 라벨을 오른쪽으로(클리핑 방지)
    ax.annotate(f"운영 설정 (임계 0.965)\n탐지 {100*op['detection']:.1f}% / 오탐 {100*op['fpr']:.2f}%",
                (opx, 100 * op["detection"]), xytext=(14 if _left else -12, -42), textcoords="offset points",
                fontsize=9.3, color=INK2, ha="left" if _left else "right",
                arrowprops=dict(arrowstyle="-", color=MUTED, lw=0.8))

    # WAF PL 점 — 색 램프(밝은→진한=PL1→4). 군집이라 값은 우측 표로, 플롯엔 PL1만 라벨.
    for pl, fp, tp in wafs:
        ax.plot(max(fp, XMIN), 100 * tp, "o", ms=11, color=PL_RAMP[min(pl - 1, 3)], mec=SURFACE, mew=1.5, zorder=5)
    if wafs:
        ax.annotate("PL1", (max(wafs[0][1], XMIN), 100 * wafs[0][2]), xytext=(11, -3), textcoords="offset points",
                    fontsize=9.5, fontweight="bold", color=INK, va="center")
    if len(wafs) > 1:  # PL2·3·4 군집 → 아래 빈 공간에 리더선
        cx = max(wafs[len(wafs) // 2][1], XMIN)
        ax.annotate("WAF PL2·3·4", (cx, 100 * min(w[2] for w in wafs[1:])),
                    xytext=(0, -34), textcoords="offset points", fontsize=9.5, fontweight="bold",
                    color=INK, ha="center", arrowprops=dict(arrowstyle="-", color=MUTED, lw=0.8))

    ax.legend(loc="lower right", frameon=False, fontsize=9.8, handlelength=2.0,
              borderaxespad=0.4, labelcolor=INK)

    a3 = lambda v: f"{v:.3f}".lstrip("0") if isinstance(v, (int, float)) else "-"
    x0 = 0.80
    fig.text(x0, 0.665, "WAF (CRS) PL별 운영점", fontsize=10, fontweight="bold", color=INK)
    fig.text(x0, 0.638, "점 색: 밝은→진한 = PL1→4", fontsize=8.5, color=MUTED)
    fig.text(x0 + 0.052, 0.611, "탐지 / 오탐", fontsize=8.8, color=INK2)
    fpf = lambda v: (f"{100*v:.2g}%" if v < 0.01 else f"{100*v:.0f}%")
    for i, (pl, fp, tp) in enumerate(wafs):
        yy = 0.586 - i * 0.030
        fig.text(x0, yy, "●", fontsize=10.5, color=PL_RAMP[min(pl - 1, 3)], va="center")
        fig.text(x0 + 0.020, yy, f"PL{pl}", fontsize=9.3, color=INK, va="center")
        fig.text(x0 + 0.062, yy, f"{100*tp:.0f}% / {fpf(fp)}", fontsize=9.3, color=INK2, va="center")
    rl = 0.586 - len(wafs) * 0.030 - 0.028
    for i, s in enumerate(["읽는 법 — 곡선이 왼쪽 위에", "붙을수록 낮은 오탐에서 높은",
                           "탐지. WAF 점은 모두 AI 곡선", "오른쪽 아래(오탐이 훨씬 큼)."]):
        fig.text(x0, rl - i * 0.029, s, fontsize=9.0, color=INK2, va="top")
    au = list(meta["auc_by_source"].items())
    fig.text(x0, rl - 4 * 0.029 - 0.012, "출처별 AUC(+게이트):", fontsize=8.8, color=MUTED, va="top")
    for j in range(0, len(au), 2):
        pair = "·".join(f"{k} {a3(v)}" for k, v in au[j:j + 2])
        fig.text(x0, rl - (5 + j // 2) * 0.029 - 0.012, pair, fontsize=8.6, color=MUTED, va="top")

    fig.text(0.012, 0.015, "AI 점수=앙상블 로짓(transformer·tree·schema soft-vote). 규칙게이트=규칙 적중/UA 초과는 공격 확정(운영 판정). "
             "WAF 점=CRS 차단(403) 전수 집계.", fontsize=8.3, color=MUTED)

    OUT.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "svg"):
        fig.savefig(OUT / f"{a.out}.{ext}", dpi=300, facecolor=SURFACE)
    plt.close(fig)
    print("저장:", OUT / f"{a.out}.png")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="dev_tools/datasets/roc-auc")
    ap.add_argument("--scores", default="scores.jsonl")
    ap.add_argument("--out", default="t1-5-roc-auc")
    ap.add_argument("--xmin", type=float, default=1e-5)
    ap.add_argument("--title", default="")
    ap.add_argument("--subtitle", default="")
    main(ap.parse_args())
