"""실험 결과로 포스터·문서용 그래프를 만든다(PNG 300dpi + 글자를 편집할 수 있는 SVG).

T1 (census 86,067건, ModSecurity PL×임계값 16조합, wafs/README.md 참고)
  t1-1-composition  출처별로 CRS·AI 중 누가 탐지/오탐했는지 구성
  t1-2-by-type      공격 유형별 CRS·AI 탐지율
  t1-3-tradeoff     PL×임계값 조합과 AI, OR·AND 결합의 탐지율·오탐률
  t1-4-precision    공격 비율에 따른 정밀도

T3·T4 (메인 스택 부하 측정, dev_tools/load-test/README.md 참고)
  t4-1-user-latency       JuiceShop 직접 접속 vs WAF 경유 응답 시간(p50·p95)
  t3-resources            WAF 경유 부하 동안 컨테이너별 CPU·메모리
  t4-2-detection-latency  공격 요청부터 위협 저장까지의 지연과 단계별 시간
  t4-3-ai-threads         AI 스레드 설정(OMP_NUM_THREADS) 개선 전후: Kafka 처리량·건당 CPU(·탐지 지연)

XAI (판정 근거 설명, AI_new/README.md 9장 · dev_tools/scripts/eval_xai_explanations.py 참고)
  xai-1-faithfulness  설명이 짚은 피처를 바꿨을 때 판정이 뒤집히는 비율(SHAP·기존 reason·무작위)
  xai-2-review-flag   '검토 권장' 표시 여부별 오탐 비율, 오탐·정탐이 표시된 쪽에 들어간 비율
  xai-3-global        판정 근거 상위 피처(평균 |기여|)와 시그니처/구조 구분
  xai-4-waterfall     지역 설명 예시 2개: 공격 구문이 이끈 판정 vs 루트 경로가 이끈 판정

입력: dev_tools/datasets/census-modsecurity*/results.csv, sample-census.jsonl, sample-census.meta.json,
      dev_tools/datasets/load-test/{latency,latency-waf-only,latency-omp1}/summary.json,
      {detection,detection-omp1}/*/latency.csv, ai-threads/summary.json, xai-eval/results.json
      (모두 Git 제외, 있는 것만 그린다)
출력: docs/images/experiments/ (--out-dir로 변경)

  pip install matplotlib
  python3 dev_tools/scripts/plot_experiment_figures.py

한글 글꼴은 맑은 고딕(Windows, WSL은 /mnt/c/Windows/Fonts)을 먼저 찾고, 없으면 Noto Sans KR·나눔고딕을 쓴다.
"""
import argparse, collections, csv, glob, json, re, sys
from pathlib import Path
from urllib.parse import unquote_plus

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.patches import PathPatch, Rectangle
from matplotlib.path import Path as MplPath
from matplotlib.transforms import blended_transform_factory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_pipeline_test as m

D = ROOT / "dev_tools/datasets"
OUT = ROOT / "docs/images/experiments"     # --out-dir로 바꾼다


def pick_korean_font():
    for path in glob.glob("/mnt/c/Windows/Fonts/malgun*.ttf") + glob.glob("C:/Windows/Fonts/malgun*.ttf"):
        font_manager.fontManager.addfont(path)
    installed = {f.name for f in font_manager.fontManager.ttflist}
    for name in ("Malgun Gothic", "Noto Sans KR", "Noto Sans CJK KR", "NanumGothic", "AppleGothic"):
        if name in installed:
            return name
    print("[warn] 한글 글꼴을 찾지 못해 글자가 깨질 수 있습니다.", file=sys.stderr)
    return "DejaVu Sans"


# ── 스타일: dataviz 기본 팔레트, 범주 슬롯 1~4는 인접 쌍 색각 검증 통과 ──────────
plt.rcParams.update({
    "font.family": pick_korean_font(), "axes.unicode_minus": False, "svg.fonttype": "none",
    "font.size": 11, "axes.edgecolor": "#c3c2b7", "axes.linewidth": 0.8,
    "xtick.color": "#898781", "ytick.color": "#898781", "xtick.labelcolor": "#52514e", "ytick.labelcolor": "#52514e",
    "xtick.major.size": 0, "ytick.major.size": 0, "axes.titlelocation": "left",
})
INK, INK2, MUTED, GRID, AXIS, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#ffffff"
CRS, AI, AND, OR = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"      # 범주 슬롯 1~4
NEITHER = "#c3c2b7"
PL_RAMP = ["#86b6ef", "#3987e5", "#1c5cab", "#0d366b"]                # PL1~4: 파랑 순서형 단계(밝을수록 낮은 PL)


def luminance(hex_color):
    rgb = [int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def text_on(fill):
    """채움 위 글자색: 흰색과 잉크 중 대비가 큰 쪽."""
    l = luminance(fill)
    return "#ffffff" if (1.05 / (l + 0.05)) >= ((l + 0.05) / (luminance(INK) + 0.05)) else INK


def header(fig, title, subtitle):
    fig.text(0.012, 0.975, title, ha="left", va="top", fontsize=15, fontweight="bold", color=INK)
    fig.text(0.012, 0.915, subtitle, ha="left", va="top", fontsize=10.5, color=INK2)


def save(fig, name):
    for ext in ("png", "svg"):
        fig.savefig(OUT / f"{name}.{ext}", dpi=300, facecolor=SURFACE)
    plt.close(fig)


def bar_segment(ax, x0, x1, y, h, color, round_end):
    """가로 막대 조각. round_end면 값 쪽(오른쪽) 끝만 4px 둥글게 한다(기준선 쪽은 각지게)."""
    if x1 <= x0:
        return
    y0, y1 = y - h / 2, y + h / 2
    if not round_end:
        ax.add_patch(Rectangle((x0, y0), x1 - x0, h, fc=color, ec="none", lw=0))
        return
    box = ax.get_position()
    fig_w, fig_h = ax.figure.get_size_inches()
    radius_in = 4 / 96
    rx = min(radius_in * (ax.get_xlim()[1] - ax.get_xlim()[0]) / (box.width * fig_w), (x1 - x0) / 2)
    ry = min(radius_in * abs(ax.get_ylim()[1] - ax.get_ylim()[0]) / (box.height * fig_h), h / 2)
    verts = [(x0, y0), (x1 - rx, y0), (x1, y0), (x1, y0 + ry), (x1, y1 - ry), (x1, y1), (x1 - rx, y1), (x0, y1), (x0, y0)]
    codes = [MplPath.MOVETO, MplPath.LINETO, MplPath.CURVE3, MplPath.CURVE3, MplPath.LINETO,
             MplPath.CURVE3, MplPath.CURVE3, MplPath.LINETO, MplPath.CLOSEPOLY]
    ax.add_patch(PathPatch(MplPath(verts, codes), fc=color, ec="none", lw=0))


def rounded_hbar(ax, y, value, h, color):
    """기준선(0)에서 시작하는 가로 막대."""
    bar_segment(ax, 0, value, y, h, color, round_end=True)


def pct(v, digits=1):
    return f"{100 * v:.{digits}f}%"


# ── T1 데이터 ──────────────────────────────────────────────────────────
def load(name):
    rows = []
    for r in csv.DictReader(open(D / name / "results.csv", encoding="utf-8")):
        rows.append({"sample_id": r["sample_id"], "label": int(r["label"]), "source": r["source"], "family": r["family"],
                     "w": r["waf_detected"] == "True", "a": r["ai_attack"] == "True"})
    return rows


REGIONS = [("CRS만", CRS, lambda r: r["w"] and not r["a"]), ("둘 다", AND, lambda r: r["w"] and r["a"]),
           ("AI만", AI, lambda r: r["a"] and not r["w"]), ("둘 다 아님", NEITHER, lambda r: not r["w"] and not r["a"])]
wrate = lambda rows, fn: m.weighted_rate(rows, population, fn)[0]


# ── 그림 1: 누가 잡았나 (출처별 구성) ─────────────────────────────────────
def composition_rows(rows):
    out = [("전체", None, [wrate(rows, fn) for _, _, fn in REGIONS])]
    for src in ("capec", "csic", "ecml", "wcp"):
        sub = [r for r in rows if r["source"] == src]
        out.append((src, len(sub), [sum(map(fn, sub)) / len(sub) for _, _, fn in REGIONS]))
    return out


def draw_stack(ax, y, shares, h, fig, regions=REGIONS):
    """100% 가로 누적 막대. 조각 사이 2px 간격, 끝은 4px 둥글게, 값은 들어갈 때만 안에 쓴다."""
    fig.canvas.draw()
    x_per_px = 100 / ax.get_window_extent().width
    gap = 2 * x_per_px * fig.dpi / 96
    labels_above = []
    x = 0.0
    for i, ((name, color, _), share) in enumerate(zip(regions, shares)):
        w = 100 * share
        if w <= 0:
            continue
        x0 = x + (gap / 2 if x > 0 else 0)
        x1 = x + w - (gap / 2 if x + w < 99.999 else 0)
        bar_segment(ax, x0, max(x1, x0 + 0.01), y, h, color, round_end=x + w >= 99.999)
        t = ax.text((x0 + x1) / 2, y, pct(share), ha="center", va="center", fontsize=9.5, color=text_on(color))
        bb = t.get_window_extent(fig.canvas.get_renderer())
        if bb.width + 8 * fig.dpi / 96 > (x1 - x0) / x_per_px:
            t.remove()
            if share >= 0.005:          # 0.5% 미만은 막대 위에도 쓰지 않는다(값은 표에 있다)
                labels_above.append(((x0 + x1) / 2, share))
        x += w
    return labels_above


def place_above(ax, fig, y, labels):
    """좁은 조각의 값을 막대 위에 쓴다. 조각 가운데에 두되, 앞 라벨과 겹치면 오른쪽으로 밀고
    막대 끝(100%)을 넘으면 묶음 전체를 왼쪽으로 당긴다."""
    renderer = fig.canvas.get_renderer()
    x_per_px = 100 / ax.get_window_extent().width
    pad = 4 * fig.dpi / 96 * x_per_px
    texts, spans = [], []
    for xc, share in labels:
        t = ax.text(xc, y, pct(share), ha="center", va="bottom", fontsize=8.5, color=INK2, clip_on=False)
        width = t.get_window_extent(renderer).width * x_per_px
        left = xc - width / 2
        if spans and left < spans[-1][1] + pad:
            left = spans[-1][1] + pad
        texts.append(t)
        spans.append([left, left + width])
    overflow = spans[-1][1] - 101 if spans else 0
    if overflow > 0:
        for span in spans:
            span[0] -= overflow
            span[1] -= overflow
    for t, (left, right) in zip(texts, spans):
        t.set_x((left + right) / 2)


def figure_composition():
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.6), gridspec_kw={"wspace": 0.08})
    fig.subplots_adjust(left=0.165, right=0.99, top=0.70, bottom=0.09)
    header(fig, "CRS와 AI는 서로 다른 공격을 잡는다",
           "ModSecurity CRS(PL1·임계값 5)와 AI의 판정 구성 · census 86,067건(공격 45,663 / 정상 40,404)")
    counts_benign = collections.Counter(r["source"] for r in ben)
    panels = [(axes[0], att, "공격 요청 — 누가 탐지했나"), (axes[1], ben, "정상 요청 — 누가 잘못 걸었나(오탐)")]
    for ax, rows, title in panels:
        data = composition_rows(rows)
        ys = [0, 1.45, 2.45, 3.45, 4.45]
        ax.set_xlim(0, 100)
        ax.set_ylim(5.0, -0.75)
        ax.axis("off")
        ax.text(0, -0.72, title, ha="left", va="bottom", fontsize=11.5, fontweight="bold", color=INK)
        for (name, n, shares), y in zip(data, ys):
            above = draw_stack(ax, y, shares, 0.52, fig)
            place_above(ax, fig, y - 0.30, above)
            if ax is axes[0]:
                if n is None:
                    ax.text(-2, y - 0.1, name, ha="right", va="center", fontsize=10.5, fontweight="bold", color=INK,
                            clip_on=False)
                    ax.text(-2, y + 0.2, "원본 구성 환산", ha="right", va="center", fontsize=8.5, color=MUTED,
                            clip_on=False)
                else:
                    ax.text(-2, y - 0.1, name, ha="right", va="center", fontsize=10.5, color=INK, clip_on=False)
                    ax.text(-2, y + 0.2, f"공격 {n:,} · 정상 {counts_benign[name]:,}", ha="right", va="center",
                            fontsize=8.5, color=MUTED, clip_on=False)
        ax.plot([0, 100], [0.74, 0.74], color=GRID, lw=0.8)
    share_att = sum(n for k, n in population.items() if k[0] == 1 and k[1] == "capec") / sum(
        n for k, n in population.items() if k[0] == 1)
    share_ben = sum(n for k, n in population.items() if k[0] == 0 and k[1] == "wcp") / sum(
        n for k, n in population.items() if k[0] == 0)
    fig.text(0.012, 0.015, f"전체: 출처별 원본 요청 수로 가중한 값(공격은 capec {share_att:.0%}, 정상은 wcp {share_ben:.0%} 비중). "
             "0.5% 미만 값은 표시하지 않음.", fontsize=8.5, color=MUTED)
    # 범례: 위쪽 한 줄
    handles = [Rectangle((0, 0), 1, 1, fc=c, ec="none") for _, c, _ in REGIONS]
    names = ["CRS만 걸림", "CRS·AI 모두 걸림", "AI만 걸림", "둘 다 안 걸림"]
    fig.legend(handles, names, loc="upper left", bbox_to_anchor=(0.008, 0.865), ncol=4, frameon=False,
               fontsize=10, handlelength=1.1, handleheight=1.1, columnspacing=1.6, labelcolor=INK2)
    save(fig, "t1-1-composition")


# ── 그림 2: 유형별 탐지율 ────────────────────────────────────────────────
SQL = re.compile(r"(union\s+(all\s+)?select|select\s.+\sfrom|\bor\b\s+\d+\s*=\s*\d+|'\s*or\s|sleep\(|benchmark\(|--|/\*)", re.I)
TYPE_NAMES = {"sqli_path": "SQLi · URL 경로에 구문", "sqli_none": "SQLi · 구문 흔적 없음*", "path_traversal": "경로 조작",
              "unlabeled": "csic 공격(유형 미표기)", "xss": "XSS", "sqli_qb": "SQLi · 쿼리·본문에 구문",
              "other": "기타 7개 유형", "code_injection": "코드 주입", "command_injection": "명령 주입",
              "xpath_injection": "XPath 주입", "ldap_injection": "LDAP 주입"}
OTHER = {"input_manipulation", "log4shell", "credential_attack", "protocol_manipulation", "xxe", "shellshock", "ssi"}


def type_rows():
    by_id = {r["sample_id"]: r for r in att}
    groups = collections.defaultdict(list)
    for line in open(D / "sample-census.jsonl", encoding="utf-8"):
        s = json.loads(line)
        r = by_id.get(s["sample_id"])
        if r is None:
            continue
        fam = r["family"]
        if fam == "sqli":
            p, q, b = (unquote_plus(s.get(k) or "") for k in ("path", "query", "body"))
            key = "sqli_path" if SQL.search(p) else "sqli_qb" if (SQL.search(q) or SQL.search(b)) else "sqli_none"
        else:
            key = "other" if fam in OTHER else fam
        groups[key].append(r)
    rows = [(TYPE_NAMES[k], len(v), sum(r["w"] for r in v) / len(v), sum(r["a"] for r in v) / len(v))
            for k, v in groups.items()]
    return sorted(rows, key=lambda t: t[3] - t[2], reverse=True)


def figure_by_type():
    rows = type_rows()
    fig = plt.figure(figsize=(9.5, 6.2))
    ax = fig.add_axes([0.27, 0.09, 0.53, 0.70])
    header(fig, "유형별 탐지율: 강한 영역이 서로 다르다",
           "공격 45,663건 전부(중복 제외) · 출처 4개 합산 · ModSecurity CRS(PL1·임계값 5) vs AI")
    n = len(rows)
    ax.set_xlim(0, 100)
    ax.set_ylim(n - 0.4, -0.7)
    for x in (0, 25, 50, 75, 100):
        ax.axvline(x, color=GRID, lw=0.8, zorder=0)
    ax.set_xticks([0, 25, 50, 75, 100], ["0%", "25%", "50%", "75%", "100%"])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)
    split = next(i for i, r in enumerate(rows) if r[3] - r[2] < 0)
    for i, (name, count, w, a) in enumerate(rows):
        ax.plot([100 * w, 100 * a], [i, i], color=AXIS, lw=2, solid_capstyle="round", zorder=1)
        dy = 0.13 if abs(w - a) < 0.02 else 0      # 겹치는 두 점은 위아래로 조금 벌린다(값은 오른쪽 표)
        ax.plot(100 * w, i - dy, "o", ms=9, color=CRS, mec=SURFACE, mew=1.6, zorder=3, clip_on=False)
        ax.plot(100 * a, i + dy, "o", ms=9, color=AI, mec=SURFACE, mew=1.6, zorder=3, clip_on=False)
        ax.text(-3, i - 0.13, name, ha="right", va="center", fontsize=10.5, color=INK, clip_on=False)
        ax.text(-3, i + 0.24, f"{count:,}건", ha="right", va="center", fontsize=8.5, color=MUTED, clip_on=False)
        ax.text(117, i, f"{100 * w:.1f}%", ha="right", va="center", fontsize=9.5, color=INK2, clip_on=False)
        ax.text(131, i, f"{100 * a:.1f}%", ha="right", va="center", fontsize=9.5, color=INK2, clip_on=False)
    ax.text(117, -0.65, "CRS", ha="right", va="bottom", fontsize=9.5, fontweight="bold", color=INK2, clip_on=False)
    ax.text(131, -0.65, "AI", ha="right", va="bottom", fontsize=9.5, fontweight="bold", color=INK2, clip_on=False)
    ax.axhline(split - 0.5, color=AXIS, lw=0.8, xmin=-0.48, xmax=1.33, clip_on=False)
    ax.text(-47, -0.62, "AI가 더 잘 잡음", ha="left", va="bottom", fontsize=9, color=MUTED, clip_on=False)
    ax.text(-47, split - 0.42, "CRS가 더 잘 잡음", ha="left", va="top", fontsize=9, color=MUTED, clip_on=False)
    handles = [plt.Line2D([], [], marker="o", ls="", ms=9, color=c, mec=SURFACE, mew=1.6) for c in (CRS, AI)]
    fig.legend(handles, ["CRS 탐지율", "AI 탐지율"], loc="upper left", bbox_to_anchor=(0.005, 0.875), ncol=2,
               frameon=False, fontsize=10, labelcolor=INK2, handletextpad=0.3, columnspacing=1.4)
    fig.text(0.012, 0.015, "* sqli 라벨이 붙었지만 요청에 SQL 구문이 보이지 않는 요청. 98%가 capec(공격 세션 전체에 라벨이 붙은 것으로 보여 라벨이 의심됨)",
             fontsize=8.5, color=MUTED)
    save(fig, "t1-2-by-type")


# ── 그림 3: PL × 임계값 트레이드오프 ────────────────────────────────────
def rates(rows, fn):
    a = [r for r in rows if r["label"] == 1]
    b = [r for r in rows if r["label"] == 0]
    return wrate(a, fn), wrate(b, fn)


def run_name(pl, t):
    return f"census-modsecurity-pl{pl}" if t == 5 else f"census-modsecurity-pl{pl}-t{t}"


THRESHOLDS = (20, 15, 10, 5)


def load_t1():
    """census 결과를 읽어 T1 그래프가 쓰는 값을 채운다."""
    global population, base, att, ben, waf_pts, or_pts, and_pts, ai_pt
    population = m.load_population(D / "sample-census.jsonl")
    base = load("census-modsecurity")        # 메인 WAF 설정(PL1·임계값 5)
    att = [r for r in base if r["label"] == 1]
    ben = [r for r in base if r["label"] == 0]
    grid = {(pl, t): load(run_name(pl, t)) for pl in (1, 2, 3, 4) for t in THRESHOLDS}
    waf_pts = {k: rates(v, lambda r: r["w"]) for k, v in grid.items()}
    or_pts = {t: rates(grid[(1, t)], lambda r: r["w"] or r["a"]) for t in THRESHOLDS}
    and_pts = {t: rates(grid[(1, t)], lambda r: r["w"] and r["a"]) for t in THRESHOLDS}
    ai_pt = rates(base, lambda r: r["a"])


def figure_tradeoff():
    fig = plt.figure(figsize=(9.5, 6.6))
    ax = fig.add_axes([0.075, 0.13, 0.63, 0.67])
    header(fig, "CRS 설정을 바꿔도 AI의 위치에 닿지 못한다",
           "ModSecurity CRS PL1~4 × 요청 임계값 20·15·10·5 (16조합) · census 86,067건 · 원본 출처 구성 환산")
    ax.set_xlim(-1.5, 66)
    ax.set_ylim(0, 100)
    for v in (0, 20, 40, 60, 80, 100):
        ax.axhline(v, color=GRID, lw=0.8, zorder=0)
    for v in (0, 20, 40, 60):
        ax.axvline(v, color=GRID, lw=0.8, zorder=0)
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60], [f"{v}%" for v in (0, 10, 20, 30, 40, 50, 60)])
    ax.set_yticks([0, 20, 40, 60, 80, 100], [f"{v}%" for v in (0, 20, 40, 60, 80, 100)])
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_xlabel("오탐률 (정상 요청 중 걸린 비율)", color=INK2, fontsize=10.5, labelpad=6)
    ax.text(-1.5, 103, "탐지율 (공격 요청 중 걸린 비율)", ha="left", va="bottom", fontsize=10.5, color=INK2)
    ax.tick_params(axis="x", pad=6)
    for pl, color in zip((1, 2, 3, 4), PL_RAMP):
        xs = [100 * waf_pts[(pl, t)][1] for t in THRESHOLDS]
        ys = [100 * waf_pts[(pl, t)][0] for t in THRESHOLDS]
        ax.plot(xs, ys, "-o", color=color, lw=2, ms=7, mec=SURFACE, mew=1.4, zorder=3, solid_capstyle="round")
        if pl == 2:
            ax.text(xs[-1] - 0.8, ys[-1] + 3.0, f"CRS PL{pl}", ha="right", va="center", fontsize=9.5, color=INK2)
        elif pl != 1:
            ax.text(xs[-1] + 1.2, ys[-1], f"CRS PL{pl}", ha="left", va="center", fontsize=9.5, color=INK2)
    for t in THRESHOLDS:                     # 임계값 숫자는 PL4 선에만
        x, y = 100 * waf_pts[(4, t)][1], 100 * waf_pts[(4, t)][0]
        if t == 20:   # 오른쪽 아래는 현재 설정 설명선이 지나가므로 왼쪽 아래에 둔다
            ax.text(x - 0.6, y - 1.6, "임계값 20", ha="right", va="top", fontsize=8.5, color=MUTED)
        else:
            ax.text(x + 0.8, y - 2.4, str(t), ha="left", va="top", fontsize=8.5, color=MUTED)
    for pts, color, label, pos in ((or_pts, OR, "CRS 또는 AI (PL1)", "end"), (and_pts, AND, "CRS 그리고 AI (PL1)", "above")):
        xs = [100 * pts[t][1] for t in THRESHOLDS]
        ys = [100 * pts[t][0] for t in THRESHOLDS]
        ax.plot(xs, ys, "-o", color=color, lw=2, ms=7, mec=SURFACE, mew=1.4, zorder=4, solid_capstyle="round")
        if pos == "end":
            ax.text(xs[-1] + 1.2, ys[-1], label, ha="left", va="center", fontsize=9.5, color=INK2)
        else:
            ax.text(0.2, ys[-1] + 6.5, label, ha="left", va="center", fontsize=9.5, color=INK2)
    ax.plot(100 * ai_pt[1], 100 * ai_pt[0], "D", ms=10, color=AI, mec=SURFACE, mew=1.6, zorder=5)
    # 핵심 점 설명(오른쪽 여백)
    notes = [(AI, "D", "AI 단독", f"{pct(ai_pt[0])} / {pct(ai_pt[1])}"),
             (OR, "o", "CRS 또는 AI · 임계값 10", f"{pct(or_pts[10][0])} / {pct(or_pts[10][1])}"),
             (PL_RAMP[0], "o", "현재 CRS (PL1·5)", f"{pct(waf_pts[(1, 5)][0])} / {pct(waf_pts[(1, 5)][1])}"),
             (AND, "o", "CRS 그리고 AI · 임계값 5", f"{pct(and_pts[5][0])} / {pct(and_pts[5][1])}"),
             (PL_RAMP[3], "o", "CRS 최고 탐지율 (PL4·5)", f"{pct(waf_pts[(4, 5)][0])} / {pct(waf_pts[(4, 5)][1])}")]
    fig.text(0.735, 0.835, "탐지율 / 오탐률", fontsize=9.5, fontweight="bold", color=INK2)
    for i, (color, marker, name, value) in enumerate(notes):
        y = 0.785 - i * 0.075
        fig.lines.append(plt.Line2D([0.742], [y + 0.004], marker=marker, ms=8 if marker == "o" else 9, color=color,
                                    mec=SURFACE, mew=1.4, transform=fig.transFigure))
        fig.text(0.758, y + 0.004, name, fontsize=9.5, color=INK, va="center")
        fig.text(0.758, y - 0.028, value, fontsize=9.5, color=INK2, va="center")
    ax.annotate("AI 단독", (100 * ai_pt[1], 100 * ai_pt[0]), xytext=(9, 97), fontsize=9.5, color=INK2,
                ha="left", va="center", arrowprops=dict(arrowstyle="-", color=AXIS, lw=0.8))
    ax.annotate("CRS PL1 · 현재 설정", (100 * waf_pts[(1, 5)][1], 100 * waf_pts[(1, 5)][0]), xytext=(27, 29),
                fontsize=9.5, color=INK2, ha="left", va="center", arrowprops=dict(arrowstyle="-", color=AXIS, lw=0.8))
    fig.text(0.012, 0.015, "선 위의 점은 요청 임계값 20 → 15 → 10 → 5 (임계값이 낮을수록 더 많이 걸린다). 왼쪽 위로 갈수록 좋다.",
             fontsize=8.5, color=MUTED)
    save(fig, "t1-3-tradeoff")


# ── 그림 4: 공격 비율별 정밀도 ──────────────────────────────────────────
def figure_precision():
    import numpy as np
    series = [("CRS 단독 (PL1·5)", CRS, waf_pts[(1, 5)]), ("AI 단독", AI, ai_pt),
              ("CRS 그리고 AI (PL1·5)", AND, and_pts[5]), ("CRS 또는 AI (PL1·10)", OR, or_pts[10])]
    fig = plt.figure(figsize=(9.5, 5.6))
    ax = fig.add_axes([0.075, 0.13, 0.67, 0.62])
    header(fig, "공격이 드물수록 오탐률이 정밀도를 좌우한다",
           "정밀도 = 걸린 요청 중 실제 공격 비율 · 탐지율·오탐률(census, 원본 구성 환산)에 공격 비율을 가정해 계산")
    base_rates = np.logspace(-3, np.log10(0.5), 200)
    ax.set_xscale("log")
    ax.set_xlim(1e-3, 0.5)
    ax.set_ylim(0, 100)
    for v in (0, 20, 40, 60, 80, 100):
        ax.axhline(v, color=GRID, lw=0.8, zorder=0)
    for v in (0.001, 0.01, 0.1):
        ax.axvline(v, color=GRID, lw=0.8, zorder=0)
    ax.set_xticks([0.001, 0.01, 0.1, 0.5], ["0.1%", "1%", "10%", "50%"])
    ax.minorticks_off()
    ax.set_yticks([0, 20, 40, 60, 80, 100], [f"{v}%" for v in (0, 20, 40, 60, 80, 100)])
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_xlabel("전체 요청 중 공격 비율 (로그 눈금)", color=INK2, fontsize=10.5, labelpad=6)
    ax.text(1e-3, 103, "정밀도 (걸린 요청 중 실제 공격 비율)", ha="left", va="bottom", fontsize=10.5, color=INK2)
    ax.tick_params(axis="x", pad=7)
    table = []
    for name, color, (tpr, fpr) in series:
        prec = 100 * tpr * base_rates / (tpr * base_rates + fpr * (1 - base_rates))
        ax.plot(base_rates, prec, color=color, lw=2, solid_capstyle="round", zorder=3)
        p1 = tpr * 0.01 / (tpr * 0.01 + fpr * 0.99)
        p10 = tpr * 0.1 / (tpr * 0.1 + fpr * 0.9)
        table.append((name, color, tpr, fpr, p1, p10))
    for x in (0.01, 0.1):
        for _, color, tpr, fpr, *_ in table:
            ax.plot(x, 100 * tpr * x / (tpr * x + fpr * (1 - x)), "o", ms=7, color=color, mec=SURFACE, mew=1.4, zorder=4)
    # 오른쪽 표: 탐지율·오탐률과 공격 1%·10%일 때 정밀도
    fig.text(0.775, 0.80, "공격 1%일 때 / 10%일 때", fontsize=9.5, fontweight="bold", color=INK2)
    for i, (name, color, tpr, fpr, p1, p10) in enumerate(sorted(table, key=lambda t: -t[4])):
        y = 0.74 - i * 0.105
        fig.lines.append(plt.Line2D([0.775, 0.795], [y + 0.004] * 2, color=color, lw=2.5, transform=fig.transFigure,
                                    solid_capstyle="round"))
        fig.text(0.802, y + 0.004, name, fontsize=9.5, color=INK, va="center")
        fig.text(0.802, y - 0.034, f"{pct(p1)} / {pct(p10)}", fontsize=9.5, color=INK2, va="center")
    fig.text(0.012, 0.015, "점: 공격 비율 1%·10% 가정. 탐지율·오탐률은 데이터셋 기준이며 실제 서비스의 공격 비율은 측정하지 않았다.",
             fontsize=8.5, color=MUTED)
    save(fig, "t1-4-precision")


# ── T3·T4: 부하 측정(dev_tools/load-test) ──────────────────────────────────
LOAD = D / "load-test"
DIRECT = "#898781"                                   # 기준선(직접 접속)은 회색, WAF는 CRS 파랑
RPS_RAMP = ["#86b6ef", "#2a78d6", "#104281"]         # 10·50·100 RPS: 파랑 순서형 단계(--ordinal 통과)
RATES = (10, 50, 100)


LATENCY_SERIES = [("direct", "직접 접속", DIRECT), ("wafonly", "WAF만 (분석 파이프라인 정지)", RPS_RAMP[0]),
                  ("waf", "WAF + 분석 파이프라인 동시 처리", CRS)]


def fmt_ms(v):
    return f"{v / 1000:.1f}초" if v >= 1000 else f"{v:.1f}ms" if v < 100 else f"{v:.0f}ms"


def figure_user_latency(summary, control):
    """직접 접속 vs WAF만 vs WAF+파이프라인. control은 파이프라인을 멈추고 잰 WAF 경유 결과(latency-waf-only)."""
    series = {"direct": summary, "waf": summary, "wafonly": {k.replace("waf-", "wafonly-"): v for k, v in control.items()}}
    rates = [r for r in RATES if all(f"{key}-{r}" in series[key] for key, _, _ in LATENCY_SERIES)]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.9), gridspec_kw={"wspace": 0.12})
    fig.subplots_adjust(left=0.085, right=0.97, top=0.66, bottom=0.2)
    reps = summary[f"waf-{rates[0]}"]["reps"]
    header(fig, "WAF는 응답에 4~6ms를 더한다. 같은 PC의 분석 파이프라인이 더 큰 변수다",
           f"JuiceShop 정상 요청 15종 · 일정 도착률 60초씩 · 직접 접속·WAF+파이프라인 {reps}회, WAF만 1회 · 로컬 PC(Ryzen 5 7500F)")
    for ax, key, title in ((axes[0], "p50", "중앙값(p50)"), (axes[1], "p95", "p95 (느린 5%의 경계)")):
        vals = [series[s_][f"{s_}-{r}"][key] for s_, _, _ in LATENCY_SERIES for r in rates]
        ax.set_xscale("log")
        lo, hi = min(vals) / 1.6, max(vals) * 1.6
        ax.set_xlim(lo, hi)
        steps = (1, 10, 100, 1000, 10000) if hi / lo > 100 else (1, 2, 5, 10, 20, 50, 100, 200, 500)   # 넓으면 10배 단위
        ticks = [t for t in steps if lo <= t <= hi]
        ax.set_xticks(ticks, [fmt_ms(t).replace(".0", "") for t in ticks])
        ax.minorticks_off()
        ax.set_ylim(len(rates) - 0.5, -0.65)
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.set_yticks(range(len(rates)), [f"{r} RPS" for r in rates] if ax is axes[0] else [""] * len(rates))
        ax.tick_params(axis="y", labelsize=10.5, labelcolor=INK)
        ax.grid(axis="x", color=GRID, lw=0.8)
        ax.set_axisbelow(True)
        ax.text(lo, -0.8, f"{title} · 로그 눈금", ha="left", va="bottom", fontsize=11, fontweight="bold", color=INK)
        for i, rate in enumerate(rates):
            row = [series[s_][f"{s_}-{rate}"][key] for s_, _, _ in LATENCY_SERIES]
            ax.plot([min(row), max(row)], [i, i], color=AXIS, lw=2, solid_capstyle="round", zorder=1)
            for (s_, _, color), v in zip(LATENCY_SERIES, row):
                ax.plot(v, i, "o", ms=9, color=color, mec=SURFACE, mew=1.6, zorder=3)
            # 값은 행마다 한 줄로(직접 → WAF만 → +파이프라인)
            ax.text(lo * 1.08, i + 0.3, " → ".join(fmt_ms(v) for v in row), ha="left", va="center", fontsize=8.5,
                    color=INK2)
    handles = [plt.Line2D([], [], marker="o", ls="", ms=9, color=c, mec=SURFACE, mew=1.6) for _, _, c in LATENCY_SERIES]
    fig.legend(handles, [name for _, name, _ in LATENCY_SERIES], loc="upper left", bbox_to_anchor=(0.005, 0.86),
               ncol=3, frameon=False, fontsize=10, labelcolor=INK2, handletextpad=0.3, columnspacing=1.4)
    fig.text(0.012, 0.035, "AI 분석은 Kafka로 비동기 처리돼 응답 경로에 없다. 하지만 같은 PC에서 AI(약 1.4코어)·Kafka·백엔드가 로그를 처리하면\n"
             "CPU를 나눠 써서, 처리 한계에 가까운 100 RPS에서 JuiceShop DB 조회 API에 대기열이 쌓였다(파이프라인을 멈추면 사라짐).",
             fontsize=8.5, color=MUTED, linespacing=1.5)
    save(fig, "t4-1-user-latency")


COMPONENTS = [("juiceshop", "JuiceShop", "보호 대상 앱"), ("waf", "WAF (ModSecurity)", "WAF"),
              ("security-ai-local", "AI 추론 서버", "분석 파이프라인"), ("kafka", "Kafka", "분석 파이프라인"),
              ("security-backend-local", "백엔드 (Spring)", "분석 파이프라인"), ("security-mysql", "MySQL", "분석 파이프라인"),
              ("zookeeper", "Zookeeper", "분석 파이프라인"), ("waf-fluent-bit", "Fluent Bit", "분석 파이프라인")]


def figure_resources(summary):
    rates = [r for r in RATES if f"waf-{r}" in summary]
    fig, (ax_cpu, ax_mem) = plt.subplots(1, 2, figsize=(10.5, 5.6), gridspec_kw={"width_ratios": [1.45, 1], "wspace": 0.08})
    fig.subplots_adjust(left=0.215, right=0.97, top=0.72, bottom=0.17)
    header(fig, "추가 비용은 대부분 AI와 Kafka에서 나온다",
           "WAF 경유 부하 동안 컨테이너별 평균 CPU(1 = CPU 코어 1개)와 최대 메모리 · docker stats 약 1초 간격 · 로컬 PC(Ryzen 5 7500F)")
    n = len(COMPONENTS)
    group_h = 0.78
    bar_h = group_h / len(rates)
    cpu = {r: summary[f"waf-{r}"]["resources"] for r in rates}
    top_cpu = max(v["cpu_mean"] for r in rates for v in cpu[r].values()) / 100
    for ax in (ax_cpu, ax_mem):
        ax.set_ylim(n - 0.4, -0.75)
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.set_yticks([])
        ax.grid(axis="x", color=GRID, lw=0.8)
        ax.set_axisbelow(True)
    ax_cpu.set_xlim(0, top_cpu * 1.22)
    ax_cpu.xaxis.set_major_formatter(lambda v, _: f"{v:g}")
    ax_cpu.text(0, -0.8, "평균 CPU (코어)", ha="left", va="bottom", fontsize=11, fontweight="bold", color=INK)
    for i, (key, name, group) in enumerate(COMPONENTS):
        for j, (rate, color) in enumerate(zip(rates, RPS_RAMP)):
            v = cpu[rate].get(key, {}).get("cpu_mean", 0) / 100
            y = i - group_h / 2 + bar_h * (j + 0.5)
            rounded_hbar(ax_cpu, y, v, bar_h * 0.86, color)
            if j == len(rates) - 1:
                ax_cpu.text(v + top_cpu * 0.015, y, f"{v:.2f}", va="center", fontsize=8.5, color=INK2)
        ax_cpu.text(-top_cpu * 0.03, i, name, ha="right", va="center", fontsize=10, color=INK, clip_on=False)
    mem_rate = rates[-1]
    mem = {k: summary[f"waf-{mem_rate}"]["resources"].get(k, {}).get("mem_max", 0) / 1024 for k, _, _ in COMPONENTS}
    top_mem = max(mem.values())
    ax_mem.set_xlim(0, top_mem * 1.3)
    ax_mem.xaxis.set_major_formatter(lambda v, _: f"{v:g}")
    ax_mem.text(0, -0.8, f"최대 메모리 (GiB, {mem_rate} RPS)", ha="left", va="bottom", fontsize=11, fontweight="bold", color=INK)
    for i, (key, _, _) in enumerate(COMPONENTS):
        rounded_hbar(ax_mem, i, mem[key], 0.42, CRS)
        ax_mem.text(mem[key] + top_mem * 0.02, i, f"{mem[key]:.2f}", va="center", fontsize=8.5, color=INK2)
    # 그룹 구분선과 이름(왼쪽 여백). 분석 파이프라인이 WAF 단독 구성 대비 추가되는 부분이다.
    groups = [g for _, _, g in COMPONENTS]
    left_margin = blended_transform_factory(fig.transFigure, ax_cpu.transData)
    for i, g in enumerate(groups):
        if i == 0 or groups[i - 1] != g:
            if i:
                for ax in (ax_cpu, ax_mem):
                    ax.axhline(i - 0.5, color=AXIS, lw=0.8)
            ax_cpu.text(0.012, i - 0.42, g, transform=left_margin, ha="left", va="top", fontsize=9, color=MUTED)
    handles = [Rectangle((0, 0), 1, 1, fc=c, ec="none") for c in RPS_RAMP[:len(rates)]]
    fig.legend(handles, [f"{r} RPS" for r in rates], loc="upper left", bbox_to_anchor=(0.005, 0.875), ncol=len(rates),
               frameon=False, fontsize=10, labelcolor=INK2, handlelength=1.1, handleheight=1.1, columnspacing=1.4)
    pipeline = [k for k, _, g in COMPONENTS if g == "분석 파이프라인"]
    res = summary[f"waf-{mem_rate}"]["resources"]
    add_cpu = sum(res.get(k, {}).get("cpu_mean", 0) for k in pipeline) / 100
    add_mem = sum(res.get(k, {}).get("mem_max", 0) for k in pipeline) / 1024
    waf_cpu, waf_mem = res["waf"]["cpu_mean"] / 100, res["waf"]["mem_max"] / 1024
    fig.text(0.012, 0.035, f"{mem_rate} RPS 기준 WAF {waf_cpu:.2f}코어·{waf_mem:.2f}GiB, 분석 파이프라인 합계 {add_cpu:.2f}코어·{add_mem:.2f}GiB.\n"
             "AI는 Kafka로 받은 요청을 한 건씩 처리해 초당 약 5건이 한계였고, 10 RPS부터 AI CPU가 같은 값(포화)에 머문다.\n"
             "AI 스레드를 1개로 제한(OMP_NUM_THREADS=1)하면 AI CPU는 10 RPS 0.16코어, 50 RPS 0.75코어로 줄고 한계는 초당 84건이다(t4-3).",
             fontsize=8.5, color=MUTED, linespacing=1.5)
    save(fig, "t3-resources")


DET_CONDITIONS = [("idle", "공격만 초당 2건"), ("load5", "정상 3 + 공격 2 = 초당 5건"), ("load10", "정상 8 + 공격 2 = 초당 10건")]
DET_STAGES = [("WAF 기록 → Kafka (Fluent Bit 수집)", "t0", "k_log"), ("Kafka → 로그 저장 (백엔드)", "k_log", "t_saved"),
              ("AI 요청 발행 (백엔드)", "t_saved", "k_ai_req"), ("AI 대기·추론", "k_ai_req", "k_ai_res"),
              ("AI 결과 → 위협 저장 (백엔드)", "k_ai_res", "t_ai_detected")]
DET_FIELDS = ("t0", "k_log", "t_saved", "k_ai_req", "k_ai_res", "t_ai_detected", "t_waf_detected")


def read_detection(path):
    rows = []
    for r in csv.DictReader(open(path, encoding="utf-8")):
        rows.append({k: (float(r[k]) if r.get(k) not in (None, "", "None") else None) for k in DET_FIELDS})
    return rows


def median(values):
    values = sorted(values)
    n = len(values)
    return (values[n // 2] + values[(n - 1) // 2]) / 2 if n else float("nan")


def span(rows, a, b):
    """두 시각의 차이(초). WSL2 시계 보정으로 드물게 생기는 음수는 뺀다."""
    return [r[b] - r[a] for r in rows if r[a] is not None and r[b] is not None and r[b] >= r[a]]


def figure_detection_latency(det_dir):
    data = {c: read_detection(det_dir / c / "latency.csv") for c, _ in DET_CONDITIONS if (det_dir / c / "latency.csv").exists()}
    fig, (ax_t, ax_s) = plt.subplots(1, 2, figsize=(11, 5.4), gridspec_kw={"width_ratios": [1.3, 1], "wspace": 0.16})
    fig.subplots_adjust(left=0.075, right=0.95, top=0.74, bottom=0.23)
    waf_meds = [median(span(data[c], "t0", "t_waf_detected")) for c, _ in DET_CONDITIONS if c in data]
    header(fig, "AI 처리량을 넘으면 AI 탐지가 밀린다 · 스레드 설정으로 풀린다" if (det_dir.parent / "detection-omp1").exists()
           else "AI 처리량을 넘으면 AI 탐지가 밀린다",
           f"AI가 공격으로 판정한 공격 요청 300건을 초당 2건 보내고 요청부터 위협 저장까지 시간을 쟀다 · "
           f"CRS 탐지 경로는 세 조건 모두 중앙값 {max(waf_meds):.1f}초 이하 · 로컬 PC")
    colors = dict(zip([c for c, _ in DET_CONDITIONS], RPS_RAMP))
    handles, names = [], []
    for cond, label in DET_CONDITIONS:
        rows = sorted((r for r in data.get(cond, []) if r["t_ai_detected"] is not None and r["t_ai_detected"] > r["t0"]),
                      key=lambda r: r["t0"])
        if not rows:
            continue
        start = rows[0]["t0"]
        ys = [r["t_ai_detected"] - r["t0"] for r in rows]
        line, = ax_t.plot([r["t0"] - start for r in rows], ys, color=colors[cond], lw=2,
                          solid_capstyle="round", solid_joinstyle="round")
        handles.append(line)
        names.append(f"기본 · {label} · 중앙값 {median(ys):.1f}초")
    fixed = det_dir.parent / "detection-omp1/load10/latency.csv"     # AI 스레드 1개로 같은 조건을 다시 잰 결과
    if fixed.exists():
        rows = sorted((r for r in read_detection(fixed) if r["t_ai_detected"] is not None and r["t_ai_detected"] > r["t0"]),
                      key=lambda r: r["t0"])
        ys = [r["t_ai_detected"] - r["t0"] for r in rows]
        line, = ax_t.plot([r["t0"] - rows[0]["t0"] for r in rows], ys, color=AI, lw=2, solid_capstyle="round")
        handles.append(line)
        names.append(f"스레드 1개 · 정상 8 + 공격 2 = 초당 10건 · 중앙값 {median(ys):.2f}초")
    for spine in ax_t.spines.values():
        spine.set_visible(False)
    ax_t.set_yscale("log")
    ax_t.set_ylim(0.1, 300)
    ticks = [0.1, 0.3, 1, 3, 10, 30, 100, 300]
    ax_t.set_yticks(ticks, [f"{t:g}초" for t in ticks])
    ax_t.minorticks_off()
    ax_t.grid(axis="y", color=GRID, lw=0.8)
    ax_t.set_axisbelow(True)
    ax_t.set_xlabel("공격 요청을 보낸 시각 (초)", color=INK2, fontsize=10, labelpad=6)
    ax_t.text(0, 340, "요청 하나가 AI 위협으로 저장되기까지 (로그 눈금)", ha="left", va="bottom", fontsize=11,
              fontweight="bold", color=INK)
    # 범례는 데이터가 없는 오른쪽 1~10초 띠에 둔다
    ax_t.legend(handles, names, loc="center right", bbox_to_anchor=(1.0, 0.45), frameon=False, fontsize=9,
                labelcolor=INK2, handlelength=1.6)
    # 단계별 중앙값(공격만 보낼 때). 스레드 1개 결과가 있으면 나란히 놓는다.
    series = [("기본", DIRECT if (det_dir.parent / "detection-omp1/idle/latency.csv").exists() else CRS, data.get("idle", []))]
    fixed_idle = det_dir.parent / "detection-omp1/idle/latency.csv"
    if fixed_idle.exists():
        series.append(("스레드 1개", AI, read_detection(fixed_idle)))
    meds = [[median(span(rows, a, b)) for _, a, b in DET_STAGES] for _, _, rows in series]
    totals = [median(span(rows, "t0", "t_ai_detected")) for _, _, rows in series]
    total_waf = median(span(data.get("idle", []), "t0", "t_waf_detected"))
    n = len(DET_STAGES)
    ax_s.set_ylim(n - 0.3, -0.9)
    smax = max(max(m) for m in meds)
    ax_s.set_xlim(0, smax * 1.3)
    for spine in ax_s.spines.values():
        spine.set_visible(False)
    ax_s.set_yticks([])
    ax_s.grid(axis="x", color=GRID, lw=0.8)
    ax_s.set_axisbelow(True)
    ax_s.xaxis.set_major_formatter(lambda v, _: f"{v:g}초")
    bar_h = 0.34 / len(series)
    fmt = lambda v: "1ms 미만" if v < 0.001 else f"{v * 1000:.0f}ms"
    for i, (name, _, _) in enumerate(DET_STAGES):     # 단계 이름은 막대 위에 쓴다
        ax_s.text(0, i - 0.16, name, ha="left", va="bottom", fontsize=9.5, color=INK)
        values = [max(m[i], 0) for m in meds]
        for j, ((label, color, _), v) in enumerate(zip(series, values)):
            y = i + 0.12 + (j - (len(series) - 1) / 2) * bar_h * 1.15
            single = len(series) == 1
            rounded_hbar(ax_s, y, v, bar_h, (AI if name.startswith("AI 대기") else CRS) if single else color)
        # 값은 단계마다 한 번(기본 → 스레드 1개)
        text = " → ".join(dict.fromkeys(fmt(v) for v in values)) if len(series) > 1 else fmt(values[0])
        ax_s.text(max(values) + smax * 0.02, i + 0.12, text, va="center", fontsize=9, color=INK2)
    if len(series) == 1:
        title = f"단계별 중앙값 (공격만 보낼 때)\nAI 탐지까지 {totals[0]:.2f}초 · CRS 탐지까지 {total_waf:.2f}초"
    else:
        title = f"단계별 중앙값 (공격만 보낼 때)\nAI 탐지까지 기본 {totals[0]:.2f}초 → 스레드 1개 {totals[1]:.2f}초"
        ax_s.legend([Rectangle((0, 0), 1, 1, fc=c, ec="none") for _, c, _ in series], [l for l, _, _ in series],
                    loc="lower right", frameon=False, fontsize=9, labelcolor=INK2, handlelength=1.1, handleheight=1.1)
    ax_s.text(0, -0.95, title, ha="left", va="bottom", fontsize=11, fontweight="bold", color=INK, linespacing=1.4)
    fig.text(0.012, 0.03, "단계 시각: Kafka 기록 시각(CreateTime)과 DB 저장 시각(created_at, detected_at; DB가 KST로 저장해 9시간 보정).\n"
             "AI는 Kafka 메시지를 한 건씩 처리해 초당 약 5건이 한계였다(기본 스레드 설정, 1개로 제한하면 초당 84건 · t4-3 그래프).\n"
             "로그(정상 요청 포함)가 그보다 많이 들어오면 대기열이 늘어난다.",
             fontsize=8.5, color=MUTED, linespacing=1.5)
    save(fig, "t4-2-detection-latency")


def ai_fix_metrics():
    """AI 스레드 설정 개선 전후 지표. 개선 후 탐지 지연은 측정했을 때만(detection-omp1) 넣는다."""
    k = json.loads((LOAD / "ai-threads/summary.json").read_text(encoding="utf-8"))["kafka_path"]
    metrics = [("Kafka 경로 초당 처리 건수", k["default"]["rate"], k["omp_num_threads_1"]["rate"], lambda v: f"{v:.1f}건/s"),
               ("메시지 1건당 CPU 시간", k["default"]["cpu_ms_per_msg"], k["omp_num_threads_1"]["cpu_ms_per_msg"],
                lambda v: f"{v:.0f}ms")]
    det_before, det_after = LOAD / "detection/load10/latency.csv", LOAD / "detection-omp1/load10/latency.csv"
    if det_before.exists() and det_after.exists():
        meds = [median(span(read_detection(path), "t0", "t_ai_detected")) for path in (det_before, det_after)]
        metrics.append(("AI 탐지 지연 중앙값 · 로그 초당 10건", *meds, lambda v: f"{v:.1f}초" if v >= 10 else f"{v:.2f}초"))
    return k, metrics


def figure_ai_threads():
    k, metrics = ai_fix_metrics()
    rows = [("기본 설정", DIRECT), ("OMP_NUM_THREADS=1", AI)]
    ncols = min(len(metrics), 3)                 # 지표 3개까지는 한 줄
    nrows = (len(metrics) + ncols - 1) // ncols
    width, height = 3.6 * ncols + 1.6, 2.2 + 1.9 * nrows
    fig, axes = plt.subplots(nrows, ncols, figsize=(width, height), squeeze=False,
                             gridspec_kw={"wspace": 0.12, "hspace": 0.9})
    fig.subplots_adjust(left=1.75 / width, right=0.96, top=1 - 1.45 / height, bottom=0.8 / height)
    gain = k["omp_num_threads_1"]["rate"] / k["default"]["rate"]
    header(fig, f"AI 스레드 수를 1개로 제한하면 처리량이 {gain:.0f}배가 되고 탐지 지연이 풀린다" if len(metrics) > 2
           else f"AI 스레드 수를 1개로 제한하면 Kafka 경로 처리량이 {gain:.0f}배가 된다",
           "같은 AI 이미지·같은 Kafka 경로에서 OMP_NUM_THREADS만 바꿔 쟀다 · 로컬 PC(Ryzen 5 7500F, 논리 CPU 12개)")
    for idx, (title, before, after, fmt) in enumerate(metrics):
        ax = axes[idx // ncols][idx % ncols]
        top = max(before, after)
        ax.set_xlim(0, top * 1.3)
        ax.set_ylim(len(rows) - 0.4, -0.75)
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.set_yticks([])
        ax.grid(axis="x", color=GRID, lw=0.8)
        ax.set_axisbelow(True)
        ax.xaxis.set_major_formatter(lambda v, _: "")
        ax.tick_params(axis="x", length=0)
        ax.text(0, -0.85, title, ha="left", va="bottom", fontsize=11, fontweight="bold", color=INK)
        for i, ((name, color), v) in enumerate(zip(rows, (before, after))):
            rounded_hbar(ax, i, v, 0.42, color)
            ax.text(v + top * 0.02, i, fmt(v), va="center", fontsize=10, color=INK2)
            if idx % ncols == 0:
                ax.text(-top * 0.03, i, name, ha="right", va="center", fontsize=10, color=INK, clip_on=False)
    for idx in range(len(metrics), nrows * ncols):
        axes[idx // ncols][idx % ncols].axis("off")
    fig.text(0.012, 0.02, f"기본 {k['default']['rate']:.1f}건/s·CPU {k['default']['cpu']:.2f}코어, 스레드 1개 "
             f"{k['omp_num_threads_1']['rate']:.1f}건/s·{k['omp_num_threads_1']['cpu']:.2f}코어. 기본 설정은 한 건을 처리할 때도 여러 CPU 스레드를 써서\n"
             "같은 처리량에 CPU를 훨씬 많이 쓰고, 여러 스레드에서 호출된 뒤에는 계속 느려졌다(묶음 호출 74 → 24건/s). 운영 반영 여부는 AI 팀이 정한다.",
             fontsize=8.5, color=MUTED, linespacing=1.5)
    save(fig, "t4-3-ai-threads")


# ── XAI: 판정 근거 설명 평가 (dev_tools/scripts/eval_xai_explanations.py) ───────────
XAI_RESULTS = D / "xai-eval/results.json"
SHAP_C, REASON_C, RANDOM_C = CRS, "#898781", NEITHER   # 새 설명(SHAP)만 파랑으로 강조, 비교 대상은 회색 두 단계
PATTERN_C, STRUCT_C = AND, OR      # 시그니처 근거(초록)·요청 구조 근거(노랑): 슬롯 3·4, 인접 쌍 색각 검증 통과
XAI_REGIONS = [("검토 권장 표시", STRUCT_C, None), ("표시 없음", PATTERN_C, None)]


def signed(v, digits=2):
    return f"{v:+.{digits}f}"     # 맑은 고딕에 U+2212(−)가 없어 ASCII 하이픈을 쓴다(axes.unicode_minus=False와 같은 이유)


def percent_axis(ax, ticks):
    ax.set_xlim(ticks[0], ticks[-1])
    for x in ticks:
        ax.axvline(x, color=GRID, lw=0.8, zorder=0)
    ax.set_xticks(ticks, [f"{t:g}%" for t in ticks])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)


def panel_title(ax, y, text):
    ax.text(ax.get_xlim()[0], y, text, ha="left", va="bottom", fontsize=11, fontweight="bold", color=INK)


def figure_xai_faithfulness(res):
    f, n = res["faithfulness"], res["population"]["model_decided"]
    same, no_ev = f["same_size_as_reason"], f["no_evidence_reason_cases"]
    fig, (ax_k, ax_s) = plt.subplots(1, 2, figsize=(11, 4.5), gridspec_kw={"width_ratios": [1.1, 1], "wspace": 0.5})
    fig.subplots_adjust(left=0.075, right=0.955, top=0.71, bottom=0.17)
    header(fig, "설명이 짚은 근거를 바꾸면 판정이 뒤집힌다",
           f"census 모델 판정 탐지 {n:,}건 · 설명이 지목한 피처를 정상 요청의 기준값(중앙값)으로 바꿔 다시 판정했을 때 정상으로 뒤집힌 비율")
    for ax in (ax_k, ax_s):
        percent_axis(ax, [0, 25, 50, 75, 100])
    # 왼쪽: 바꾼 피처 수별 SHAP 상위 vs 무작위
    ax_k.set_ylim(2.55, -0.85)
    for i, k in enumerate((1, 2, 3)):
        for dy, key, color in ((-0.19, f"shap_top{k}", SHAP_C), (0.19, f"random{k}", RANDOM_C)):
            v = 100 * f[key]["flip_rate"]
            rounded_hbar(ax_k, i + dy, v, 0.34, color)
            ax_k.text(v + 1.5, i + dy, f"{v:.1f}%", ha="left", va="center", fontsize=9.5, color=INK2, clip_on=False)
        ax_k.text(-3, i, f"{k}개", ha="right", va="center", fontsize=10.5, color=INK, clip_on=False)
    panel_title(ax_k, -0.6, "바꾼 피처 수별")
    # 오른쪽: 기존 reason과 같은 개수로 비교
    rows = sorted([("SHAP 설명", same["shap"]["flip_rate"], SHAP_C),
                   ("기존 reason", same["current_reason"]["flip_rate"], REASON_C),
                   ("무작위", same["random"]["flip_rate"], RANDOM_C)], key=lambda r: -r[1])
    ax_s.set_ylim(2.55, -0.85)
    for i, (name, v, color) in enumerate(rows):
        rounded_hbar(ax_s, i, 100 * v, 0.5, color)
        ax_s.text(100 * v + 1.5, i, pct(v), ha="left", va="center", fontsize=9.5, color=INK2, clip_on=False)
        ax_s.text(-3, i, name, ha="right", va="center", fontsize=10.5, color=INK, clip_on=False)
    panel_title(ax_s, -0.6, f"기존 reason과 같은 개수로 · {same['current_reason']['n']:,}건(평균 {same['mean_size']:.1f}개)")
    handles = [Rectangle((0, 0), 1, 1, fc=c, ec="none") for c in (SHAP_C, REASON_C, RANDOM_C)]
    fig.legend(handles, ["SHAP 설명이 지목한 피처", "기존 reason이 언급한 피처", "무작위로 고른 피처"],
               loc="upper left", bbox_to_anchor=(0.008, 0.865), ncol=3, frameon=False, fontsize=10,
               handlelength=1.1, handleheight=1.1, columnspacing=1.6, labelcolor=INK2)
    fig.text(0.012, 0.025, f"기존 reason이 '통계적 이상'(근거 없음)이던 {no_ev['n']:,}건도 SHAP 상위 3개를 바꾸면 "
             f"{pct(no_ev['shap_top3']['flip_rate'])}가 뒤집힌다. 트랜스포머(가중치 0.05) 확률은 고정했다.",
             fontsize=8.5, color=MUTED)
    save(fig, "xai-1-faithfulness")


def figure_xai_review(res):
    c = res["trust"]["review_flag"]["counts"]
    flagged, unflagged = c["flagged_tp"] + c["flagged_fp"], c["unflagged_tp"] + c["unflagged_fp"]
    fp, tp = c["flagged_fp"] + c["unflagged_fp"], c["flagged_tp"] + c["unflagged_tp"]
    fig, (ax_r, ax_c) = plt.subplots(1, 2, figsize=(11, 4.2), gridspec_kw={"width_ratios": [1, 1.15], "wspace": 0.45})
    fig.subplots_adjust(left=0.14, right=0.97, top=0.71, bottom=0.18)
    header(fig, f"'검토 권장' 표시가 없는 모델 판정은 오탐이 {pct(c['unflagged_fp'] / unflagged)}",
           f"census 모델 판정 탐지 {flagged + unflagged:,}건 · 트리 기여 중 시그니처 근거 비율이 0.5 미만이면 "
           "'검토 권장'(기준은 평가 전에 정함)")
    # 왼쪽: 표시 여부별 오탐 비율
    groups = [("검토 권장 표시", flagged, c["flagged_fp"] / flagged, STRUCT_C),
              ("표시 없음", unflagged, c["unflagged_fp"] / unflagged, PATTERN_C)]
    percent_axis(ax_r, [0, 5, 10, 15])
    ax_r.set_ylim(1.75, -0.85)
    for i, (name, count, rate, color) in enumerate(groups):
        rounded_hbar(ax_r, i, 100 * rate, 0.5, color)
        ax_r.text(100 * rate + 0.3, i, pct(rate), ha="left", va="center", fontsize=9.5, color=INK2, clip_on=False)
        ax_r.text(-0.5, i - 0.1, name, ha="right", va="center", fontsize=10.5, color=INK, clip_on=False)
        ax_r.text(-0.5, i + 0.22, f"{count:,}건", ha="right", va="center", fontsize=8.5, color=MUTED, clip_on=False)
    overall = fp / (fp + tp)
    ax_r.plot([100 * overall] * 2, [-0.35, 1.45], color=INK2, lw=1, ls=(0, (3, 3)), zorder=2)
    ax_r.text(100 * overall + 0.3, 1.45, f"전체 {pct(overall)}", ha="left", va="center", fontsize=8.5, color=INK2)
    panel_title(ax_r, -0.6, "오탐 비율 (정상 라벨인 탐지)")
    # 오른쪽: 오탐·정탐이 표시된 쪽에 들어간 비율
    ax_c.set_xlim(0, 100)
    ax_c.set_ylim(1.75, -0.85)
    ax_c.axis("off")
    panel_title(ax_c, -0.6, "어느 쪽에 들어갔나")
    for i, (name, a, b) in enumerate([(f"오탐 {fp:,}건", c["flagged_fp"], c["unflagged_fp"]),
                                      (f"정탐 {tp:,}건", c["flagged_tp"], c["unflagged_tp"])]):
        above = draw_stack(ax_c, i, [a / (a + b), b / (a + b)], 0.5, fig, regions=XAI_REGIONS)
        place_above(ax_c, fig, i - 0.29, above)
        ax_c.text(-2, i, name, ha="right", va="center", fontsize=10.5, color=INK, clip_on=False)
    handles = [Rectangle((0, 0), 1, 1, fc=color, ec="none") for _, color, _ in XAI_REGIONS]
    fig.legend(handles, ["검토 권장 표시 (요청 구조 근거 위주)", "표시 없음 (시그니처 근거 위주)"],
               loc="upper left", bbox_to_anchor=(0.008, 0.865), ncol=2, frameon=False, fontsize=10,
               handlelength=1.1, handleheight=1.1, columnspacing=1.6, labelcolor=INK2)
    fig.text(0.012, 0.025, f"표시 범위가 넓어(모델 판정의 {pct(flagged / (flagged + unflagged), 0)}) '표시 없음 = 높은 신뢰'로 "
             "쓰는 것이 맞다. 기준은 census 결과에 맞춰 바꾸지 않았다. 규칙 판정은 표시 대상이 아니다.",
             fontsize=8.5, color=MUTED)
    save(fig, "xai-2-review-flag")


def xai_feature_name(key, labels):
    model, name = key.split(":")
    text = {"schema:paramset_known": "경로·파라미터 조합을 본 적 있는가",
            "schema:path_known": "경로를 본 적 있는가"}.get(key, labels[key])
    if name.endswith("_count") or name in ("n_params", "n_unknown_params", "n_numeric_vals", "n_encoded_vals"):
        text += " 수"
    return text + (" (스키마)" if model == "schema" else "")


def figure_xai_global(res, top=10):
    rows = res["global_contribution"][:top]
    pattern = set(res["pattern_features"])
    is_pattern = lambda r: r["model"] == "tree" and r["feature"] in pattern
    n_struct = sum(not is_pattern(r) for r in rows)
    fig = plt.figure(figsize=(9.5, 6.0))
    ax = fig.add_axes([0.37, 0.1, 0.42, 0.62])
    header(fig, f"판정 근거 상위 {top}개 중 {n_struct}개가 요청의 구조 특성",
           "census 모델 판정 탐지 무작위 표본 · 피처별 평균 |기여|(판정 로짓 단위, 클수록 판정을 많이 움직인다)")
    hi = max(r["mean_abs"] for r in rows) * 1.12
    ax.set_xlim(0, hi)
    ax.set_ylim(len(rows) - 0.4, -0.75)
    ticks = [t for t in (0, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0) if t <= hi]
    for x in ticks:
        ax.axvline(x, color=GRID, lw=0.8, zorder=0)
    ax.set_xticks(ticks, [f"{t:g}" for t in ticks])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)
    top1 = res["top1_feature_share"]
    for i, r in enumerate(rows):
        key = f"{r['model']}:{r['feature']}"
        rounded_hbar(ax, i, r["mean_abs"], 0.58, PATTERN_C if is_pattern(r) else STRUCT_C)
        ax.text(r["mean_abs"] + hi * 0.015, i, f"{r['mean_abs']:.2f}", ha="left", va="center", fontsize=9.5,
                color=INK2, clip_on=False)
        ax.text(-hi * 0.03, i, xai_feature_name(key, res["feature_labels"]), ha="right", va="center", fontsize=10,
                color=INK, clip_on=False)
        share = top1.get(key, 0)
        ax.text(hi * 1.38, i, "—" if not share else "<0.1%" if share < 0.001 else pct(share), ha="right",
                va="center", fontsize=9.5, color=INK2, clip_on=False)
    ax.text(hi * 1.38, -0.7, "1순위 비율", ha="right", va="bottom", fontsize=9.5, fontweight="bold", color=INK2,
            clip_on=False)
    handles = [Rectangle((0, 0), 1, 1, fc=color, ec="none") for color in (PATTERN_C, STRUCT_C)]
    fig.legend(handles, ["시그니처 근거 (공격 패턴·URL 인코딩·특수문자)", "요청 구조 근거 (경로·길이·비율·확장자·스키마)"],
               loc="upper left", bbox_to_anchor=(0.008, 0.865), ncol=2, frameon=False, fontsize=10,
               handlelength=1.1, handleheight=1.1, columnspacing=1.6, labelcolor=INK2)
    fig.text(0.012, 0.025, "1순위 비율: 그 피처가 공격 쪽 기여 1위인 모델 판정 탐지의 비율(전체 기준). "
             "트랜스포머(가중치 0.05)는 피처로 나누지 않아 빠져 있다.", fontsize=8.5, color=MUTED)
    save(fig, "xai-3-global")


def waterfall_steps(example, top):
    items = example["contributions"]          # |기여| 큰 순
    steps = [(i["display"], i["contribution"], PATTERN_C if i["pattern"] else STRUCT_C) for i in items[:top]]
    steps.append((f"나머지 피처 {len(items) - top}개", sum(i["contribution"] for i in items[top:]), NEITHER))
    steps.append(("트랜스포머 (한 항목)", example["transformer"] + example["adjustment"], NEITHER))
    return steps


def figure_xai_waterfall(res, top=6):
    examples = {e["kind"]: e for e in res.get("waterfall_examples", [])}
    if not {"signature", "shortcut"} <= set(examples):
        return False
    panels = [(examples["signature"], "① 공격 구문이 이끈 판정"),
              (examples["shortcut"], "② 루트 경로(/)가 이끈 판정 · 검토 권장")]
    # 두 패널을 같은 눈금으로 그린다
    points = []
    for ex, _ in panels:
        x = ex["base_logit"]
        points += [x, ex["threshold_logit"]]
        for _, c, _ in waterfall_steps(ex, top):
            x += c
            points.append(x)
    lo, hi = min(points) - 1.2, max(points) + 1.6
    fig, axes = plt.subplots(1, 2, figsize=(13, 6.4), gridspec_kw={"wspace": 1.05})
    fig.subplots_adjust(left=0.185, right=0.975, top=0.6, bottom=0.11)
    header(fig, "같은 '공격' 판정이라도 근거가 다르다",
           "TreeSHAP 로짓 분해 · 기준값에서 피처별 기여를 차례로 더하면 판정 로짓이 되고, 점선(판정 기준)을 넘으면 공격")
    for ax, (ex, title) in zip(axes, panels):
        steps = waterfall_steps(ex, top)
        n = len(steps)
        ax.set_xlim(lo, hi)
        ax.set_ylim(n + 1.6, -0.9)
        ticks = [t for t in range(int(lo) - 1, int(hi) + 2) if lo <= t <= hi and t % 2 == 0]
        for t in ticks:
            ax.axvline(t, color=GRID, lw=0.8, zorder=0)
        ax.set_xticks(ticks, [str(t) for t in ticks])
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.set_yticks(range(n + 2), ["기준값 (평균 요청)"] + [s[0] for s in steps] + ["판정 로짓"])
        ax.tick_params(axis="y", labelsize=9.5, labelcolor=INK)
        on_surface = {"boxstyle": "square,pad=0.15", "fc": SURFACE, "ec": "none"}   # 점선·격자가 숫자를 가르지 않게
        threshold = ex["threshold_logit"]
        ax.plot([threshold] * 2, [-0.6, n + 1.45], color=INK2, lw=1, ls=(0, (3, 3)), zorder=2)
        ax.text(threshold, -0.65, f"판정 기준 {threshold:.2f}", ha="center", va="bottom", fontsize=8.5, color=INK2,
                bbox=on_surface, zorder=4)
        pad = (hi - lo) * 0.012
        cum = ex["base_logit"]
        ax.plot(cum, 0, "o", ms=8, color=INK2, mec=SURFACE, mew=1.5, zorder=3)
        ax.text(cum + pad * 1.6, 0, f"{cum:.2f}", ha="left", va="center", fontsize=9, color=INK2, bbox=on_surface,
                zorder=4)
        for j, (_, c, color) in enumerate(steps, start=1):
            ax.barh(j, c, left=cum, height=0.6, color=color, edgecolor="none", zorder=3)
            ax.plot([cum + c] * 2, [j + 0.3, j + 0.7], color=AXIS, lw=0.8, zorder=2)      # 다음 막대로 잇는 선
            ax.text(cum + c + (pad if c >= 0 else -pad), j, signed(c), ha="left" if c >= 0 else "right",
                    va="center", fontsize=9, color=INK2, bbox=on_surface, zorder=4)
            cum += c
        score = 1 / (1 + 2.718281828459045 ** -cum)
        ax.plot(cum, n + 1, "o", ms=9, color=INK, mec=SURFACE, mew=1.5, zorder=3)
        ax.text(cum + (hi - lo) * 0.025, n + 1, f"{cum:.2f} → 점수 {score:.3f}", ha="left", va="center",
                fontsize=9.5, fontweight="bold", color=INK, bbox=on_surface, zorder=4)
        # 패널 제목·요청·기존 reason (라벨 열 왼쪽에 맞춘다). 인코딩된 URL은 디코딩한 모양을 함께 적는다
        x_text = ax.get_position().x0 - 0.17
        y_top = ax.get_position().y1
        decoded = unquote_plus(ex["url"])
        request = f"{ex['method']} {ex['url']}" + (f"  (= {decoded})" if decoded != ex["url"] else "") \
            + (f"   본문 {ex['body']}" if ex["body"] else "")
        fig.text(x_text, y_top + 0.105, title, ha="left", va="bottom", fontsize=11.5, fontweight="bold", color=INK)
        fig.text(x_text, y_top + 0.068, request if len(request) <= 78 else request[:77] + "…", ha="left",
                 va="bottom", fontsize=9, color=INK2)
        fig.text(x_text, y_top + 0.035, f"기존 reason: {ex['old_reason']}", ha="left", va="bottom", fontsize=9,
                 color=MUTED)
    handles = [Rectangle((0, 0), 1, 1, fc=c, ec="none") for c in (PATTERN_C, STRUCT_C, NEITHER)]
    handles.append(plt.Line2D([], [], color=INK2, lw=1, ls=(0, (3, 3))))
    fig.legend(handles, ["시그니처 근거", "요청 구조 근거", "나머지 피처·트랜스포머", "판정 기준(점수 0.965)"],
               loc="upper left", bbox_to_anchor=(0.008, 0.865), ncol=4, frameon=False, fontsize=10,
               handlelength=1.1, handleheight=1.1, columnspacing=1.6, labelcolor=INK2)
    fig.text(0.012, 0.025, "기여는 모델이 공격 쪽으로 기운 정도이며 공격 성공의 증거가 아니다. ②의 기존 reason은 본문에서 찾은 패턴이지만, "
             "트리 모델(가중치 0.85)은 본문을 보지 않고 '루트로 보낸 요청'이라는 구조로 판정했다.", fontsize=8.5, color=MUTED)
    save(fig, "xai-4-waterfall")
    return True


def figure_t2_generalization(compact=False, figsize=None, name=None):
    """T2: 학습 분포 안(census) vs 새 사이트(DVWA)에서 WAF·AI·결합의 탐지율 대 오탐률.

    compact=True면 포스터 칸(가로로 짧은 슬롯)용 축소본(t2-generalization-poster)을 그린다.

    핵심: 데이터에 따라 WAF와 AI의 강약이 뒤바뀌며 서로의 약점을 덮는다. census에선 AI가 왼쪽 위(저오탐·
    고탐지), 새 사이트에선 WAF가 위쪽(고탐지). DVWA 점은 results.csv에서 바로 계산하고, census는 원본
    구성 환산 헤드라인값(wafs/README.md·census 리포트)을 상수로 쓴다(가중 환산이라 재계산 생략)."""
    PAYLOAD = {"sqli", "xss", "cmd_injection", "path_traversal", "rfi", "upload_webshell"}

    def rows(sub):
        with open(D / "t2-dvwa" / sub / "results.csv", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def rate(items, pred):
        items = list(items)
        return sum(bool(pred(r)) for r in items) / len(items) if items else 0.0

    wd = lambda r: r["waf_detected"] == "True"
    ad = lambda r: r["ai_attack"] == "True"
    # DVWA: 공격 탐지는 페이로드 68건(atk-*), 정상 오탐은 52건(정상 세트)
    a1 = [r for r in rows("atk-modsecurity-pl1") if r["family"] in PAYLOAD]
    a2 = [r for r in rows("atk-modsecurity-pl2") if r["family"] in PAYLOAD]
    n1, n2 = rows("modsecurity"), rows("modsec-pl2")       # 정상 PL1, PL2
    dvwa = {
        "WAF PL1": (rate(a1, wd), rate(n1, wd)),
        "WAF PL2": (rate(a2, wd), rate(n2, wd)),
        "AI": (rate(a2, ad), rate(n2, ad)),
        "OR": (rate(a2, lambda r: wd(r) or ad(r)), rate(n2, lambda r: wd(r) or ad(r))),
        "AND": (rate(a2, lambda r: wd(r) and ad(r)), rate(n2, lambda r: wd(r) and ad(r))),
    }
    # census: 원본 구성 환산 헤드라인 (탐지율, 오탐률). 결합은 운영 알림 기준인 탐지 PL2.
    census = {"WAF PL1": (0.430, 0.196), "WAF PL2": (0.745, 0.389), "AI": (0.863, 0.044),
              "OR": (0.936, 0.396), "AND": (0.671, 0.037)}

    COL = {"WAF PL1": PL_RAMP[0], "WAF PL2": PL_RAMP[1], "AI": AI, "OR": OR, "AND": AND}
    MK = {"WAF PL1": "o", "WAF PL2": "o", "AI": "D", "OR": "o", "AND": "o"}

    def f1(v):     # 비율 → "94%" / 소수점은 10% 미만에서만
        p = 100 * v
        return f"{p:.1f}%" if 0 < p < 10 else f"{p:.0f}%"

    s = 0.80 if compact else 1.0          # compact: 포스터 칸(가로로 짧은 슬롯)용 축소본
    figsize = figsize or ((12.4, 4.05) if compact else (10.5, 5.6))
    name = name or ("t2-generalization-poster" if compact else "t2-generalization")
    fig = plt.figure(figsize=figsize)
    if compact:
        fig.text(0.012, 0.95, "WAF와 AI는 서로의 약점을 덮는다", fontsize=12.5, fontweight="bold", color=INK)
        fig.text(0.012, 0.845, "탐지율 대 오탐률 · 왼쪽 위가 좋다 · OR=하나라도, AND=둘 다 · 결합은 탐지 PL2",
                 fontsize=8.6, color=INK2)
        axes = [fig.add_axes([0.055, 0.215, 0.415, 0.54]), fig.add_axes([0.555, 0.215, 0.415, 0.54])]
    else:
        header(fig, "WAF와 AI는 서로의 약점을 덮는다",
               "탐지율 대 오탐률 · 왼쪽 위로 갈수록 좋다 · OR = 둘 중 하나라도, AND = 둘 다 · 결합은 탐지 PL2 기준")
        axes = [fig.add_axes([0.065, 0.135, 0.405, 0.63]), fig.add_axes([0.565, 0.135, 0.405, 0.63])]
    # 패널별 라벨 위치(겹침 피해 수동 지정): dx,dy는 데이터좌표 오프셋, ha/va
    LBL = {
        0: {"WAF PL1": (2, -1.5, "left", "top"), "WAF PL2": (-2, 3, "right", "bottom"),
            "AI": (2, 1.5, "left", "bottom"), "OR": (-2, 1, "right", "bottom"), "AND": (2, 0, "left", "center")},
        1: {"WAF PL1": (2.3, -3.2, "left", "top"), "WAF PL2": (2.3, 0, "left", "center"),
            "AI": (2.3, 0, "left", "center")},
    }
    panels = [("학습 분포 안  (census 86,067건)", census, 0),
              ("새 사이트  (DVWA · 공격 68 · 정상 52)", dvwa, 1)]
    for ax, (ptitle, data, idx) in zip(axes, panels):
        ax.set_xlim(-1.5, 46)
        ax.set_ylim(38, 100)
        for v in (40, 60, 80, 100):
            ax.axhline(v, color=GRID, lw=0.8, zorder=0)
        for v in (0, 20, 40):
            ax.axvline(v, color=GRID, lw=0.8, zorder=0)
        ax.set_xticks([0, 20, 40], ["0%", "20%", "40%"])
        ax.set_yticks([40, 60, 80, 100], ["40%", "60%", "80%", "100%"])
        ax.tick_params(axis="both", labelsize=9.5 * s)
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.set_xlabel("오탐률 (정상 중 걸린 비율)", color=INK2, fontsize=10 * s, labelpad=4)
        ax.text(-1.5, 101.5, ptitle, ha="left", va="bottom", fontsize=11 * s, fontweight="bold", color=INK)
        ax.text(-1.0, 98.5, "이상적", ha="left", va="top", fontsize=9 * s, color=MUTED)
        if idx == 0 and not compact:
            ax.text(-1.5, 104.5, "탐지율 (공격 중 걸린 비율)", ha="left", va="bottom", fontsize=10, color=INK2)
        # WAF PL1→PL2 연결선(규칙 민감도 손잡이)
        ax.plot([100 * data["WAF PL1"][1], 100 * data["WAF PL2"][1]],
                [100 * data["WAF PL1"][0], 100 * data["WAF PL2"][0]],
                "-", color=PL_RAMP[1], lw=1.6, alpha=0.5, zorder=2, solid_capstyle="round")
        drawn = ["WAF PL1", "WAF PL2", "AI", "OR", "AND"] if idx == 0 else ["WAF PL1", "WAF PL2", "AI"]
        names = {"WAF PL1": "WAF PL1", "WAF PL2": "WAF PL2" if idx == 0 else "WAF PL2 · OR",
                 "AI": "AI" if idx == 0 else "AI · AND", "OR": "OR", "AND": "AND"}
        for key in drawn:
            det, fp = data[key]
            x, y = 100 * fp, 100 * det
            ms = (11 if MK[key] == "D" else 9) * (s if compact else 1.0)
            ax.plot(x, y, MK[key], ms=ms, color=COL[key], mec=SURFACE, mew=1.5, zorder=5)
            dx, dy, ha, va = LBL[idx][key]
            ax.annotate(f"{names[key]}\n{f1(det)} / {f1(fp)}", (x, y), xytext=(x + dx, y + dy),
                        fontsize=8.6 * s, color=INK2, ha=ha, va=va, linespacing=1.2, zorder=6)
    fig.text(0.012, 0.02 if compact else 0.015,
             "숫자 = 탐지율 / 오탐률. census는 원본 구성 환산값, DVWA는 실측. 새 사이트에선 OR=WAF PL2, AND=AI "
             "(AI가 WAF에 공격 탐지를 더하지 못함).",
             fontsize=8.6 * s, color=MUTED)
    save(fig, name)
    print(f"T2{'(poster)' if compact else ''}: DVWA 공격 WAF PL2 {f1(dvwa['WAF PL2'][0])}·AI {f1(dvwa['AI'][0])}, "
          f"정상 오탐 WAF PL2 {f1(dvwa['WAF PL2'][1])}·AI {f1(dvwa['AI'][1])}")


def main():
    global OUT
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", type=Path, default=OUT)
    OUT = parser.parse_args().out_dir
    OUT.mkdir(parents=True, exist_ok=True)
    if (D / "census-modsecurity/results.csv").exists():
        load_t1()
        figure_composition()
        figure_by_type()
        figure_tradeoff()
        figure_precision()
        print(f"T1: AI {pct(ai_pt[0])}/{pct(ai_pt[1])}, CRS PL1·5 {pct(waf_pts[(1, 5)][0])}/{pct(waf_pts[(1, 5)][1])}, "
              f"OR PL1·10 {pct(or_pts[10][0])}/{pct(or_pts[10][1])} (탐지율/오탐률, 원본 구성 환산)")
    else:
        print("T1: census 결과가 없어 건너뜀")
    latency = LOAD / "latency/summary.json"
    if latency.exists():
        summary = json.loads(latency.read_text(encoding="utf-8"))
        control_path = LOAD / "latency-waf-only/summary.json"     # PAUSE_PIPELINE=1로 잰 WAF만 구성
        control = json.loads(control_path.read_text(encoding="utf-8")) if control_path.exists() else {}
        figure_user_latency(summary, control)
        figure_resources(summary)
        print("T3·T4: 응답 지연·자원 그래프 저장")
    else:
        print(f"T3·T4: {latency}가 없어 건너뜀 (dev_tools/load-test/README.md 참고)")
    if (LOAD / "detection/idle/latency.csv").exists():
        figure_detection_latency(LOAD / "detection")
        print("T4: 탐지 지연 그래프 저장")
    if (LOAD / "ai-threads/summary.json").exists():
        figure_ai_threads()
        print("T4: AI 스레드 설정 그래프 저장")
    if XAI_RESULTS.exists():
        res = json.loads(XAI_RESULTS.read_text(encoding="utf-8"))
        figure_xai_faithfulness(res)
        figure_xai_review(res)
        figure_xai_global(res)
        drew = figure_xai_waterfall(res)
        print("XAI: 판정 설명 그래프 저장" + ("" if drew else " (지역 설명 예시가 없어 xai-4 생략 — eval_xai_explanations.py 재실행)"))
    else:
        print(f"XAI: {XAI_RESULTS}가 없어 건너뜀 (dev_tools/scripts/eval_xai_explanations.py)")
    if (D / "t2-dvwa/atk-modsecurity-pl2/results.csv").exists():
        figure_t2_generalization()
        print("T2: WAF·AI 일반화 비교 그래프 저장")
    else:
        print("T2: t2-dvwa 결과가 없어 건너뜀 (capture_dvwa_traffic.py·make_dvwa_attacks.py)")
    print("저장:", OUT)


if __name__ == "__main__":
    main()
