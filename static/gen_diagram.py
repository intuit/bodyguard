"""Generate the Bodyguard architecture diagram for managers."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

fig, ax = plt.subplots(figsize=(14, 9))
fig.patch.set_facecolor("#0d1117")
ax.set_facecolor("#0d1117")
ax.set_xlim(0, 14)
ax.set_ylim(0, 9)
ax.axis("off")

# ── Colour palette ──────────────────────────────────────────────
C_BOX    = "#161b22"
C_BORDER = "#30363d"
C_BLUE   = "#1f6feb"
C_GREEN  = "#238636"
C_PURPLE = "#6e40c9"
C_TEAL   = "#0e7490"
C_ORANGE = "#d97706"
C_TEXT   = "#e6edf3"
C_MUTED  = "#8b949e"
C_ACCENT = "#58a6ff"


def box(ax, x, y, w, h, label, sublabel="", color=C_BOX, border=C_BORDER):
    rect = mpatches.FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.08",
        linewidth=1.5,
        edgecolor=border,
        facecolor=color,
        zorder=3,
    )
    ax.add_patch(rect)
    ax.text(x + w / 2, y + h / 2 + (0.18 if sublabel else 0),
            label, ha="center", va="center",
            fontsize=11, fontweight="bold", color=C_TEXT, zorder=4)
    if sublabel:
        ax.text(x + w / 2, y + h / 2 - 0.25,
                sublabel, ha="center", va="center",
                fontsize=8.5, color=C_MUTED, zorder=4)


def arrow(ax, x1, y1, x2, y2, color=C_ACCENT, dashed=False):
    style = "--" if dashed else "-"
    ax.annotate("",
        xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(
            arrowstyle="-|>", color=color,
            lw=1.8, mutation_scale=14,
            linestyle=style,
            connectionstyle="arc3,rad=0.0",
        ),
        zorder=2)


# ── Title ────────────────────────────────────────────────────────
ax.text(7, 8.55, "Who is my Bodyguard?", ha="center", va="center",
        fontsize=17, fontweight="bold", color=C_ACCENT)
ax.text(7, 8.15, "AI-powered security knowledge assistant",
        ha="center", va="center", fontsize=10, color=C_MUTED)

# ── LEFT column — Inputs ─────────────────────────────────────────
box(ax, 0.4, 6.0, 3.2, 1.1,
    "Knowledge Base", "Git, Confluence, Google Drive...",
    color="#0f2942", border=C_BLUE)

box(ax, 0.4, 4.5, 3.2, 1.1,
    "Custom System Prompt", "Your org's security context",
    color="#1a0f42", border=C_PURPLE)

box(ax, 0.4, 3.0, 3.2, 1.1,
    "Security Rules & Docs", "SQL rules, runbooks, policies",
    color="#0f2942", border=C_BLUE)

# ── BigQuery optional box ────────────────────────────────────────
box(ax, 0.4, 1.2, 3.2, 1.1,
    "BigQuery (optional)", "Live data queries",
    color="#1a1000", border=C_ORANGE)

# dashed border to signal optional
rect_opt = mpatches.FancyBboxPatch(
    (0.4, 1.2), 3.2, 1.1,
    boxstyle="round,pad=0.08",
    linewidth=1.5,
    edgecolor=C_ORANGE,
    facecolor="none",
    linestyle="--",
    zorder=5,
)
ax.add_patch(rect_opt)

ax.text(2.0, 0.85, "optional — turns the agent into a live query tool",
        ha="center", fontsize=7.5, color=C_ORANGE, style="italic", zorder=6)

# ── CENTRE — Core agent ──────────────────────────────────────────
box(ax, 5.1, 3.8, 3.8, 2.2,
    "Bodyguard AI Agent", "Semantic search + LLM reasoning",
    color="#0d2137", border=C_ACCENT)

# ── RIGHT column — Outputs ───────────────────────────────────────
box(ax, 10.4, 6.0, 3.2, 1.1,
    "Web App", "Chat UI · localhost:5001",
    color="#0f2918", border=C_GREEN)

box(ax, 10.4, 4.5, 3.2, 1.1,
    "Slack Integration", "@Bodyguard in any channel",
    color="#0f2918", border=C_GREEN)

box(ax, 10.4, 3.0, 3.2, 1.1,
    "REST API / CLI", "Integrate with your pipelines",
    color="#0f2918", border=C_GREEN)

# ── Arrows: inputs → agent ───────────────────────────────────────
arrow(ax, 3.6, 6.55, 5.1, 5.3)
arrow(ax, 3.6, 5.05, 5.1, 4.9)
arrow(ax, 3.6, 3.55, 5.1, 4.3)

# ── Arrow: BigQuery → agent (dashed, optional) ───────────────────
arrow(ax, 3.6, 1.75, 5.1, 3.9, color=C_ORANGE, dashed=True)

# ── Arrows: agent → outputs ──────────────────────────────────────
arrow(ax, 8.9, 5.3, 10.4, 6.55)
arrow(ax, 8.9, 4.9, 10.4, 5.05)
arrow(ax, 8.9, 4.3, 10.4, 3.55)

# ── Section labels ───────────────────────────────────────────────
ax.text(2.0, 7.35, "INPUTS", ha="center", fontsize=8,
        color=C_MUTED, fontweight="bold", zorder=4)
ax.text(12.0, 7.35, "INTERFACES", ha="center", fontsize=8,
        color=C_MUTED, fontweight="bold", zorder=4)

plt.tight_layout(pad=0.3)
plt.savefig("static/architecture.png", dpi=160,
            bbox_inches="tight", facecolor=fig.get_facecolor())
print("Saved static/architecture.png")
