"""
Code Injection Techniques Database — main GUI application.
"""
import threading
import time
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import font as tkfont
import customtkinter as ctk

from techniques import (
    TECHNIQUES, TECHNIQUE_BY_ID, TECHNIQUES_BY_CATEGORY,
    CATEGORIES, DIFFICULTY_COLORS,
)
from simulations import (
    SIMULATION_STEPS, key_event_to_row, run_shellcode_sim,
)

# ─────────────────────────────────────────────────────────────────────────────
# Appearance
# ─────────────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

C = {
    "bg":          "#0B0B14",
    "panel":       "#12121F",
    "card":        "#1A1A2E",
    "card_hover":  "#1F1F38",
    "border":      "#2A2A45",
    "accent":      "#00D4FF",
    "accent_dim":  "#007FA0",
    "danger":      "#FF4A6E",
    "success":     "#00E676",
    "warning":     "#FFB300",
    "text":        "#E0E6FF",
    "text_dim":    "#6B7099",
    "text_code":   "#ABB2E8",
    "sidebar_sel": "#1E1E3A",
    "tag_bg":      "#1E2840",
}

FONT_UI    = ("Segoe UI", 11)
FONT_TITLE = ("Segoe UI Semibold", 22)
FONT_H2    = ("Segoe UI Semibold", 14)
FONT_H3    = ("Segoe UI Semibold", 12)
FONT_MONO  = ("Consolas", 10)
FONT_SMALL = ("Segoe UI", 9)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _tag_label(parent, text: str, bg: str, fg: str = "#FFFFFF",
               font=None, padx: int = 8, pady: int = 2) -> ctk.CTkLabel:
    lbl = ctk.CTkLabel(
        parent, text=text,
        fg_color=bg, text_color=fg,
        corner_radius=4,
        font=font or ("Segoe UI Semibold", 9),
    )
    lbl.grid_configure(padx=padx, pady=pady)
    return lbl


def _scroll_text(parent, height: int = 8, font=None,
                 fg: str = C["text"], bg: str = C["card"]) -> ctk.CTkTextbox:
    tb = ctk.CTkTextbox(
        parent, height=height, font=font or FONT_UI,
        fg_color=bg, text_color=fg,
        border_color=C["border"], border_width=1,
        corner_radius=6, wrap="word",
        activate_scrollbars=True,
    )
    return tb


# ─────────────────────────────────────────────────────────────────────────────
# Main window
# ─────────────────────────────────────────────────────────────────────────────

class InjectionTechniqueDB(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Code Injection Techniques Database  •  Security Research Edition")
        self.geometry("1440x900")
        self.minsize(1100, 700)
        self.configure(fg_color=C["bg"])

        self._current_id: str | None = None
        self._sim_running   = False
        self._sim_thread: threading.Thread | None = None
        self._filter_cat    = "All"
        self._search_var    = tk.StringVar()
        self._search_var.trace_add("write", self._on_search)

        self._build_layout()
        self._populate_list()
        # Select first technique
        if TECHNIQUES:
            self._show_technique(TECHNIQUES[0]["id"])

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_layout(self):
        self.grid_columnconfigure(0, weight=0, minsize=295)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._sidebar   = self._build_sidebar()
        self._mainpanel = self._build_main_panel()

    # ── Sidebar ───────────────────────────────────────────────────────────────

    def _build_sidebar(self) -> ctk.CTkFrame:
        sb = ctk.CTkFrame(self, fg_color=C["panel"], corner_radius=0,
                           border_width=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_rowconfigure(3, weight=1)
        sb.grid_columnconfigure(0, weight=1)

        # ── logo area
        logo_frame = ctk.CTkFrame(sb, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=16, pady=(20, 12), sticky="ew")

        ctk.CTkLabel(logo_frame, text="⚡ InjectionDB",
                     font=("Segoe UI Semibold", 17),
                     text_color=C["accent"]).pack(side="left")

        ctk.CTkLabel(logo_frame, text="v1.0",
                     font=FONT_SMALL, text_color=C["text_dim"]).pack(side="left", padx=(6, 0))

        # ── search
        search_entry = ctk.CTkEntry(
            sb, textvariable=self._search_var,
            placeholder_text="🔍  Search techniques…",
            font=FONT_UI, height=34,
            fg_color=C["card"], border_color=C["border"],
            text_color=C["text"],
        )
        search_entry.grid(row=1, column=0, padx=12, pady=(0, 10), sticky="ew")

        # ── category filter
        cat_frame = ctk.CTkFrame(sb, fg_color="transparent")
        cat_frame.grid(row=2, column=0, padx=8, pady=(0, 8), sticky="ew")

        self._cat_buttons: dict[str, ctk.CTkButton] = {}
        for i, cat in enumerate(CATEGORIES):
            short = cat if len(cat) <= 10 else cat.split()[0]
            btn = ctk.CTkButton(
                cat_frame, text=short,
                width=60, height=24,
                font=("Segoe UI", 9),
                corner_radius=4,
                fg_color=C["accent"] if cat == "All" else C["card"],
                hover_color=C["accent_dim"],
                command=lambda c=cat: self._filter_category(c),
            )
            btn.grid(row=0, column=i, padx=3, pady=0)
            self._cat_buttons[cat] = btn

        # ── technique list
        list_frame = ctk.CTkScrollableFrame(
            sb, fg_color="transparent",
            scrollbar_button_color=C["border"],
        )
        list_frame.grid(row=3, column=0, sticky="nsew", padx=6, pady=(0, 8))
        list_frame.grid_columnconfigure(0, weight=1)
        self._list_frame = list_frame
        self._tech_cards: dict[str, ctk.CTkFrame] = {}

        # ── stats bar
        self._stats_lbl = ctk.CTkLabel(
            sb, text="", font=FONT_SMALL, text_color=C["text_dim"])
        self._stats_lbl.grid(row=4, column=0, pady=(0, 8))

        return sb

    def _make_tech_card(self, tech: dict) -> ctk.CTkFrame:
        diff  = tech["difficulty"]
        dcolor = DIFFICULTY_COLORS.get(diff, "#888")
        card = ctk.CTkFrame(
            self._list_frame, fg_color=C["card"],
            corner_radius=8, border_width=1, border_color=C["border"],
            cursor="hand2",
        )
        card.grid_columnconfigure(0, weight=1)

        # title row
        title_row = ctk.CTkFrame(card, fg_color="transparent")
        title_row.grid(row=0, column=0, padx=10, pady=(8, 2), sticky="ew")
        title_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(title_row, text=tech["name"],
                     font=("Segoe UI Semibold", 10),
                     text_color=C["text"],
                     anchor="w", wraplength=200).grid(row=0, column=0, sticky="w")

        # difficulty badge
        ctk.CTkLabel(title_row, text=diff[:3].upper(),
                     font=("Segoe UI Semibold", 8),
                     fg_color=dcolor, text_color="#000",
                     corner_radius=3, width=30).grid(row=0, column=1, padx=(4, 0))

        # category + MITRE
        meta_row = ctk.CTkFrame(card, fg_color="transparent")
        meta_row.grid(row=1, column=0, padx=10, pady=(0, 6), sticky="ew")

        ctk.CTkLabel(meta_row, text=tech["category"],
                     font=FONT_SMALL, text_color=C["text_dim"],
                     anchor="w").pack(side="left")

        ctk.CTkLabel(meta_row, text=tech["mitre_attack"],
                     font=FONT_SMALL, text_color=C["accent_dim"],
                     anchor="e").pack(side="right")

        # bind click
        def _click(e, tid=tech["id"]):
            self._show_technique(tid)

        for w in [card, title_row, meta_row] + list(title_row.winfo_children()) + list(meta_row.winfo_children()):
            try:
                w.bind("<Button-1>", _click)
            except Exception:
                pass

        return card

    def _populate_list(self, query: str = "", category: str = "All"):
        for w in list(self._list_frame.winfo_children()):
            w.destroy()
        self._tech_cards.clear()

        filtered = [
            t for t in TECHNIQUES
            if (category == "All" or t["category"] == category)
            and (not query or query.lower() in t["name"].lower()
                 or query.lower() in t["short_desc"].lower()
                 or any(query.lower() in tag for tag in t["tags"]))
        ]

        for i, tech in enumerate(filtered):
            card = self._make_tech_card(tech)
            card.grid(row=i, column=0, padx=4, pady=4, sticky="ew")
            self._tech_cards[tech["id"]] = card

        n = len(filtered)
        total = len(TECHNIQUES)
        self._stats_lbl.configure(
            text=f"{n} / {total} techniques" if n < total else f"{total} techniques")

        # Re-apply selection highlight
        if self._current_id and self._current_id in self._tech_cards:
            self._highlight_card(self._current_id)

    def _highlight_card(self, tid: str):
        for cid, card in self._tech_cards.items():
            card.configure(
                fg_color=C["sidebar_sel"] if cid == tid else C["card"],
                border_color=C["accent"] if cid == tid else C["border"],
            )

    def _filter_category(self, cat: str):
        self._filter_cat = cat
        for c, btn in self._cat_buttons.items():
            btn.configure(fg_color=C["accent"] if c == cat else C["card"])
        self._populate_list(self._search_var.get(), cat)

    def _on_search(self, *_):
        self._populate_list(self._search_var.get(), self._filter_cat)

    # ── Main panel ────────────────────────────────────────────────────────────

    def _build_main_panel(self) -> ctk.CTkFrame:
        mp = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        mp.grid(row=0, column=1, sticky="nsew")
        mp.grid_rowconfigure(1, weight=1)
        mp.grid_columnconfigure(0, weight=1)

        # header placeholder
        self._header_frame = ctk.CTkFrame(mp, fg_color=C["panel"],
                                           corner_radius=0, height=110)
        self._header_frame.grid(row=0, column=0, sticky="ew")
        self._header_frame.grid_propagate(False)

        # tab view
        self._tabs = ctk.CTkTabview(
            mp, fg_color=C["card"],
            segmented_button_fg_color=C["panel"],
            segmented_button_selected_color=C["accent"],
            segmented_button_selected_hover_color=C["accent_dim"],
            segmented_button_unselected_color=C["panel"],
            segmented_button_unselected_hover_color=C["card"],
            text_color=C["text"],
            corner_radius=0,
        )
        self._tabs.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)

        for name in ("Overview", "Code", "Simulate", "Detection"):
            self._tabs.add(name)

        return mp

    # ── Show technique ────────────────────────────────────────────────────────

    def _show_technique(self, tid: str):
        if self._sim_running:
            self._stop_sim()

        tech = TECHNIQUE_BY_ID.get(tid)
        if not tech:
            return
        self._current_id = tid
        self._highlight_card(tid)

        self._render_header(tech)
        self._render_overview(tech)
        self._render_code(tech)
        self._render_simulate(tech)
        self._render_detection(tech)

    # ── Header ────────────────────────────────────────────────────────────────

    def _render_header(self, tech: dict):
        for w in self._header_frame.winfo_children():
            w.destroy()

        self._header_frame.grid_columnconfigure(0, weight=1)

        # name + badges row
        top = ctk.CTkFrame(self._header_frame, fg_color="transparent")
        top.grid(row=0, column=0, padx=20, pady=(14, 4), sticky="ew")
        top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(top, text=tech["name"],
                     font=("Segoe UI Semibold", 20),
                     text_color=C["text"], anchor="w").grid(row=0, column=0, sticky="w")

        badges = ctk.CTkFrame(top, fg_color="transparent")
        badges.grid(row=0, column=1, sticky="e")

        diff  = tech["difficulty"]
        dcolor = DIFFICULTY_COLORS.get(diff, "#888")
        ctk.CTkLabel(badges, text=diff,
                     font=("Segoe UI Semibold", 10),
                     fg_color=dcolor, text_color="#000",
                     corner_radius=4, width=90, height=22).pack(side="left", padx=4)

        ctk.CTkLabel(badges, text=tech["platform"],
                     font=("Segoe UI", 10), text_color=C["text_dim"],
                     fg_color=C["tag_bg"], corner_radius=4,
                     width=70, height=22).pack(side="left", padx=4)

        ctk.CTkLabel(badges, text=tech["mitre_attack"],
                     font=("Consolas", 10), text_color=C["accent"],
                     fg_color=C["tag_bg"], corner_radius=4,
                     width=90, height=22).pack(side="left", padx=4)

        # short description
        ctk.CTkLabel(self._header_frame,
                     text=tech["short_desc"],
                     font=("Segoe UI", 11),
                     text_color=C["text_dim"], anchor="w",
                     wraplength=900).grid(row=1, column=0, padx=20, pady=(0, 6), sticky="w")

        # tags
        tag_row = ctk.CTkFrame(self._header_frame, fg_color="transparent")
        tag_row.grid(row=2, column=0, padx=16, pady=(0, 10), sticky="w")
        for tag in tech.get("tags", []):
            ctk.CTkLabel(tag_row, text=f"#{tag}",
                         font=("Segoe UI", 9),
                         fg_color=C["tag_bg"], text_color=C["accent_dim"],
                         corner_radius=3, height=18).pack(side="left", padx=3)

    # ── Overview tab ──────────────────────────────────────────────────────────

    def _render_overview(self, tech: dict):
        tab = self._tabs.tab("Overview")
        for w in tab.winfo_children():
            w.destroy()
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        # Description
        ctk.CTkLabel(tab, text="Description",
                     font=FONT_H2, text_color=C["accent"],
                     anchor="w").grid(row=0, column=0, padx=20, pady=(16, 6), sticky="w")

        desc_box = _scroll_text(tab, height=130)
        desc_box.grid(row=1, column=0, padx=20, sticky="ew")
        desc_box.insert("0.0", tech["description"].strip())
        desc_box.configure(state="disabled")

        # How it works
        ctk.CTkLabel(tab, text="How It Works",
                     font=FONT_H2, text_color=C["accent"],
                     anchor="w").grid(row=2, column=0, padx=20, pady=(16, 6), sticky="w")

        steps_frame = ctk.CTkScrollableFrame(
            tab, fg_color="transparent", height=260)
        steps_frame.grid(row=3, column=0, padx=16, pady=(0, 16), sticky="ew")
        steps_frame.grid_columnconfigure(1, weight=1)

        for i, step in enumerate(tech["how_it_works"]):
            # step number circle
            ctk.CTkLabel(steps_frame, text=str(i + 1),
                         width=28, height=28,
                         fg_color=C["accent"], text_color="#000",
                         corner_radius=14,
                         font=("Segoe UI Semibold", 10)).grid(
                row=i, column=0, padx=(4, 10), pady=4, sticky="n")

            ctk.CTkLabel(steps_frame, text=step,
                         font=FONT_UI, text_color=C["text"],
                         anchor="w", justify="left",
                         wraplength=780).grid(
                row=i, column=1, pady=4, sticky="w")

    # ── Code tab ──────────────────────────────────────────────────────────────

    def _render_code(self, tech: dict):
        tab = self._tabs.tab("Code")
        for w in tab.winfo_children():
            w.destroy()
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        lang = tech.get("code_language", "c").upper()

        hdr = ctk.CTkFrame(tab, fg_color="transparent")
        hdr.grid(row=0, column=0, padx=20, pady=(14, 6), sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(hdr, text=f"Example ({lang})",
                     font=FONT_H2, text_color=C["accent"],
                     anchor="w").grid(row=0, column=0, sticky="w")

        ctk.CTkButton(hdr, text="⎘ Copy",
                      width=80, height=28, font=FONT_SMALL,
                      fg_color=C["tag_bg"], hover_color=C["border"],
                      command=lambda: self._copy_code(tech)).grid(
            row=0, column=1, sticky="e")

        code_box = ctk.CTkTextbox(
            tab, font=("Consolas", 10),
            fg_color="#0D1117", text_color=C["text_code"],
            border_color=C["border"], border_width=1,
            corner_radius=6, wrap="none",
            activate_scrollbars=True,
        )
        code_box.grid(row=1, column=0, padx=20, pady=(0, 16), sticky="nsew")
        code_box.insert("0.0", tech["code_example"].strip())
        self._apply_syntax_colors(code_box, lang)
        code_box.configure(state="disabled")
        self._code_box = code_box

    def _apply_syntax_colors(self, tb: ctk.CTkTextbox, lang: str):
        """Very lightweight keyword colorizer using CTkTextbox tags (via underlying tk.Text)."""
        inner: tk.Text = tb._textbox

        # Configure color tags
        inner.tag_configure("kw",      foreground="#569CD6")   # keywords
        inner.tag_configure("type",    foreground="#4EC9B0")   # types
        inner.tag_configure("comment", foreground="#6A9955")   # comments
        inner.tag_configure("string",  foreground="#CE9178")   # strings
        inner.tag_configure("func",    foreground="#DCDCAA")   # function names
        inner.tag_configure("macro",   foreground="#C586C0")   # preprocessor
        inner.tag_configure("number",  foreground="#B5CEA8")   # numbers

        content = inner.get("1.0", "end")
        lines   = content.split("\n")

        C_KW    = {"if","else","for","while","return","NULL","FALSE","TRUE",
                   "break","continue","switch","case","default","sizeof",
                   "typedef","struct","enum","union","static","const","void",
                   "int","char","BOOL","BYTE","DWORD","WORD","HANDLE","LPVOID",
                   "PBYTE","HMODULE","HWND","HMENU","WPARAM","LPARAM",
                   "ULONG_PTR","LONGLONG","ULONGLONG","SIZE_T",
                   "LRESULT","LPCVOID","NTSTATUS","PVOID"}
        C_TYPES = {"HANDLE","DWORD","BOOL","BYTE","WORD","PBYTE","LPVOID",
                   "HMODULE","ULONG_PTR","SIZE_T","LONGLONG","ULONGLONG",
                   "NTSTATUS","PVOID","LPCVOID","LRESULT","WPARAM","LPARAM"}

        import re
        for lineno, line in enumerate(lines, start=1):
            # Preprocessor / macros
            if line.strip().startswith("#"):
                start = f"{lineno}.0"
                end   = f"{lineno}.{len(line)}"
                inner.tag_add("macro", start, end)
                continue

            # Comments
            m = re.search(r'(//.*)$', line)
            if m:
                s = m.start()
                inner.tag_add("comment", f"{lineno}.{s}", f"{lineno}.{len(line)}")

            # Strings
            for m in re.finditer(r'"[^"\n]*"', line):
                inner.tag_add("string", f"{lineno}.{m.start()}", f"{lineno}.{m.end()}")

            # Numbers (hex + decimal)
            for m in re.finditer(r'\b(0x[0-9A-Fa-f]+|\d+)\b', line):
                inner.tag_add("number", f"{lineno}.{m.start()}", f"{lineno}.{m.end()}")

            # Keywords / types — word boundary match
            for m in re.finditer(r'\b([A-Z_][A-Z_0-9]+|[a-z_]+)\b', line):
                word = m.group()
                if word in C_TYPES:
                    inner.tag_add("type", f"{lineno}.{m.start()}", f"{lineno}.{m.end()}")
                elif word in C_KW:
                    inner.tag_add("kw", f"{lineno}.{m.start()}", f"{lineno}.{m.end()}")

            # Function calls: word followed by '('
            for m in re.finditer(r'\b([a-zA-Z_]\w*)\s*\(', line):
                inner.tag_add("func", f"{lineno}.{m.start(1)}", f"{lineno}.{m.end(1)}")

    def _copy_code(self, tech: dict):
        self.clipboard_clear()
        self.clipboard_append(tech["code_example"].strip())

    # ── Simulate tab ─────────────────────────────────────────────────────────

    def _render_simulate(self, tech: dict):
        tab = self._tabs.tab("Simulate")
        for w in tab.winfo_children():
            w.destroy()
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(tab, text="Simulation",
                     font=FONT_H2, text_color=C["accent"],
                     anchor="w").grid(row=0, column=0, padx=20, pady=(16, 4), sticky="w")

        ctk.CTkLabel(tab, text=tech.get("sim_description", ""),
                     font=FONT_UI, text_color=C["text_dim"],
                     anchor="w", wraplength=900,
                     justify="left").grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        # dispatch to per-technique renderer
        tid = tech["id"]
        if tid == "keylogger_hookex":
            self._sim_keylogger(tab, tech)
        elif tid == "shellcode_injection":
            self._sim_shellcode(tab)
        elif tid in SIMULATION_STEPS:
            self._sim_walkthrough(tab, tid, tech)
        else:
            ctk.CTkLabel(tab, text="Simulation not available for this technique.",
                         font=FONT_UI, text_color=C["text_dim"]).grid(
                row=2, column=0, pady=40)

    # Keylogger concept demo
    def _sim_keylogger(self, tab, tech):
        tab.grid_rowconfigure(2, weight=0)
        tab.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(tab, text="Input capture area — type here:",
                     font=FONT_H3, text_color=C["text"],
                     anchor="w").grid(row=2, column=0, padx=20, pady=(0, 4), sticky="w")

        input_box = ctk.CTkTextbox(
            tab, height=70, font=FONT_UI,
            fg_color=C["card"], text_color=C["text"],
            border_color=C["accent"], border_width=1,
            corner_radius=6,
        )
        input_box.grid(row=3, column=0, padx=20, sticky="ew")
        input_box.focus_set()

        # Output table header
        hdr_frame = ctk.CTkFrame(tab, fg_color=C["panel"], corner_radius=6)
        hdr_frame.grid(row=4, column=0, padx=20, pady=(12, 0), sticky="ew")
        cols = [("Time (ms)", 90), ("vkCode", 80), ("scanCode", 90),
                ("keyName", 160), ("flags", 70)]
        for col, (label, w) in enumerate(cols):
            ctk.CTkLabel(hdr_frame, text=label,
                         font=("Consolas", 9), text_color=C["accent"],
                         width=w, anchor="w").grid(row=0, column=col, padx=6, pady=4)

        log_frame = ctk.CTkScrollableFrame(tab, fg_color=C["card"],
                                            corner_radius=6, height=240)
        log_frame.grid(row=5, column=0, padx=20, pady=(0, 16), sticky="ew")
        self._kl_row = 0

        ctk.CTkButton(tab, text="⬛  Clear Log",
                      width=120, height=28, font=FONT_SMALL,
                      fg_color=C["tag_bg"], hover_color=C["border"],
                      command=lambda: self._clear_kl_log(log_frame)).grid(
            row=6, column=0, padx=20, pady=(0, 10), sticky="w")

        def _on_key(event):
            row_data = key_event_to_row(event)
            r = self._kl_row
            self._kl_row += 1
            row_bg = C["card"] if r % 2 == 0 else C["card_hover"]
            row_frame = ctk.CTkFrame(log_frame, fg_color=row_bg, corner_radius=0)
            row_frame.grid(row=r, column=0, sticky="ew", padx=0, pady=0)
            vals = [
                str(row_data["time"]),
                row_data["vkCode"],
                row_data["scanCode"],
                row_data["keyName"],
                row_data["flags"],
            ]
            for col, (val, (_, w)) in enumerate(zip(vals, cols)):
                color = C["accent"] if col == 3 else C["text_code"]
                ctk.CTkLabel(row_frame, text=val,
                             font=("Consolas", 9), text_color=color,
                             width=w, anchor="w").grid(row=0, column=col, padx=6, pady=2)

        input_box._textbox.bind("<KeyPress>", _on_key)

    def _clear_kl_log(self, log_frame):
        for w in log_frame.winfo_children():
            w.destroy()
        self._kl_row = 0

    # Shellcode real-alloc demo
    def _sim_shellcode(self, tab):
        tab.grid_rowconfigure(2, weight=1)

        btn_frame = ctk.CTkFrame(tab, fg_color="transparent")
        btn_frame.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")

        output_box = _scroll_text(tab, height=380, font=("Consolas", 10),
                                   fg=C["success"], bg="#0D1117")
        output_box.grid(row=3, column=0, padx=20, pady=(0, 16), sticky="ew")

        def _run():
            output_box.configure(state="normal")
            output_box.delete("0.0", "end")
            output_box.insert("end", "Running VirtualAlloc simulation...\n\n")
            steps = run_shellcode_sim()
            for label, detail in steps:
                output_box.insert("end", f"▶ {label}\n", "label")
                output_box.insert("end", f"{detail}\n\n", "detail")
                output_box._textbox.see("end")
                output_box.update()
                time.sleep(0.4)
            output_box.configure(state="disabled")

        output_box._textbox.tag_configure("label",  foreground=C["accent"],
                                           font=("Consolas", 10, "bold"))
        output_box._textbox.tag_configure("detail", foreground=C["text_code"],
                                           font=("Consolas", 9))

        ctk.CTkButton(btn_frame, text="▶  Run Simulation",
                      height=34, font=FONT_UI,
                      fg_color=C["accent"], text_color="#000",
                      hover_color=C["accent_dim"],
                      command=lambda: threading.Thread(target=_run, daemon=True).start()
                      ).pack(side="left", padx=(0, 8))

    # Generic step-by-step walkthrough
    def _sim_walkthrough(self, tab, tid: str, tech: dict):
        steps = SIMULATION_STEPS[tid]
        tab.grid_rowconfigure(3, weight=1)

        # Step navigation
        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        self._wt_step_idx   = 0
        self._wt_steps      = steps
        self._wt_auto_running = False

        step_lbl = ctk.CTkLabel(ctrl, text="Step 0 / 0",
                                 font=FONT_H3, text_color=C["text_dim"])
        step_lbl.grid(row=0, column=0, padx=(0, 12))

        progress = ctk.CTkProgressBar(ctrl, height=8,
                                       progress_color=C["accent"],
                                       fg_color=C["border"])
        progress.grid(row=0, column=1, sticky="ew", padx=8)
        progress.set(0)

        # Step title + detail area
        step_title = ctk.CTkLabel(tab, text="",
                                   font=("Segoe UI Semibold", 13),
                                   text_color=C["accent"], anchor="w",
                                   wraplength=900)
        step_title.grid(row=3, column=0, padx=20, pady=(0, 6), sticky="w")

        detail_box = ctk.CTkTextbox(
            tab, font=("Consolas", 10),
            fg_color="#0D1117", text_color=C["text_code"],
            border_color=C["border"], border_width=1,
            corner_radius=6, wrap="none",
            activate_scrollbars=True, height=300,
        )
        detail_box.grid(row=4, column=0, padx=20, pady=(0, 16), sticky="ew")

        def _show_step(idx: int):
            if not steps:
                return
            idx = max(0, min(idx, len(steps) - 1))
            self._wt_step_idx = idx
            _, title, detail = steps[idx]
            step_title.configure(text=f"Step {idx + 1}: {title}")
            step_lbl.configure(text=f"Step {idx + 1} / {len(steps)}")
            progress.set((idx + 1) / len(steps))
            detail_box.configure(state="normal")
            detail_box.delete("0.0", "end")
            detail_box.insert("0.0", detail)
            detail_box.configure(state="disabled")

        def _auto_play():
            self._wt_auto_running = True
            auto_btn.configure(text="⏹  Stop", fg_color=C["danger"])
            for i in range(self._wt_step_idx, len(steps)):
                if not self._wt_auto_running:
                    break
                tab.after(0, _show_step, i)
                time.sleep(1.4)
            self._wt_auto_running = False
            tab.after(0, lambda: auto_btn.configure(
                text="▶  Auto Play", fg_color=C["accent"]))

        def _toggle_auto():
            if self._wt_auto_running:
                self._wt_auto_running = False
            else:
                threading.Thread(target=_auto_play, daemon=True).start()

        # Button bar
        btn_bar = ctk.CTkFrame(tab, fg_color="transparent")
        btn_bar.grid(row=5, column=0, padx=20, pady=(0, 12), sticky="w")

        ctk.CTkButton(btn_bar, text="⏮  First", width=80, height=30,
                      font=FONT_SMALL, fg_color=C["tag_bg"],
                      hover_color=C["border"],
                      command=lambda: _show_step(0)).pack(side="left", padx=3)

        ctk.CTkButton(btn_bar, text="◀  Prev", width=80, height=30,
                      font=FONT_SMALL, fg_color=C["tag_bg"],
                      hover_color=C["border"],
                      command=lambda: _show_step(self._wt_step_idx - 1)).pack(side="left", padx=3)

        ctk.CTkButton(btn_bar, text="▶  Next", width=80, height=30,
                      font=FONT_SMALL, fg_color=C["tag_bg"],
                      hover_color=C["border"],
                      command=lambda: _show_step(self._wt_step_idx + 1)).pack(side="left", padx=3)

        ctk.CTkButton(btn_bar, text="⏭  Last", width=80, height=30,
                      font=FONT_SMALL, fg_color=C["tag_bg"],
                      hover_color=C["border"],
                      command=lambda: _show_step(len(steps) - 1)).pack(side="left", padx=3)

        auto_btn = ctk.CTkButton(btn_bar, text="▶  Auto Play", width=110, height=30,
                                  font=FONT_SMALL, fg_color=C["accent"],
                                  text_color="#000",
                                  hover_color=C["accent_dim"],
                                  command=_toggle_auto)
        auto_btn.pack(side="left", padx=(12, 3))

        _show_step(0)

    def _stop_sim(self):
        self._sim_running      = False
        self._wt_auto_running  = False

    # ── Detection tab ─────────────────────────────────────────────────────────

    def _render_detection(self, tech: dict):
        tab = self._tabs.tab("Detection")
        for w in tab.winfo_children():
            w.destroy()
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(tab, text="Detection & Mitigation",
                     font=FONT_H2, text_color=C["accent"],
                     anchor="w").grid(row=0, column=0, padx=20, pady=(16, 8), sticky="w")

        scroll = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        scroll.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="nsew")
        scroll.grid_columnconfigure(1, weight=1)

        for i, item in enumerate(tech.get("detection", [])):
            ctk.CTkLabel(scroll, text="⚑",
                         font=("Segoe UI", 11),
                         text_color=C["danger"],
                         width=20).grid(row=i, column=0, padx=(4, 8), pady=5, sticky="n")

            ctk.CTkLabel(scroll, text=item,
                         font=FONT_UI, text_color=C["text"],
                         anchor="w", justify="left",
                         wraplength=850).grid(row=i, column=1, pady=5, sticky="w")

        # MITRE footer
        mid = tech.get("mitre_attack", "")
        if mid:
            footer = ctk.CTkFrame(tab, fg_color=C["tag_bg"], corner_radius=6)
            footer.grid(row=2, column=0, padx=20, pady=(0, 16), sticky="ew")
            ctk.CTkLabel(footer,
                         text=f"MITRE ATT&CK®  ›  {mid}",
                         font=("Consolas", 10),
                         text_color=C["accent"]).pack(padx=12, pady=8, side="left")
            ctk.CTkLabel(footer,
                         text=f"https://attack.mitre.org/techniques/{mid.replace('.', '/')}/",
                         font=("Consolas", 9), text_color=C["text_dim"]).pack(
                padx=12, pady=8, side="left")
