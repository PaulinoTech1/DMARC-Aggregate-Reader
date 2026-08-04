"""DMARC Desk: fast local batch viewer for aggregate reports."""

from __future__ import annotations

import csv
import queue
import threading
import tkinter as tk
from collections import Counter
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from dmarc_parser import DmarcRow, ParseResult, discover_files, parse_files


BG = "#f4f6f8"
INK = "#17202a"
MUTED = "#667085"
NAVY = "#102a43"
TEAL = "#0f766e"
RED = "#b42318"
WHITE = "#ffffff"


class DmarcApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("DMARC Desk")
        self.geometry("1280x780")
        self.minsize(960, 620)
        self.configure(bg=BG)
        self.rows: list[DmarcRow] = []
        self.filtered_rows: list[DmarcRow] = []
        self._queue: queue.Queue[ParseResult | Exception] = queue.Queue()
        self._sort_column = "count"
        self._sort_reverse = True
        self._configure_styles()
        self._build_ui()

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background=WHITE, fieldbackground=WHITE, foreground=INK, rowheight=30, borderwidth=0)
        style.configure("Treeview.Heading", background="#e9eef3", foreground=NAVY, font=("Segoe UI Semibold", 10), relief="flat")
        style.map("Treeview", background=[("selected", "#d5f5ef")], foreground=[("selected", INK)])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(16, 9), font=("Segoe UI Semibold", 10))

    def _build_ui(self) -> None:
        header = tk.Frame(self, bg=NAVY, padx=26, pady=18)
        header.pack(fill="x")
        tk.Label(header, text="DMARC DESK", bg=NAVY, fg=WHITE, font=("Segoe UI Semibold", 20)).pack(side="left")
        tk.Label(header, text="Local aggregate report explorer", bg=NAVY, fg="#b9d5e8", font=("Segoe UI", 10)).pack(side="left", padx=16, pady=(7, 0))
        tk.Button(header, text="Open folder", command=self.choose_folder, bg=TEAL, fg=WHITE, activebackground="#115e59", activeforeground=WHITE, relief="flat", padx=18, pady=8, font=("Segoe UI Semibold", 10), cursor="hand2").pack(side="right")

        toolbar = tk.Frame(self, bg=BG, padx=24, pady=15)
        toolbar.pack(fill="x")
        self.folder_var = tk.StringVar(value="Choose a folder containing XML, ZIP, or GZ reports")
        tk.Label(toolbar, textvariable=self.folder_var, bg=BG, fg=MUTED, anchor="w", font=("Segoe UI", 10)).pack(side="left", fill="x", expand=True)
        tk.Button(toolbar, text="Export filtered CSV", command=self.export_csv, bg=WHITE, fg=NAVY, relief="solid", bd=1, padx=13, pady=7, cursor="hand2").pack(side="right")

        cards = tk.Frame(self, bg=BG, padx=18)
        cards.pack(fill="x")
        self.card_vars = {name: tk.StringVar(value="—") for name in ("Messages", "Pass rate", "Sources", "Reports")}
        for i, (name, variable) in enumerate(self.card_vars.items()):
            card = tk.Frame(cards, bg=WHITE, padx=18, pady=13, highlightbackground="#dfe5eb", highlightthickness=1)
            card.grid(row=0, column=i, padx=6, sticky="ew")
            cards.grid_columnconfigure(i, weight=1)
            tk.Label(card, text=name.upper(), bg=WHITE, fg=MUTED, font=("Segoe UI Semibold", 9)).pack(anchor="w")
            tk.Label(card, textvariable=variable, bg=WHITE, fg=NAVY, font=("Segoe UI Semibold", 22)).pack(anchor="w", pady=(3, 0))

        filters = tk.Frame(self, bg=BG, padx=24, pady=14)
        filters.pack(fill="x")
        tk.Label(filters, text="Search", bg=BG, fg=INK, font=("Segoe UI Semibold", 9)).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.apply_filters())
        search = tk.Entry(filters, textvariable=self.search_var, relief="solid", bd=1, font=("Segoe UI", 10), width=34)
        search.pack(side="left", padx=(8, 18), ipady=6)
        tk.Label(filters, text="Result", bg=BG, fg=INK, font=("Segoe UI Semibold", 9)).pack(side="left")
        self.result_var = tk.StringVar(value="All")
        combo = ttk.Combobox(filters, textvariable=self.result_var, values=("All", "Pass", "Fail"), state="readonly", width=10)
        combo.pack(side="left", padx=8)
        combo.bind("<<ComboboxSelected>>", lambda _: self.apply_filters())
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(filters, textvariable=self.status_var, bg=BG, fg=MUTED).pack(side="right")

        main = tk.Frame(self, bg=BG, padx=24)
        main.pack(fill="both", expand=True, pady=(0, 20))
        columns = ("source_ip", "count", "domain", "organization", "dkim", "spf", "disposition", "begin")
        self.tree = ttk.Treeview(main, columns=columns, show="headings", selectmode="browse")
        headings = {"source_ip": "Source IP", "count": "Messages", "domain": "Policy domain", "organization": "Reporter", "dkim": "DKIM", "spf": "SPF", "disposition": "Action", "begin": "Period start"}
        widths = {"source_ip": 145, "count": 85, "domain": 170, "organization": 150, "dkim": 80, "spf": 80, "disposition": 95, "begin": 155}
        for column in columns:
            self.tree.heading(column, text=headings[column], command=lambda c=column: self.sort_by(c))
            self.tree.column(column, width=widths[column], minwidth=65, anchor="e" if column == "count" else "w")
        self.tree.tag_configure("fail", foreground=RED)
        self.tree.tag_configure("pass", foreground=INK)
        self.tree.bind("<Double-1>", self.show_details)
        scrollbar = ttk.Scrollbar(main, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def choose_folder(self) -> None:
        selected = filedialog.askdirectory(title="Choose DMARC report folder")
        if not selected:
            return
        folder = Path(selected)
        self.folder_var.set(str(folder))
        files = discover_files(folder)
        if not files:
            messagebox.showinfo("No reports found", "This folder contains no .xml, .zip, or .gz files.")
            return
        self.status_var.set(f"Reading {len(files):,} files…")
        self._set_busy(True)
        threading.Thread(target=self._parse_worker, args=(files,), daemon=True).start()
        self.after(80, self._poll_worker)

    def _set_busy(self, busy: bool) -> None:
        self.configure(cursor="watch" if busy else "")

    def _parse_worker(self, files: list[Path]) -> None:
        try:
            self._queue.put(parse_files(files))
        except Exception as exc:
            self._queue.put(exc)

    def _poll_worker(self) -> None:
        try:
            result = self._queue.get_nowait()
        except queue.Empty:
            self.after(80, self._poll_worker)
            return
        self._set_busy(False)
        if isinstance(result, Exception):
            messagebox.showerror("Could not read reports", str(result))
            self.status_var.set("Read failed")
            return
        self.rows = result.rows
        self.apply_filters()
        self._update_cards(result)
        issue_note = f" · {len(result.issues)} skipped" if result.issues else ""
        self.status_var.set(f"{result.reports_parsed:,} reports · {len(result.rows):,} rows{issue_note}")
        if result.issues:
            preview = "\n".join(f"• {i.source_file}: {i.message}" for i in result.issues[:8])
            more = f"\n…and {len(result.issues) - 8} more" if len(result.issues) > 8 else ""
            messagebox.showwarning("Some files were skipped", preview + more)

    def _update_cards(self, result: ParseResult) -> None:
        messages = sum(row.count for row in self.rows)
        passed = sum(row.count for row in self.rows if row.aligned)
        rate = (passed / messages * 100) if messages else 0
        self.card_vars["Messages"].set(f"{messages:,}")
        self.card_vars["Pass rate"].set(f"{rate:.1f}%")
        self.card_vars["Sources"].set(f"{len({row.source_ip for row in self.rows}):,}")
        self.card_vars["Reports"].set(f"{result.reports_parsed:,}")

    def apply_filters(self) -> None:
        needle = self.search_var.get().strip().lower()
        outcome = self.result_var.get()
        def matches(row: DmarcRow) -> bool:
            text = " ".join((row.source_ip, row.domain, row.organization, row.header_from, row.source_file)).lower()
            return (not needle or needle in text) and (outcome == "All" or (outcome == "Pass") == row.aligned)
        self.filtered_rows = [row for row in self.rows if matches(row)]
        self.sort_by(self._sort_column, preserve_direction=True)

    def sort_by(self, column: str, preserve_direction: bool = False) -> None:
        if not preserve_direction:
            self._sort_reverse = not self._sort_reverse if column == self._sort_column else column == "count"
        self._sort_column = column
        self.filtered_rows.sort(key=lambda row: getattr(row, column), reverse=self._sort_reverse)
        self.tree.delete(*self.tree.get_children())
        for index, row in enumerate(self.filtered_rows):
            self.tree.insert("", "end", iid=str(index), values=(row.source_ip, f"{row.count:,}", row.domain, row.organization, row.dkim.upper(), row.spf.upper(), row.disposition, row.begin), tags=("pass" if row.aligned else "fail",))

    def show_details(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        row = self.filtered_rows[int(selected[0])]
        details = (
            f"Source file: {row.source_file}\nReport ID: {row.report_id}\nReporter: {row.organization}\n"
            f"Period: {row.begin} — {row.end}\n\nSource IP: {row.source_ip}\nMessages: {row.count:,}\n"
            f"Policy domain: {row.domain}\nHeader From: {row.header_from or '—'}\nEnvelope From: {row.envelope_from or '—'}\n\n"
            f"DKIM: {row.dkim.upper()}  ({row.dkim_domains or 'no domain'})\nSPF: {row.spf.upper()}  ({row.spf_domains or 'no domain'})\nDisposition: {row.disposition}"
        )
        messagebox.showinfo("Record details", details)

    def export_csv(self) -> None:
        if not self.filtered_rows:
            messagebox.showinfo("Nothing to export", "Load reports first, or change the filters.")
            return
        destination = filedialog.asksaveasfilename(title="Export filtered records", defaultextension=".csv", filetypes=(("CSV files", "*.csv"),))
        if not destination:
            return
        fields = tuple(DmarcRow.__dataclass_fields__)
        try:
            with open(destination, "w", newline="", encoding="utf-8-sig") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                for row in self.filtered_rows:
                    writer.writerow({field: getattr(row, field) for field in fields})
            self.status_var.set(f"Exported {len(self.filtered_rows):,} rows")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))


if __name__ == "__main__":
    DmarcApp().mainloop()

