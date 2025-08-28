

import os
import json
import hashlib
import queue
import threading
import time
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox
import tkinter.ttk as ttk
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet

# ------------------ Paths ------------------
APP_DIR = Path.home() / ".hexmire_antivirus"
QUARANTINE_DIR = APP_DIR / "quarantine"
SIGN_FILE = APP_DIR / "signatures.json"

DEFAULT_SIGS = {
    "known_bad": [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ]
}

SUSPICIOUS_STRINGS = [
    "powershell -enc", "from base64 import b64decode", "cmd.exe /c",
    "WScript.Shell", "reg add", "schtasks /create", "Add-MpPreference",
    "VirtualAlloc", "WriteProcessMemory", "rundll32"
]

RISKY_EXTENSIONS = {".exe",".dll",".js",".vbs",".ps1",".bat",".cmd",".scr",".pif",".jar",".msi",".hta",".lnk"}

# ------------------ Helpers ------------------
def ensure_dirs():
    APP_DIR.mkdir(exist_ok=True)
    QUARANTINE_DIR.mkdir(exist_ok=True)
    if not SIGN_FILE.exists():
        SIGN_FILE.write_text(json.dumps(DEFAULT_SIGS, indent=2))

def load_signatures():
    try:
        data = json.loads(SIGN_FILE.read_text())
        return set(sig.lower() for sig in data.get("known_bad", []))
    except:
        return set(sig.lower() for sig in DEFAULT_SIGS["known_bad"])

def sha256_file(f: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with f.open('rb') as fd:
            for chunk in iter(lambda: fd.read(1024*1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

@dataclass
class Detection:
    path: Path
    status: str
    reason: str
    sha256: Optional[str]

# ------------------ Heuristic ------------------
def heuristic_check(f: Path):
    reasons = []
    if f.suffix.lower() in RISKY_EXTENSIONS:
        reasons.append(f"Risky extension: {f.suffix.lower()}")
    
    try:
        head = f.read_bytes()[:64*1024]  # first 64KB
        text_head = head.decode('utf-8', errors='ignore').lower()
        for s in SUSPICIOUS_STRINGS:
            if s.lower() in text_head:
                reasons.append(f"Suspicious string: {s}")
                break
        # entropy check
        if head:
            counts = [0]*256
            for b in head: counts[b]+=1
            from math import log2
            ent = -sum((c/len(head))*log2(c/len(head)) for c in counts if c)
            if ent>7.5: reasons.append(f"High entropy: {ent:.2f}")
    except:
        pass
    return (len(reasons)>0, reasons)

# ------------------ Scanner Thread ------------------
class Scanner(threading.Thread):
    def __init__(self, roots, q, stop_evt, stats_func):
        super().__init__()
        self.roots = roots
        self.q = q
        self.stop = stop_evt
        self.stats = stats_func
        self.sigs = load_signatures()

    def run(self):
        scanned=0
        hits=0
        start=time.time()
        for r in self.roots:
            if self.stop.is_set(): break
            for folder,_,files in os.walk(r):
                for fn in files:
                    if self.stop.is_set(): break
                    p = Path(folder)/fn
                    det = self.scan_file(p)
                    scanned+=1
                    if det.status in ("INFECTED","SUSPICIOUS"): hits+=1
                    self.stats(scanned,hits,round(time.time()-start,1))
                    self.q.put(det)
        self.q.put(None)

    def scan_file(self,f:Path):
        try:
            sus,reasons = heuristic_check(f)
            h = sha256_file(f)
            if h and h.lower() in self.sigs:
                return Detection(f,"INFECTED","Signature match",h)
            if sus:
                return Detection(f,"SUSPICIOUS","; ".join(reasons),h)
            return Detection(f,"CLEAN","",h)
        except Exception as e:
            return Detection(f,"ERROR",str(e),None)

# ------------------ GUI ------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")
COLORS = ["#f58529","#dd2a7b","#8134af","#515bd4"]

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Mini Antivirus – HEXMIRE Pro")
        self.geometry("1200x700")
        ensure_dirs()

        self.q = queue.Queue()
        self.stop_evt = threading.Event()
        self.scan_thread = None

        self.files_scanned=0
        self.hits=0
        self.time_elapsed=0
        self.results: List[Detection]=[]

        self.build_ui()
        self.poll_queue()

    def build_ui(self):
        ctk.CTkLabel(self,text="🛡 HEXMIRE Antivirus Dashboard",font=("Arial",28,"bold")).pack(pady=10)
        btn_frame=ctk.CTkFrame(self)
        btn_frame.pack(fill="x",padx=20,pady=10)
        ctk.CTkButton(btn_frame,text="Quick Scan",fg_color=COLORS[0],command=self.quick_scan).pack(side="left",padx=6)
        ctk.CTkButton(btn_frame,text="Scan Folder",fg_color=COLORS[1],command=self.scan_folder).pack(side="left",padx=6)
        ctk.CTkButton(btn_frame,text="Full Scan",fg_color=COLORS[2],command=self.full_scan).pack(side="left",padx=6)
        ctk.CTkButton(btn_frame,text="Stop",fg_color="#ff4d4d",command=self.stop_scan).pack(side="left",padx=6)
        ctk.CTkButton(btn_frame,text="Export PDF",fg_color="#3cb371",command=self.export_pdf).pack(side="left",padx=6)
        ctk.CTkButton(btn_frame,text="Show Chart",fg_color="#1e90ff",command=self.show_chart).pack(side="left",padx=6)

        self.progress=ctk.CTkProgressBar(self,width=500)
        self.progress.set(0)
        self.progress.pack(pady=8)
        self.stats_label=ctk.CTkLabel(self,text="Files Scanned: 0 | Detections: 0 | Time: 0s",font=("Arial",16))
        self.stats_label.pack(pady=5)

        self.tree=ttk.Treeview(self,columns=("path","status","reason","sha256"),show="headings",height=15)
        for c in self.tree["columns"]:
            self.tree.heading(c,text=c.capitalize())
            self.tree.column(c,width=300 if c=="sha256" else 150)
        self.tree.pack(fill="both",expand=True,padx=20,pady=10)

    def update_stats(self,scanned,hits,elapsed):
        self.files_scanned=scanned
        self.hits=hits
        self.time_elapsed=elapsed
        self.stats_label.configure(text=f"Files Scanned: {scanned} | Detections: {hits} | Time: {elapsed}s")
        self.progress.set(min(1,scanned/500))

    def quick_scan(self):
        self.start_scan([Path.home()])

    def scan_folder(self):
        folder=filedialog.askdirectory(title="Select Folder")
        if folder: self.start_scan([Path(folder)])

    def full_scan(self):
        root = Path(os.environ.get("SystemDrive","C:")+"/") if os.name=="nt" else Path("/")
        self.start_scan([root])

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_evt.set()

    def start_scan(self,roots):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan running","Stop the current scan first!")
            return
        for i in self.tree.get_children(): self.tree.delete(i)
        self.results.clear()
        self.stop_evt.clear()
        self.q=queue.Queue()
        self.progress.set(0)
        self.files_scanned=self.hits=self.time_elapsed=0
        self.stats_label.configure(text="Files Scanned: 0 | Detections: 0 | Time: 0s")
        self.scan_thread=Scanner(roots,self.q,self.stop_evt,self.update_stats)
        self.scan_thread.start()

    def poll_queue(self):
        try:
            while True:
                item=self.q.get_nowait()
                if item is None: break
                self.results.append(item)
                self.tree.insert('','end',values=(str(item.path),item.status,item.reason,item.sha256 or ""))
        except queue.Empty: pass
        self.after(80,self.poll_queue)

    def show_chart(self):
        clean=self.files_scanned-self.hits
        infected=self.hits
        plt.figure(figsize=(6,6))
        plt.pie([infected,clean],labels=["Detections","Clean"],colors=["#dd2a7b","#3cb371"],autopct='%1.1f%%')
        plt.title("Scan Results")
        plt.show()

    def export_pdf(self):
        file_path=filedialog.asksaveasfilename(defaultextension=".pdf",filetypes=[("PDF files","*.pdf")])
        if not file_path: return
        doc=SimpleDocTemplate(file_path,pagesize=A4)
        styles=getSampleStyleSheet()
        content=[]
        content.append(Paragraph("<b>HEXMIRE Antivirus Scan Report</b>",styles['Title']))
        content.append(Spacer(1,12))
        content.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",styles['Normal']))
        content.append(Paragraph(f"Files Scanned: {self.files_scanned}",styles['Normal']))
        content.append(Paragraph(f"Detections: {self.hits}",styles['Normal']))
        content.append(Paragraph(f"Elapsed Time: {self.time_elapsed}s",styles['Normal']))
        content.append(Spacer(1,12))
        data=[["Path","Status","Reason"]]+[[str(r.path),r.status,r.reason] for r in self.results[:20]]
        content.append(Table(data))
        doc.build(content)
        messagebox.showinfo("Export","PDF saved to "+file_path)

if __name__=="__main__":
    try:
        app=App()
        app.mainloop()
    except KeyboardInterrupt:
        pass
