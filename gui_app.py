"""
Modern GUI Application for OSINT Tool
Windows-based footprinting tool with graph visualization
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
from datetime import datetime
import os
from typing import Dict
import sys
import platform
import tempfile
import shutil

# Suppress whois errors before importing analyzers
import logging
logging.basicConfig(level=logging.CRITICAL, format='', force=True)
_whois_log = logging.getLogger('whois')
_whois_log.setLevel(logging.CRITICAL + 1)
_whois_log.disabled = True
_whois_log.propagate = False
for _h in list(_whois_log.handlers):
    _whois_log.removeHandler(_h)

# Sound support for Windows
try:
    if platform.system() == 'Windows':
        import winsound
        SOUND_AVAILABLE = True
    else:
        # For Linux/Mac, try using system beep
        SOUND_AVAILABLE = False
except ImportError:
    SOUND_AVAILABLE = False

# Core imports
from osint_tool.core.entity_detector import EntityDetector, EntityType
from osint_tool.core.domain_analyzer import DomainAnalyzer
from osint_tool.core.url_analyzer import URLAnalyzer
from osint_tool.core.email_analyzer import EmailAnalyzer
from osint_tool.core.ip_analyzer import IPAnalyzer
from osint_tool.core.mobile_analyzer import MobileAnalyzer
from osint_tool.core.person_analyzer import PersonAnalyzer
from osint_tool.core.organization_analyzer import OrganizationAnalyzer
from osint_tool.core.ioc_analyzer import IOCAnalyzer
from osint_tool.core.relationship_analyzer import RelationshipAnalyzer

# Graph visualization
try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    import matplotlib.pyplot as plt
    import networkx as nx
    GRAPH_AVAILABLE = True
except ImportError:
    GRAPH_AVAILABLE = False


class ModernOSINTGUI:
    """Modern GUI for OSINT Footprinting Tool"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("OSINT Footprint Gathering Tool")
        self.root.configure(bg='#2b2b2b')
        self.root.resizable(True, True)

        self.root.update_idletasks()
        sw = max(1024, self.root.winfo_screenwidth())
        sh = max(768, self.root.winfo_screenheight())

        # Responsive size: fit 85–92% of screen, clamp for small/large laptops
        self._screen_w = sw
        self._screen_h = sh
        win_w = min(max(int(sw * 0.90), 960), 1920)
        win_h = min(max(int(sh * 0.88), 600), 1080)
        self._init_w = win_w
        self._init_h = win_h

        self.root.minsize(880, 560)
        cx = max(0, (sw - win_w) // 2)
        cy = max(0, (sh - win_h) // 2)
        self.root.geometry(f"{win_w}x{win_h}+{cx}+{cy}")
        self.root.update_idletasks()
        
        # Style configuration
        self.setup_styles()
        
        # Data storage
        self.analysis_history = []
        self.relationship_analyzer = RelationshipAnalyzer()
        self.current_results = None
        
        self._resize_after_id = None
        self.create_widgets()
        self.root.bind('<Configure>', self._on_configure_resize)
        self.root.update_idletasks()
        self.center_window()
    
    def setup_styles(self):
        """Configure modern styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors for dark theme
        style.configure('TFrame', background='#2b2b2b')
        style.configure('TLabel', background='#2b2b2b', foreground='#ffffff', font=('Segoe UI', 10))
        style.configure('TEntry', fieldbackground='#3c3c3c', foreground='#ffffff', borderwidth=1)
        style.configure('TButton', background='#0078d4', foreground='#ffffff', font=('Segoe UI', 9))
        style.map('TButton', background=[('active', '#005a9e')])
        style.configure('TNotebook', background='#2b2b2b', borderwidth=0)
        # Touch-friendly tabs: larger padding, clear font, top-aligned tab bar
        style.configure(
            'TNotebook.Tab',
            background='#3c3c3c',
            foreground='#ffffff',
            font=('Segoe UI', 11),
            padding=[28, 16],
        )
        style.map('TNotebook.Tab', background=[('selected', '#0078d4')])
        # Vertical scrollbar for Results / History (dark theme)
        style.configure(
            'Vertical.TScrollbar',
            background='#3c3c3c',
            troughcolor='#2b2b2b',
            darkcolor='#3c3c3c',
            lightcolor='#555555',
            arrowcolor='#ffffff',
        )
        style.map('Vertical.TScrollbar', background=[('active', '#0078d4')])

    def _on_mousewheel(self, event, widget):
        """Scroll widget vertically with mousewheel (Windows: delta; Linux: Button-4/5; macOS: delta)."""
        delta = 0
        if hasattr(event, 'delta') and event.delta:
            delta = -1 * (event.delta // 120) if event.delta else 0
        elif getattr(event, 'num', None) == 5:
            delta = -1
        elif getattr(event, 'num', None) == 4:
            delta = 1
        if delta:
            try:
                widget.yview_scroll(delta, 'units')
            except Exception:
                pass

    def _create_scrollable_text(self, parent, wrap=tk.WORD, font=('Consolas', 10), **kwargs):
        """Create a Text widget with vertical scrollbar and mousewheel support. Returns the Text widget."""
        container = ttk.Frame(parent)
        container.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, style='Vertical.TScrollbar')
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text = tk.Text(
            container,
            wrap=wrap,
            font=font,
            yscrollcommand=scrollbar.set,
            **kwargs
        )
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text.yview)

        def _wheel(e):
            self._on_mousewheel(e, text)

        text.bind('<MouseWheel>', _wheel)
        text.bind('<Button-4>', _wheel)
        text.bind('<Button-5>', _wheel)
        return text

    def center_window(self):
        """Center the window on screen; use responsive size if not yet rendered."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        if width <= 1 or height <= 1:
            width = self._init_w
            height = self._init_h
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = max(0, min((sw - width) // 2, sw - width - 20))
        y = max(0, min((sh - height) // 2, sh - height - 20))
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def _responsive(self, key, width=None):
        """Return responsive values from screen or current width (for all laptop screens)."""
        sw = width if width is not None else self._screen_w
        sh = self._screen_h
        r = {
            'entity_btn_width': min(18, max(12, sw // 80)),
            'entity_desc_wraplength': min(220, max(120, sw // 6)),
            'input_width': min(60, max(32, sw // 22)),
            'progress_length': min(400, max(180, sw // 4)),
            'examples_wraplength': max(320, sw - 220),
            'notebook_minsize': min(320, max(240, sh // 4)),
        }
        return r.get(key, 0)

    def _on_configure_resize(self, event):
        """Debounced resize: update examples wraplength and progress length."""
        if event.widget != self.root:
            return
        w = event.width
        if w <= 1:
            return
        if self._resize_after_id:
            self.root.after_cancel(self._resize_after_id)
        def _apply():
            self._resize_after_id = None
            try:
                ex = self._responsive('examples_wraplength', w)
                self.examples_label.config(wraplength=max(200, ex))
                pl = self._responsive('progress_length', w)
                self.progress.config(length=pl)
            except (AttributeError, tk.TclError):
                pass
        self._resize_after_id = self.root.after(120, _apply)

    def create_widgets(self):
        """Create main UI widgets (responsive for all laptop screens)."""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.main_frame = main_frame
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        nb_minsize = self._responsive('notebook_minsize')
        main_frame.rowconfigure(3, weight=1, minsize=nb_minsize)

        # Header
        header_frame = tk.Frame(main_frame, bg='#2b2b2b')
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        header_frame.columnconfigure(0, weight=1)
        
        title_label = tk.Label(
            header_frame,
            text="OSINT Footprint Gathering Tool",
            font=('Segoe UI', 22, 'bold'),
            bg='#2b2b2b',
            fg='#ffffff'
        )
        title_label.pack(side=tk.LEFT)
        subtitle_label = tk.Label(
            header_frame,
            text="Comprehensive Intelligence Gathering Platform",
            font=('Segoe UI', 10),
            bg='#2b2b2b',
            fg='#aaaaaa',
            wraplength=max(260, self._screen_w - 420),
        )
        subtitle_label.pack(side=tk.LEFT, padx=(15, 0), fill=tk.X, expand=True)
        
        # Entity Type Selection Frame
        entity_frame = tk.LabelFrame(
            main_frame,
            text="Select Entity Type for Footprint Gathering",
            font=('Segoe UI', 11, 'bold'),
            bg='#2b2b2b',
            fg='#ffffff',
            padx=15,
            pady=15
        )
        entity_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        entity_frame.columnconfigure(0, weight=1)

        # Entity type buttons in a grid
        self.selected_entity_type = tk.StringVar(value="auto")
        
        entity_types = [
            ("Domain", "domain", "Analyze domains, DNS, WHOIS, subdomains"),
            ("URL", "url", "Analyze URLs, headers, content, security"),
            ("Email", "email", "Analyze emails, MX, SPF/DKIM/DMARC"),
            ("IP Address", "ip", "Geolocation, ASN, ISP, port scan"),
            ("Mobile Number", "mobile", "Country, carrier, format analysis"),
            ("Person/Username", "person", "Social media, GitHub, profiles"),
            ("Organization", "organization", "Domains, infrastructure, footprint"),
            ("IOC/Threat Intel", "ioc", "Malicious indicators, threat intel"),
            ("Auto-Detect", "auto", "Automatically detect entity type")
        ]
        
        buttons_frame = tk.Frame(entity_frame, bg='#2b2b2b')
        buttons_frame.pack(fill=tk.BOTH, expand=True)
        
        for i, (label, value, desc) in enumerate(entity_types):
            row = i // 3
            col = i % 3
            
            btn_frame = tk.Frame(buttons_frame, bg='#3c3c3c', relief=tk.RAISED, bd=1)
            btn_frame.grid(row=row, column=col, padx=5, pady=5, sticky=(tk.W, tk.E))
            buttons_frame.columnconfigure(col, weight=1)
            
            ew = self._responsive('entity_btn_width')
            btn = tk.Radiobutton(
                btn_frame,
                text=label,
                variable=self.selected_entity_type,
                value=value,
                font=('Segoe UI', 10),
                bg='#3c3c3c',
                fg='#ffffff',
                selectcolor='#0078d4',
                activebackground='#0078d4',
                activeforeground='#ffffff',
                indicatoron=0,
                padx=10,
                pady=8,
                width=ew
            )
            btn.pack(fill=tk.BOTH, expand=True)
            dw = self._responsive('entity_desc_wraplength')
            desc_label = tk.Label(
                btn_frame,
                text=desc,
                font=('Segoe UI', 8),
                bg='#3c3c3c',
                fg='#aaaaaa',
                wraplength=dw,
            )
            desc_label.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        # Input section - MUST BE VISIBLE
        input_frame = tk.LabelFrame(
            main_frame,
            text="Target Input - Enter Your Target for Footprint Gathering",
            font=('Segoe UI', 11, 'bold'),
            bg='#2b2b2b',
            fg='#ffffff',
            padx=15,
            pady=15
        )
        input_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N), pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)
        input_frame.grid_propagate(True)  # Allow frame to shrink/expand naturally
        
        # Instruction label
        instruction_label = tk.Label(
            input_frame,
            text="Enter the target below based on the selected entity type above:",
            font=('Segoe UI', 9, 'italic'),
            bg='#2b2b2b',
            fg='#aaaaaa',
            anchor='w'
        )
        instruction_label.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Target input row
        target_row = tk.Frame(input_frame, bg='#2b2b2b')
        target_row.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        target_row.columnconfigure(1, weight=1)
        
        input_label = tk.Label(
            target_row,
            text="Target:",
            font=('Segoe UI', 11, 'bold'),
            bg='#2b2b2b',
            fg='#ffffff',
            width=10,
            anchor='w'
        )
        input_label.grid(row=0, column=0, padx=(0, 10), sticky=tk.W)
        
        # Input entry with placeholder effect
        entry_frame = tk.Frame(target_row, bg='#3c3c3c', relief=tk.FLAT, bd=1)
        entry_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        entry_frame.columnconfigure(0, weight=1)
        
        iw = self._responsive('input_width')
        self.input_entry = tk.Entry(
            entry_frame,
            font=('Segoe UI', 11),
            bg='#3c3c3c',
            fg='#ffffff',
            insertbackground='#ffffff',
            relief=tk.FLAT,
            bd=8,
            highlightthickness=1,
            highlightbackground='#555555',
            highlightcolor='#0078d4',
            width=iw,
        )
        self.input_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=2, pady=2)
        self.input_entry.bind('<Return>', lambda e: self.start_analysis())
        self.input_entry.bind('<FocusIn>', self.on_entry_focus_in)
        self.input_entry.bind('<FocusOut>', self.on_entry_focus_out)
        self.input_entry.bind('<Key>', self.on_entry_key)  # Track typing
        
        # Placeholder text based on entity type
        self.placeholder_texts = {
            "domain": "Enter domain name (e.g., example.com)",
            "url": "Enter URL (e.g., https://example.com or example.com)",
            "email": "Enter email address (e.g., user@example.com)",
            "ip": "Enter IP address (e.g., 8.8.8.8)",
            "mobile": "Enter mobile number (e.g., +1234567890)",
            "person": "Enter username/person name (e.g., johndoe)",
            "organization": "Enter organization name (e.g., Example Corp)",
            "ioc": "Enter IOC indicator (IP, domain, URL, or hash)",
            "auto": "Enter any target - auto-detect type"
        }
        self.placeholder_text = self.placeholder_texts["auto"]
        self.input_entry.insert(0, self.placeholder_text)
        self.input_entry.config(fg='#888888')
        self.entry_has_placeholder = True
        
        # Update placeholder when entity type changes
        self.selected_entity_type.trace_add('write', self.update_placeholder)
        
        self.input_entry.focus()
        
        # Action buttons frame
        button_frame = tk.Frame(target_row, bg='#2b2b2b')
        button_frame.grid(row=0, column=2, sticky=tk.W)
        
        self.analyze_button = tk.Button(
            button_frame,
            text="Analyze Target",
            font=('Segoe UI', 10, 'bold'),
            bg='#0078d4',
            fg='#ffffff',
            activebackground='#005a9e',
            activeforeground='#ffffff',
            relief=tk.FLAT,
            padx=20,
            pady=8,
            cursor='hand2',
            command=self.start_analysis
        )
        self.analyze_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.clear_button = tk.Button(
            button_frame,
            text="Clear",
            font=('Segoe UI', 10),
            bg='#6c757d',
            fg='#ffffff',
            activebackground='#5a6268',
            activeforeground='#ffffff',
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor='hand2',
            command=self.clear_input
        )
        self.clear_button.pack(side=tk.LEFT)
        
        # Progress bar with label
        progress_frame = tk.Frame(input_frame, bg='#2b2b2b')
        progress_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(15, 5))
        progress_frame.columnconfigure(1, weight=1)
        
        self.progress_label = tk.Label(
            progress_frame,
            text="Status: Ready",
            font=('Segoe UI', 9),
            bg='#2b2b2b',
            fg='#6a9955',
            anchor='w'
        )
        self.progress_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        plen = self._responsive('progress_length')
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate', length=plen)
        self.progress.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        # Example targets section
        examples_container = tk.Frame(input_frame, bg='#2b2b2b')
        examples_container.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        examples_title = tk.Label(
            examples_container,
            text="Quick Examples:",
            font=('Segoe UI', 9, 'bold'),
            bg='#2b2b2b',
            fg='#ffc107',
            anchor='w'
        )
        examples_title.pack(side=tk.LEFT, padx=(0, 10))
        
        ex_wrap = self._responsive('examples_wraplength')
        self.examples_label = tk.Label(
            examples_container,
            text="Domain: example.com | IP: 8.8.8.8 | Email: user@example.com | URL: https://example.com | Username: johndoe | Mobile: +1234567890",
            font=('Segoe UI', 8),
            bg='#2b2b2b',
            fg='#888888',
            anchor='w',
            wraplength=ex_wrap,
        )
        self.examples_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Main content area with tabs - top-aligned, touch-friendly (Results | Relationship Graph | History)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        self.notebook.grid_propagate(False)

        # Results tab
        self.results_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.results_frame, text="Results")

        self.create_results_display()

        # Relationship Graph tab
        if GRAPH_AVAILABLE:
            self.graph_frame = ttk.Frame(self.notebook, padding="10")
            self.notebook.add(self.graph_frame, text="Relationship Graph")
            self.create_graph_display()
        else:
            graph_warning = ttk.Label(
                self.notebook,
                text="Graph visualization requires matplotlib and networkx.\nInstall with: pip install matplotlib networkx",
                foreground='#ff6b6b'
            )
            self.notebook.add(graph_warning, text="Relationship Graph")

        # History tab
        self.history_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.history_frame, text="History")
        self.create_history_display()
        
        # Footer (responsive: status grows, buttons stay right)
        footer_frame = tk.Frame(main_frame, bg='#2b2b2b')
        footer_frame.grid(row=4, column=0, sticky=(tk.W, tk.E))
        footer_frame.columnconfigure(0, weight=1)

        status_label = tk.Label(
            footer_frame,
            text="Ready - Select entity type above and enter target",
            bg='#2b2b2b',
            fg='#6a9955',
            font=('Segoe UI', 9),
            anchor='w',
        )
        status_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.status_label = status_label

        button_container = tk.Frame(footer_frame, bg='#2b2b2b')
        button_container.grid(row=0, column=1, sticky=tk.E)
        
        export_json_btn = tk.Button(
            button_container,
            text="Export JSON",
            font=('Segoe UI', 9),
            bg='#28a745',
            fg='#ffffff',
            activebackground='#218838',
            activeforeground='#ffffff',
            relief=tk.FLAT,
            padx=12,
            pady=5,
            cursor='hand2',
            command=self.export_results
        )
        export_json_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        export_report_btn = tk.Button(
            button_container,
            text="Export Report (TXT)",
            font=('Segoe UI', 9),
            bg='#17a2b8',
            fg='#ffffff',
            activebackground='#138496',
            activeforeground='#ffffff',
            relief=tk.FLAT,
            padx=12,
            pady=5,
            cursor='hand2',
            command=self.export_report
        )
        export_report_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        export_pdf_btn = tk.Button(
            button_container,
            text="Export PDF Report",
            font=('Segoe UI', 9),
            bg='#dc3545',
            fg='#ffffff',
            activebackground='#c82333',
            activeforeground='#ffffff',
            relief=tk.FLAT,
            padx=12,
            pady=5,
            cursor='hand2',
            command=self.export_pdf_report
        )
        export_pdf_btn.pack(side=tk.LEFT)
    
    def create_results_display(self):
        """Create results display area with vertical scrollbar and mousewheel."""
        self.results_text = self._create_scrollable_text(
            self.results_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#1e1e1e',
            fg='#d4d4d4',
            insertbackground='#ffffff',
            relief=tk.FLAT,
        )
        # Configure text tags for syntax highlighting
        self.results_text.tag_configure('header', foreground='#4ec9b0', font=('Consolas', 12, 'bold'))
        self.results_text.tag_configure('key', foreground='#9cdcfe')
        self.results_text.tag_configure('value', foreground='#ce9178')
        self.results_text.tag_configure('error', foreground='#f48771')
        self.results_text.tag_configure('success', foreground='#6a9955')
    
    def create_graph_display(self):
        """Create graph visualization area with interactive features"""
        if not GRAPH_AVAILABLE:
            return
        
        # Main container for canvas and toolbar
        graph_container = ttk.Frame(self.graph_frame)
        graph_container.pack(fill=tk.BOTH, expand=True)
        
        self.graph_canvas_frame = ttk.Frame(graph_container)
        self.graph_canvas_frame.pack(fill=tk.BOTH, expand=True)

        fw = min(12.0, max(7.0, self._screen_w / 110.0))
        fh = min(8.0, max(5.0, self._screen_h / 110.0))
        self.fig = plt.figure(figsize=(fw, fh), facecolor='#2b2b2b')
        self.ax = self.fig.add_subplot(111, facecolor='#2b2b2b')
        self.ax.axis('off')
        
        # Canvas
        self.canvas = FigureCanvasTkAgg(self.fig, self.graph_canvas_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add interactive navigation toolbar (Zoom, Pan, etc.)
        toolbar_frame = ttk.Frame(graph_container)
        toolbar_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.toolbar = NavigationToolbar2Tk(self.canvas, toolbar_frame)
        self.toolbar.update()
        
        # Make toolbar buttons visible (dark theme compatible)
        try:
            # Style toolbar for dark theme
            for child in self.toolbar.winfo_children():
                if isinstance(child, tk.Button):
                    child.config(bg='#3c3c3c', fg='#ffffff', activebackground='#0078d4', 
                               activeforeground='#ffffff', relief=tk.FLAT)
        except Exception:
            pass  # If styling fails, continue with default
        
        # Additional controls
        controls_frame = ttk.Frame(self.graph_frame)
        controls_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(controls_frame, text="Refresh Graph", command=self.update_graph).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(controls_frame, text="Save Graph", command=self.save_graph).pack(side=tk.LEFT, padx=(0, 10))
        
        # Add reset zoom button
        ttk.Button(controls_frame, text="Reset Zoom", command=self.reset_graph_view).pack(side=tk.LEFT)
    
    def create_history_display(self):
        """Create history display with vertical scrollbar and mousewheel."""
        self.history_text = self._create_scrollable_text(
            self.history_frame,
            wrap=tk.WORD,
            font=('Segoe UI', 9),
            bg='#1e1e1e',
            fg='#d4d4d4',
            relief=tk.FLAT,
        )
    
    def play_loading_sound(self):
        """Play loading sound when analysis starts"""
        try:
            if SOUND_AVAILABLE and platform.system() == 'Windows':
                winsound.Beep(800, 100)  # Frequency 800Hz, duration 100ms
            else:
                # Fallback: print bell character (may work on some terminals)
                print('\a', end='', flush=True)
        except Exception:
            pass
    
    def play_completion_sound(self):
        """Play completion sound"""
        try:
            if SOUND_AVAILABLE and platform.system() == 'Windows':
                winsound.Beep(1000, 150)  # Higher pitch for completion
            else:
                print('\a', end='', flush=True)
        except Exception:
            pass
    
    def play_error_sound(self):
        """Play error sound"""
        try:
            if SOUND_AVAILABLE and platform.system() == 'Windows':
                winsound.Beep(400, 200)  # Lower pitch for error
            else:
                print('\a\a', end='', flush=True)  # Double beep for error
        except Exception:
            pass
    
    def start_analysis(self):
        """Start analysis in background thread"""
        entity = self.input_entry.get().strip()
        
        # Check if placeholder text or empty
        if self.entry_has_placeholder or not entity:
            messagebox.showwarning("Warning", "Please enter a target to analyze")
            self.input_entry.focus()
            # Clear placeholder if still there
            if self.entry_has_placeholder:
                self.input_entry.delete(0, tk.END)
                self.input_entry.config(fg='#ffffff')
                self.entry_has_placeholder = False
            return
        
        # Check against all possible placeholder texts
        if entity in self.placeholder_texts.values():
            messagebox.showwarning("Warning", "Please enter a valid target to analyze")
            self.input_entry.focus()
            self.input_entry.delete(0, tk.END)
            self.input_entry.config(fg='#ffffff')
            self.entry_has_placeholder = False
            return
        
        entity_type_selection = self.selected_entity_type.get()
        
        # For URLs, ensure proper format but preserve user input
        if entity_type_selection == "url":
            # Strip spaces and ensure proper URL format
            entity = entity.strip()
            # Remove any trailing/leading spaces
            entity = ' '.join(entity.split())  # Normalize multiple spaces to single space, but keep single space
            # Don't auto-add https:// if user didn't include it - let analyzer handle it
        
        # Get entity type label for display
        type_labels = {
            "domain": "Domain",
            "url": "URL",
            "email": "Email",
            "ip": "IP Address",
            "mobile": "Mobile Number",
            "person": "Person/Username",
            "organization": "Organization",
            "ioc": "IOC/Threat Intel",
            "auto": "Auto-Detect"
        }
        type_label = type_labels.get(entity_type_selection, entity_type_selection)
        
        # Play loading sound
        self.play_loading_sound()
        
        # Disable button and start progress
        self.analyze_button.config(state='disabled')
        self.clear_button.config(state='disabled')
        self.input_entry.config(state='disabled')
        self.progress.start(10)
        
        # Update status labels
        status_text = f"Analyzing {type_label}: {entity}"
        self.status_label.config(text=status_text, fg='#ffc107')
        self.progress_label.config(text=f"Status: Analyzing {entity}...", fg='#ffc107')
        
        # Run analysis in background thread
        thread = threading.Thread(target=self.perform_analysis, args=(entity, entity_type_selection))
        thread.daemon = True
        thread.start()
    
    def perform_analysis(self, entity: str, selected_type: str = "auto"):
        """Perform the actual analysis"""
        try:
            # Use selected type or auto-detect
            if selected_type == "auto":
                entity_type = EntityDetector.detect(entity)
            else:
                # Map selection to EntityType enum
                type_map = {
                    "domain": EntityType.DOMAIN,
                    "url": EntityType.URL,
                    "email": EntityType.EMAIL,
                    "ip": EntityType.IP,
                    "mobile": EntityType.MOBILE,
                    "person": EntityType.PERSON,
                    "organization": EntityType.ORGANIZATION,
                    "ioc": EntityType.IOC
                }
                entity_type = type_map.get(selected_type, EntityDetector.detect(entity))
            
            # Run appropriate analyzer
            result = None
            analyzer_name = None
            
            if entity_type == EntityType.DOMAIN:
                analyzer = DomainAnalyzer()
                result = analyzer.analyze(entity)
                analyzer_name = "Domain Analyzer"
                
            elif entity_type == EntityType.URL:
                analyzer = URLAnalyzer()
                result = analyzer.analyze(entity)
                analyzer_name = "URL Analyzer"
                
            elif entity_type == EntityType.EMAIL:
                analyzer = EmailAnalyzer()
                result = analyzer.analyze(entity)
                analyzer_name = "Email Analyzer"
                
            elif entity_type == EntityType.IP:
                analyzer = IPAnalyzer()
                result = analyzer.analyze(entity)
                analyzer_name = "IP Analyzer"
                
            elif entity_type == EntityType.MOBILE:
                analyzer = MobileAnalyzer()
                result = analyzer.analyze(entity)
                analyzer_name = "Mobile Analyzer"
                
            elif entity_type == EntityType.PERSON:
                analyzer = PersonAnalyzer()
                result = analyzer.analyze(entity)
                analyzer_name = "Person Analyzer"
                
            elif entity_type == EntityType.IOC:
                analyzer = IOCAnalyzer()
                result = analyzer.analyze(entity)
                analyzer_name = "IOC Analyzer"
                
            else:
                # Try organization
                if EntityDetector.is_organization(entity):
                    analyzer = OrganizationAnalyzer()
                    result = analyzer.analyze(entity)
                    analyzer_name = "Organization Analyzer"
                else:
                    # Default to person
                    analyzer = PersonAnalyzer()
                    result = analyzer.analyze(entity)
                    analyzer_name = "Person Analyzer"
            
            # Store result
            self.current_results = result
            result['entity'] = entity
            result['entity_type'] = entity_type.value if entity_type else 'unknown'
            result['analyzer'] = analyzer_name
            result['timestamp'] = datetime.now().isoformat()
            
            # Add to relationship analyzer
            self.relationship_analyzer.add_entity(entity, result['entity_type'], result)
            
            # Add to history
            self.analysis_history.append(result)
            
            # Play completion sound
            self.play_completion_sound()
            
            # Update UI in main thread
            self.root.after(0, self.display_results, result)
            self.root.after(0, self.update_status, f"Analysis complete: {entity}", '#6a9955')
            self.root.after(0, self.update_progress_label, f"Status: Analysis complete - {entity_type.value}", '#6a9955')
            
        except Exception as e:
            # Play error sound
            self.play_error_sound()
            
            error_msg = f"Error during analysis: {str(e)}"
            self.root.after(0, self.display_error, error_msg)
            self.root.after(0, self.update_status, f"Analysis failed: {str(e)}", '#f48771')
            self.root.after(0, self.update_progress_label, f"Status: Error - {str(e)[:50]}...", '#f48771')
        finally:
            self.root.after(0, self.analysis_complete)
    
    def display_results(self, result: Dict):
        """Display analysis results"""
        self.results_text.delete(1.0, tk.END)
        
        # Format and display results
        output = []
        output.append(f"{'='*80}\n")
        output.append(f"Analysis Results - {result.get('analyzer', 'Unknown')}\n")
        output.append(f"{'='*80}\n\n")
        output.append(f"Entity: {result.get('entity', 'N/A')}\n")
        output.append(f"Type: {result.get('entity_type', 'unknown').upper()}\n")
        output.append(f"Timestamp: {result.get('timestamp', 'N/A')}\n")
        output.append(f"\n{'-'*80}\n\n")
        
        # Format JSON-like output
        formatted = self.format_dict(result)
        output.append(formatted)
        
        # Insert into text widget
        self.results_text.insert(tk.END, ''.join(output))
        
        # Update graph if available
        if GRAPH_AVAILABLE:
            self.root.after(100, self.update_graph)
        
        # Update history
        self.update_history()
    
    def format_dict(self, d, indent=0, skip_keys=None):
        """Format dictionary for display"""
        if skip_keys is None:
            skip_keys = ['entity', 'entity_type', 'analyzer', 'timestamp']
        
        output = []
        indent_str = "  " * indent
        
        for key, value in d.items():
            if key in skip_keys:
                continue
            
            if isinstance(value, dict):
                output.append(f"{indent_str}{key}:\n")
                output.append(self.format_dict(value, indent + 1))
            elif isinstance(value, list):
                output.append(f"{indent_str}{key}:\n")
                if not value:
                    output.append(f"{indent_str}  (empty)\n")
                else:
                    for item in value:
                        if isinstance(item, dict):
                            output.append(self.format_dict(item, indent + 1, skip_keys=[]))
                        else:
                            output.append(f"{indent_str}  - {item}\n")
            elif value is None:
                output.append(f"{indent_str}{key}: None\n")
            else:
                output.append(f"{indent_str}{key}: {value}\n")
        
        return ''.join(output)
    
    def display_error(self, error_msg: str):
        """Display error message"""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"ERROR: {error_msg}\n", 'error')
    
    def build_current_analysis_graph(self):
        """Build graph from current analysis results only (not history)"""
        if not self.current_results:
            return {'nodes': [], 'edges': []}
        
        nodes = []
        edges = []
        entity = self.current_results.get('entity', '')
        entity_type = self.current_results.get('entity_type', 'unknown')
        
        # Add main entity node
        nodes.append({'id': entity, 'label': entity, 'type': entity_type})
        
        # Build relationships from current analysis based on entity type
        if entity_type == 'domain':
            # Add subdomains
            subdomains = self.current_results.get('subdomains', [])
            if subdomains and isinstance(subdomains, list):
                for subdomain in subdomains:
                    if subdomain and isinstance(subdomain, str):
                        nodes.append({'id': subdomain, 'label': subdomain, 'type': 'domain'})
                        edges.append({'source': entity, 'target': subdomain, 'type': 'subdomain'})
            
            # Add DNS records (A, AAAA, MX, NS)
            dns_records = self.current_results.get('dns_records', {})
            if dns_records and isinstance(dns_records, dict):
                # IP addresses from A and AAAA records
                for record_type in ['A', 'AAAA']:
                    records = dns_records.get(record_type, [])
                    if records and isinstance(records, list):
                        for ip in records:
                            if ip and isinstance(ip, str):
                                if not any(n['id'] == ip for n in nodes):
                                    nodes.append({'id': ip, 'label': ip, 'type': 'ip'})
                                edges.append({'source': entity, 'target': ip, 'type': f'resolves_to ({record_type})'})
                
                # Name servers
                ns_records = dns_records.get('NS', [])
                if ns_records and isinstance(ns_records, list):
                    for ns in ns_records:
                        if ns and isinstance(ns, str):
                            ns_clean = ns.rstrip('.')
                            if not any(n['id'] == ns_clean for n in nodes):
                                nodes.append({'id': ns_clean, 'label': ns_clean, 'type': 'domain'})
                            edges.append({'source': entity, 'target': ns_clean, 'type': 'name_server'})
                
                # MX records (mail servers)
                mx_records = dns_records.get('MX', [])
                if mx_records and isinstance(mx_records, list):
                    for mx in mx_records:
                        if mx and isinstance(mx, str):
                            mx_clean = mx.rstrip('.').split()[1] if ' ' in mx else mx.rstrip('.')
                            if not any(n['id'] == mx_clean for n in nodes):
                                nodes.append({'id': mx_clean, 'label': mx_clean, 'type': 'domain'})
                            edges.append({'source': entity, 'target': mx_clean, 'type': 'mail_server'})
            
            # Add registrant emails
            registrant = self.current_results.get('registrant_details', {})
            if registrant and isinstance(registrant, dict):
                emails = registrant.get('emails', [])
                if emails and isinstance(emails, list):
                    for email in emails:
                        if email and isinstance(email, str):
                            if not any(n['id'] == email for n in nodes):
                                nodes.append({'id': email, 'label': email, 'type': 'email'})
                            edges.append({'source': entity, 'target': email, 'type': 'registrant_email'})
        
        elif entity_type == 'email':
            # Extract domain from email
            domain = entity.split('@')[1] if '@' in entity else None
            if domain:
                if not any(n['id'] == domain for n in nodes):
                    nodes.append({'id': domain, 'label': domain, 'type': 'domain'})
                edges.append({'source': entity, 'target': domain, 'type': 'email_domain'})
        
        elif entity_type == 'ip':
            # Reverse DNS
            reverse_dns = self.current_results.get('reverse_dns')
            if reverse_dns:
                if not any(n['id'] == reverse_dns for n in nodes):
                    nodes.append({'id': reverse_dns, 'label': reverse_dns, 'type': 'domain'})
                edges.append({'source': entity, 'target': reverse_dns, 'type': 'reverse_dns'})
            
            # ISP/Organization
            isp = self.current_results.get('isp')
            if isp:
                if not any(n['id'] == isp for n in nodes):
                    nodes.append({'id': isp, 'label': isp, 'type': 'organization'})
                edges.append({'source': entity, 'target': isp, 'type': 'isp'})
        
        return {'nodes': nodes, 'edges': edges}
    
    def update_graph(self):
        """Update relationship graph showing current analysis with all connections"""
        if not GRAPH_AVAILABLE:
            return
        
        try:
            self.ax.clear()
            
            # Use current analysis graph (not accumulated history)
            graph_data = self.build_current_analysis_graph()
            
            # Fallback to relationship analyzer if no current results
            if not graph_data['nodes'] and self.relationship_analyzer:
                graph_data = self.relationship_analyzer.get_relationship_graph()
            
            if not graph_data['nodes']:
                self.ax.text(0.5, 0.5, 'No relationships to display\nAnalyze an entity to see connections', 
                           ha='center', va='center', fontsize=14, color='white',
                           transform=self.ax.transAxes)
                self.canvas.draw()
                return
            
            # Create networkx graph (use DiGraph for directed relationships if needed)
            G = nx.Graph()
            
            # Add nodes
            node_colors = {
                'domain': '#4ec9b0',
                'email': '#9cdcfe',
                'ip': '#ce9178',
                'person': '#dcdcaa',
                'organization': '#569cd6',
                'url': '#c586c0',
                'ioc': '#f48771',
                'mobile': '#6a9955'
            }
            
            nodes = graph_data['nodes']
            node_list = []
            color_list = []
            node_labels = {}
            
            for node in nodes:
                node_id = node['id']
                node_label = node.get('label', node_id)
                # Truncate long labels for display
                display_label = node_label[:20] + '...' if len(node_label) > 20 else node_label
                G.add_node(node_id, label=node_label, type=node.get('type', 'unknown'))
                node_list.append(node_id)
                color_list.append(node_colors.get(node.get('type', 'unknown'), '#888888'))
                node_labels[node_id] = display_label
            
            # Add edges with relationship types
            edge_types = {}
            for edge in graph_data['edges']:
                source = edge.get('source')
                target = edge.get('target')
                rel_type = edge.get('type', 'related')
                if source and target and source in node_list and target in node_list:
                    G.add_edge(source, target, relationship=rel_type)
                    edge_types[(source, target)] = rel_type
            
            if not node_list:
                self.ax.text(0.5, 0.5, 'No nodes to display', 
                           ha='center', va='center', fontsize=14, color='white',
                           transform=self.ax.transAxes)
                self.canvas.draw()
                return
            
            # Improved layout with better spacing
            try:
                if len(node_list) == 1:
                    pos = {node_list[0]: (0, 0)}
                elif len(node_list) == 2:
                    pos = {node_list[0]: (-1, 0), node_list[1]: (1, 0)}
                else:
                    # Use spring layout with better parameters for proper connections
                    pos = nx.spring_layout(G, k=3, iterations=100, seed=42)
                    # If spring layout fails, use circular as fallback
                    if not pos:
                        pos = nx.circular_layout(G)
            except Exception:
                pos = nx.circular_layout(G) if len(node_list) > 2 else {node_list[0]: (0, 0)}
            
            # Draw nodes with better visibility
            nx.draw_networkx_nodes(G, pos, nodelist=node_list, node_color=color_list,
                                 node_size=1500, alpha=0.9, ax=self.ax, linewidths=2, 
                                 edgecolors='white')
            
            # Draw edges with better visibility and different styles for connection types
            edge_styles = {
                'owns': '-', 'related_to': '--', 'contains': '-.',
                'connects_to': ':', 'associated_with': '-'
            }
            
            # Group edges by type for better visualization
            for (source, target), rel_type in edge_types.items():
                style = edge_styles.get(rel_type, '-')
                nx.draw_networkx_edges(G, pos, edgelist=[(source, target)], 
                                     alpha=0.7, edge_color='#888888', width=2, 
                                     style=style, ax=self.ax)
            
            # Draw labels with better positioning
            nx.draw_networkx_labels(G, pos, node_labels, font_size=9, 
                                  font_color='white', font_weight='bold', ax=self.ax)
            
            # Draw edge labels for relationship types
            if edge_types:
                nx.draw_networkx_edge_labels(G, pos, edge_types, 
                                            font_size=7, font_color='#ffff00', 
                                            bbox=dict(boxstyle='round,pad=0.3', 
                                                    facecolor='#2b2b2b', 
                                                    edgecolor='#ffff00', 
                                                    alpha=0.8),
                                            ax=self.ax)
            
            # Set background
            self.ax.set_facecolor('#2b2b2b')
            self.ax.axis('off')
            self.fig.patch.set_facecolor('#2b2b2b')
            self.canvas.draw()
            
        except Exception as e:
            print(f"Error updating graph: {e}")
            import traceback
            traceback.print_exc()
    
    def reset_graph_view(self):
        """Reset graph zoom and pan to default view"""
        if not GRAPH_AVAILABLE:
            return
        try:
            # Reset axes limits to auto
            self.ax.relim()
            self.ax.autoscale()
            self.canvas.draw()
        except Exception as e:
            print(f"Error resetting graph view: {e}")
    
    def save_graph(self):
        """Save graph to file with proper connections"""
        if not GRAPH_AVAILABLE:
            messagebox.showwarning("Warning", "Graph visualization not available")
            return
        
        # Update graph first to ensure latest connections
        self.update_graph()
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[
                ("PNG files", "*.png"), 
                ("PDF files", "*.pdf"), 
                ("SVG files", "*.svg"),
                ("All files", "*.*")
            ]
        )
        if filename:
            try:
                # Create a high-quality version for export
                export_fig = plt.figure(figsize=(16, 12), facecolor='white')
                export_ax = export_fig.add_subplot(111)
                
                # Use current analysis graph (not accumulated history)
                graph_data = self.build_current_analysis_graph()
                
                # Fallback to relationship analyzer if no current results
                if not graph_data['nodes'] and self.relationship_analyzer:
                    graph_data = self.relationship_analyzer.get_relationship_graph()
                
                if not graph_data['nodes']:
                    messagebox.showwarning("Warning", "No graph data to save")
                    plt.close(export_fig)
                    return
                
                # Recreate graph for export with better quality
                G = nx.Graph()
                node_colors = {
                    'domain': '#4ec9b0', 'email': '#9cdcfe', 'ip': '#ce9178',
                    'person': '#dcdcaa', 'organization': '#569cd6', 'url': '#c586c0',
                    'ioc': '#f48771', 'mobile': '#6a9955'
                }
                
                nodes = graph_data['nodes']
                node_list = []
                color_list = []
                node_labels = {}
                
                for node in nodes:
                    node_id = node['id']
                    node_label = node.get('label', node_id)
                    G.add_node(node_id, label=node_label, type=node.get('type', 'unknown'))
                    node_list.append(node_id)
                    color_list.append(node_colors.get(node.get('type', 'unknown'), '#888888'))
                    node_labels[node_id] = node_label
                
                edge_types = {}
                for edge in graph_data['edges']:
                    source = edge.get('source')
                    target = edge.get('target')
                    rel_type = edge.get('type', 'related')
                    if source and target:
                        G.add_edge(source, target, relationship=rel_type)
                        edge_types[(source, target)] = rel_type
                
                # Layout
                if len(node_list) == 1:
                    pos = {node_list[0]: (0, 0)}
                elif len(node_list) == 2:
                    pos = {node_list[0]: (-1, 0), node_list[1]: (1, 0)}
                else:
                    try:
                        pos = nx.spring_layout(G, k=3, iterations=150, seed=42)
                    except:
                        pos = nx.circular_layout(G)
                
                # Draw with better quality for export
                nx.draw_networkx_nodes(G, pos, nodelist=node_list, node_color=color_list,
                                     node_size=2000, alpha=0.9, ax=export_ax, 
                                     linewidths=3, edgecolors='black')
                
                for (source, target), rel_type in edge_types.items():
                    nx.draw_networkx_edges(G, pos, edgelist=[(source, target)], 
                                         alpha=0.8, edge_color='gray', width=3, ax=export_ax)
                
                nx.draw_networkx_labels(G, pos, node_labels, font_size=10, 
                                      font_color='black', font_weight='bold', ax=export_ax)
                
                if edge_types:
                    nx.draw_networkx_edge_labels(G, pos, edge_types, 
                                                font_size=8, font_color='red', 
                                                bbox=dict(boxstyle='round,pad=0.5', 
                                                        facecolor='white', 
                                                        edgecolor='black', 
                                                        alpha=0.9),
                                                ax=export_ax)
                
                export_ax.set_facecolor('white')
                export_ax.axis('off')
                
                # Save with high DPI
                export_fig.savefig(filename, facecolor='white', dpi=300, 
                                 bbox_inches='tight', pad_inches=0.2)
                plt.close(export_fig)
                
                messagebox.showinfo("Success", f"Graph saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save graph: {str(e)}")
                import traceback
                traceback.print_exc()
    
    def update_history(self):
        """Update history display"""
        self.history_text.delete(1.0, tk.END)
        
        if not self.analysis_history:
            self.history_text.insert(tk.END, "No analysis history yet.\n")
            return
        
        for i, result in enumerate(reversed(self.analysis_history[-20:]), 1):  # Show last 20
            timestamp = result.get('timestamp', 'Unknown')
            entity = result.get('entity', 'Unknown')
            entity_type = result.get('entity_type', 'unknown')
            analyzer = result.get('analyzer', 'Unknown')
            
            self.history_text.insert(tk.END, f"{i}. [{timestamp}] {entity} ({entity_type}) - {analyzer}\n")
    
    def update_placeholder(self, *args):
        """Update placeholder text based on selected entity type"""
        if self.entry_has_placeholder:
            selected_type = self.selected_entity_type.get()
            new_placeholder = self.placeholder_texts.get(selected_type, self.placeholder_texts["auto"])
            
            # Only update if currently showing placeholder
            current_text = self.input_entry.get()
            if current_text == self.placeholder_text:
                self.input_entry.delete(0, tk.END)
                self.input_entry.insert(0, new_placeholder)
                self.placeholder_text = new_placeholder
    
    def on_entry_key(self, event):
        """Handle key press - ensure placeholder is cleared"""
        if self.entry_has_placeholder:
            self.input_entry.delete(0, tk.END)
            self.input_entry.config(fg='#ffffff')
            self.entry_has_placeholder = False
            # Re-insert the typed character
            self.input_entry.insert(tk.INSERT, event.char if event.char else '')
            return 'break'
    
    def on_entry_focus_in(self, event):
        """Handle entry focus in - remove placeholder"""
        if self.entry_has_placeholder:
            self.input_entry.delete(0, tk.END)
            self.input_entry.config(fg='#ffffff')
            self.entry_has_placeholder = False
    
    def on_entry_focus_out(self, event):
        """Handle entry focus out - restore placeholder if empty"""
        current_text = self.input_entry.get().strip()
        if not current_text:
            # Update placeholder based on current selection
            selected_type = self.selected_entity_type.get()
            self.placeholder_text = self.placeholder_texts.get(selected_type, self.placeholder_texts["auto"])
            self.input_entry.insert(0, self.placeholder_text)
            self.input_entry.config(fg='#888888')
            self.entry_has_placeholder = True
    
    def clear_input(self):
        """Clear input field"""
        self.input_entry.delete(0, tk.END)
        # Get current placeholder based on selected type
        selected_type = self.selected_entity_type.get()
        self.placeholder_text = self.placeholder_texts.get(selected_type, self.placeholder_texts["auto"])
        self.input_entry.insert(0, self.placeholder_text)
        self.input_entry.config(fg='#888888', state='normal')
        self.entry_has_placeholder = True
        self.results_text.delete(1.0, tk.END)
        self.current_results = None
        self.status_label.config(text="Ready - Select entity type above and enter target", fg='#6a9955')
        self.progress_label.config(text="Status: Ready", fg='#6a9955')
        self.progress.stop()
        self.input_entry.focus()
    
    def analysis_complete(self):
        """Called when analysis completes"""
        self.progress.stop()
        self.analyze_button.config(state='normal')
        self.clear_button.config(state='normal')
        self.input_entry.config(state='normal')
    
    def update_status(self, message: str, color='#6a9955'):
        """Update status label"""
        self.status_label.config(text=message, fg=color)
    
    def update_progress_label(self, message: str, color='#6a9955'):
        """Update progress label"""
        self.progress_label.config(text=message, fg=color)
    
    def export_results(self):
        """Export results to JSON"""
        if not self.current_results:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.current_results, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def export_report(self):
        """Export formatted report to TXT"""
        if not self.current_results:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("OSINT Footprint Gathering Report\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(f"Entity: {self.current_results.get('entity', 'N/A')}\n")
                    f.write(f"Type: {self.current_results.get('entity_type', 'unknown')}\n")
                    f.write(f"Analyzer: {self.current_results.get('analyzer', 'Unknown')}\n")
                    f.write(f"Timestamp: {self.current_results.get('timestamp', 'N/A')}\n")
                    f.write("\n" + "-" * 80 + "\n\n")
                    f.write(self.format_dict(self.current_results, skip_keys=[]))
                messagebox.showinfo("Success", f"Report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def export_pdf_report(self):
        """Export comprehensive PDF report (results only, no graph)"""
        if not self.current_results:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Image
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
        except ImportError:
            messagebox.showerror("Error", 
                "PDF export requires reportlab library.\n"
                "Install it using: pip install reportlab")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if not filename:
            return
        
        try:
            # Create PDF document
            doc = SimpleDocTemplate(filename, pagesize=letter,
                                  rightMargin=72, leftMargin=72,
                                  topMargin=72, bottomMargin=18)
            
            # Container for PDF elements
            story = []
            
            # Styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a1a'),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#0078d4'),
                spaceAfter=12,
                spaceBefore=12
            )
            
            # Title
            story.append(Paragraph("OSINT Footprint Gathering Report", title_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Metadata table
            metadata_data = [
                ['Entity:', self.current_results.get('entity', 'N/A')],
                ['Type:', self.current_results.get('entity_type', 'unknown').upper()],
                ['Analyzer:', self.current_results.get('analyzer', 'Unknown')],
                ['Timestamp:', self.current_results.get('timestamp', 'N/A')]
            ]
            metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
            metadata_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#0078d4')),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#f0f0f0')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(metadata_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Analysis Results
            story.append(Paragraph("Analysis Results", heading_style))
            
            # Format results for PDF
            results_text = self._format_results_for_pdf(self.current_results)
            story.append(Paragraph(results_text, styles['Normal']))
            
            # Note: Graph is not included in export - view in Graph tab for visualization
            
            # Build PDF
            doc.build(story)
            messagebox.showinfo("Success", f"PDF report exported to {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export PDF: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def _format_results_for_pdf(self, data, indent=0):
        """Format results data for PDF"""
        output = []
        indent_str = "&nbsp;" * (indent * 4)
        
        for key, value in data.items():
            if key in ['entity', 'entity_type', 'analyzer', 'timestamp']:
                continue
            
            key_display = key.replace('_', ' ').title()
            
            if isinstance(value, dict):
                output.append(f"<b>{indent_str}{key_display}:</b><br/>")
                output.append(self._format_results_for_pdf(value, indent + 1))
            elif isinstance(value, list):
                output.append(f"<b>{indent_str}{key_display}:</b><br/>")
                if not value:
                    output.append(f"{indent_str}&nbsp;&nbsp;(empty)<br/>")
                else:
                    for item in value:
                        if isinstance(item, dict):
                            output.append(self._format_results_for_pdf(item, indent + 1))
                        else:
                            output.append(f"{indent_str}&nbsp;&nbsp;• {item}<br/>")
            elif value is None:
                output.append(f"{indent_str}{key_display}: None<br/>")
            else:
                # Escape HTML special characters
                value_str = str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                output.append(f"{indent_str}{key_display}: {value_str}<br/>")
        
        return ''.join(output)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = ModernOSINTGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
