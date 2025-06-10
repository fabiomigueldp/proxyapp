#!/usr/bin/env python3
"""
Advanced Auditing Proxy - Enhanced Version
Based on the original realfxbook_enhanced_en.py

Implemented improvements:
- Display of all possible HTTPFlow information
- Reorganized interface with tabs for better organization
- Advanced visualization and analysis features
- Enhanced content formatting
- Detailed connection and TLS information
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import gzip
import json
import queue
import re
import subprocess
import sys
import threading
import time
import zlib
from typing import Any, Dict, Optional, Tuple
from urllib.parse import unquote_plus, quote_plus
import hashlib
import datetime

from mitmproxy import http, ctx
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import tkinter.font as tkFont

class Codec:
    """Class for encoding and decoding HTTP content"""
    ENCODING_TYPES = ["AUTO", "GZIP", "DEFLATE", "BASE64", "URL_ENCODED", "TEXT"]

    @staticmethod
    def auto_decode(body_bytes: bytes, headers: Dict[str, str] = None) -> Tuple[str, str, bool]:
        """Automatically decodes content based on headers and heuristics"""
        if not body_bytes:
            return "", "TEXT", True

        content_encoding = (headers or {}).get("content-encoding", "").lower()
        if "gzip" in content_encoding:
            try:
                decoded = gzip.decompress(body_bytes).decode("utf-8", "ignore")
                return decoded, "GZIP", True
            except (IOError, zlib.error):
                pass
        elif "deflate" in content_encoding:
            try:
                decoded = zlib.decompress(body_bytes).decode("utf-8", "ignore")
                return decoded, "DEFLATE", True
            except zlib.error:
                pass

        try:
            decoded_b64 = base64.b64decode(body_bytes, validate=True)
            if all(c in range(32, 127) or c in [9, 10, 13] for c in decoded_b64):
                return decoded_b64.decode("utf-8", "ignore"), "BASE64", True
        except (ValueError, TypeError):
            pass

        try:
            decoded_url = unquote_plus(body_bytes.decode("utf-8", "ignore"))
            if decoded_url != body_bytes.decode("utf-8", "ignore"):
                return decoded_url, "URL_ENCODED", True
        except Exception:
            pass

        try:
            return body_bytes.decode("utf-8"), "TEXT", True
        except UnicodeDecodeError:
            return "<non-editable binary data>", "BINARY", False

    @staticmethod
    def encode(text: str, encoding_type: str) -> bytes:
        """Encodes text into the specified format"""
        if encoding_type == "GZIP":
            return gzip.compress(text.encode("utf-8"))
        if encoding_type == "DEFLATE":
            return zlib.compress(text.encode("utf-8"))
        if encoding_type == "BASE64":
            return base64.b64encode(text.encode("utf-8"))
        if encoding_type == "URL_ENCODED":
            return quote_plus(text).encode("utf-8")
        if encoding_type == "TEXT":
            return text.encode("utf-8")
        return text.encode("utf-8", "ignore")

    @staticmethod
    def format_content(content: str, content_type: str = "") -> str:
        """Formats content based on MIME type"""
        if not content:
            return content
            
        content_type = content_type.lower()
        
        if "json" in content_type or content.strip().startswith(("{", "[")):
            try:
                parsed = json.loads(content)
                return json.dumps(parsed, indent=2, ensure_ascii=False)
            except:
                pass
        
        if "xml" in content_type or "html" in content_type:
            import re
            content = re.sub(r'><', '>\n<', content)
            
        return content

class FlowAnalyzer:
    """Class for advanced analysis of HTTP flows"""
    
    @staticmethod
    def calculate_hash(content: bytes) -> str:
        """Calculates MD5 hash of the content"""
        if not content:
            return "N/A"
        return hashlib.md5(content).hexdigest()
    
    @staticmethod
    def analyze_timing(flow_data: Dict[str, Any]) -> Dict[str, str]:
        """Analyzes flow timing information"""
        timing_info = {}
        
        if "timestamp_start" in flow_data:
            timing_info["Start"] = flow_data["timestamp_start"]
        
        if "duration" in flow_data:
            timing_info["Duration"] = flow_data["duration"]
            
        return timing_info
    
    @staticmethod
    def get_content_info(content: bytes, headers: Dict[str, str]) -> Dict[str, str]:
        """Gets information about the content"""
        info = {}
        
        if content:
            info["Size"] = f"{len(content)} bytes"
            info["MD5 Hash"] = FlowAnalyzer.calculate_hash(content)
            
            content_type = headers.get("content-type", "")
            if content_type:
                info["Content Type"] = content_type
                
        return info

PATTERN = re.compile(r"upload1", flags=re.I)

class AuditorAddon:
    """mitmproxy addon to intercept and process HTTP flows"""

    def __init__(
        self,
        gui_q: queue.Queue[Dict[str, Any]],
        mod_q: queue.Queue[Dict[str, Any]],
        mode_q: queue.Queue[str],
    ) -> None:
        self.gui_q = gui_q
        self.mod_q = mod_q
        self.mode_q = mode_q
        self.mode = "interception"
        self.first_post_seen = False

    def _update_mode(self) -> None:
        """Fetches the latest mode from the queue if available"""
        while True:
            try:
                new_mode = self.mode_q.get_nowait()
                if new_mode in ("inspection", "interception"):
                    self.mode = new_mode
            except queue.Empty:
                break

    def response(self, flow: http.HTTPFlow) -> None:
        """Processes intercepted HTTP responses"""
        self._update_mode()
        if not PATTERN.search(flow.request.pretty_url):
            return

        is_initial_post = False
        if flow.request.method.upper() == "POST" and not self.first_post_seen:
            self.first_post_seen = True
            is_initial_post = True
        
        ctx.log.info(f"[Auditor] Intercepted: {flow.request.method} {flow.request.pretty_url}")

        flow_data = self._extract_flow_data(flow, is_initial_post)
        self.gui_q.put(flow_data)

        if self.mode == "inspection":
            return

        flow.reply.take()
        while True:
            self._update_mode()
            try:
                mod_data = self.mod_q.get(timeout=0.1)
                if mod_data["id"] == flow.id:
                    if mod_data.get("req_body_modified") is not None:
                        flow.request.content = mod_data["req_body_modified"]
                    if mod_data.get("resp_body_modified") is not None:
                        flow.response.content = mod_data["resp_body_modified"]
                    break
            except queue.Empty:
                continue
            except Exception:
                break
        flow.reply()

    def _extract_flow_data(self, flow: http.HTTPFlow, is_initial_post: bool) -> Dict[str, Any]:
        """Extracts all possible information from the HTTP flow"""
        
        flow_data = {
            "id": flow.id,
            "is_initial_post": is_initial_post,
            "type": flow.type,
            "mode": self.mode,
            
            "timestamp_created": getattr(flow, 'timestamp_created', time.time()),
            "timestamp_start": time.strftime("%H:%M:%S", time.localtime(flow.request.timestamp_start)),
            "timestamp_start_raw": flow.request.timestamp_start,
            
            "intercepted": getattr(flow, 'intercepted', False),
            "marked": getattr(flow, 'marked', False),
            "is_replay": getattr(flow, 'is_replay', None),
            "live": getattr(flow, 'live', True),
            "modified": getattr(flow, 'modified', False),
            "killable": getattr(flow, 'killable', False),
            
            "metadata": getattr(flow, 'metadata', {}),
            "comment": getattr(flow, 'comment', ''),
        }
        
        if flow.client_conn and flow.client_conn.peername:
            flow_data["client_ip"] = str(flow.client_conn.peername[0])
            flow_data["client_port"] = str(flow.client_conn.peername[1])
        else:
            flow_data["client_ip"] = "N/A"
            flow_data["client_port"] = "N/A"
            
        if flow.server_conn and flow.server_conn.ip_address:
            flow_data["server_ip"] = str(flow.server_conn.ip_address[0])
            flow_data["server_port"] = str(flow.server_conn.ip_address[1])
        else:
            flow_data["server_ip"] = "N/A"
            flow_data["server_port"] = "N/A"
        
        if flow.server_conn and flow.server_conn.tls_established:
            flow_data["tls_info"] = f"{flow.server_conn.tls_version}, {flow.server_conn.cipher}"
            flow_data["tls_version"] = getattr(flow.server_conn, 'tls_version', 'N/A')
            flow_data["tls_cipher"] = getattr(flow.server_conn, 'cipher', 'N/A')
        else:
            flow_data["tls_info"] = "Non-TLS"
            flow_data["tls_version"] = "N/A"
            flow_data["tls_cipher"] = "N/A"
        
        flow_data.update({
            "req_method": flow.request.method,
            "req_url": flow.request.pretty_url,
            "req_headers": dict(flow.request.headers),
            "req_body_bytes": flow.request.content or b'',
            "req_http_version": flow.request.http_version,
            "req_is_http10": flow.request.is_http10,
            "req_is_http11": flow.request.is_http11,
            "req_is_http2": flow.request.is_http2,
            "req_is_http3": flow.request.is_http3,
            "req_trailers": dict(flow.request.trailers) if flow.request.trailers else {},
            "req_stream": getattr(flow.request, 'stream', False),
        })
        
        if flow.response:
            flow_data.update({
                "resp_status": f"{flow.response.status_code} {flow.response.reason}",
                "resp_status_code": flow.response.status_code,
                "resp_reason": flow.response.reason,
                "resp_headers": dict(flow.response.headers),
                "resp_body_bytes": flow.response.content or b'',
                "resp_http_version": flow.response.http_version,
                "resp_is_http10": flow.response.is_http10,
                "resp_is_http11": flow.response.is_http11,
                "resp_is_http2": flow.response.is_http2,
                "resp_is_http3": flow.response.is_http3,
                "resp_trailers": dict(flow.response.trailers) if flow.response.trailers else {},
                "resp_stream": getattr(flow.response, 'stream', False),
                "duration": f"{flow.response.timestamp_end - flow.request.timestamp_start:.3f}s",
                "timestamp_end": time.strftime("%H:%M:%S", time.localtime(flow.response.timestamp_end)),
                "timestamp_end_raw": flow.response.timestamp_end,
            })
        else:
            flow_data.update({
                "resp_status": "N/A",
                "resp_status_code": 0,
                "resp_reason": "N/A",
                "resp_headers": {},
                "resp_body_bytes": b'',
                "resp_http_version": "N/A",
                "resp_is_http10": False,
                "resp_is_http11": False,
                "resp_is_http2": False,
                "resp_is_http3": False,
                "resp_trailers": {},
                "resp_stream": False,
                "duration": "N/A",
                "timestamp_end": "N/A",
                "timestamp_end_raw": 0,
            })
        
        if flow.error:
            flow_data["error_msg"] = str(flow.error.msg)
            flow_data["error_timestamp"] = time.strftime("%H:%M:%S", time.localtime(flow.error.timestamp))
        else:
            flow_data["error_msg"] = None
            flow_data["error_timestamp"] = None
        
        if flow.websocket:
            flow_data["websocket_messages"] = len(flow.websocket.messages)
            flow_data["websocket_closed"] = flow.websocket.closed
        else:
            flow_data["websocket_messages"] = 0
            flow_data["websocket_closed"] = False
        
        return flow_data

def run_proxy(
    gui_q: queue.Queue,
    mod_q: queue.Queue,
    mode_q: queue.Queue,
    port: int,
    verbose: bool,
) -> None:
    """Runs the mitmproxy proxy in a separate thread"""
    async def main_coro():
        opts = Options(listen_host="127.0.0.1", listen_port=port, ssl_insecure=True)
        master = DumpMaster(opts, with_termlog=verbose, with_dumper=False)
        master.addons.add(AuditorAddon(gui_q, mod_q, mode_q))

        try:
            await master.run()
        except asyncio.CancelledError:
            pass
        finally:
            master.shutdown()

    try:
        asyncio.run(main_coro())
    except KeyboardInterrupt:
        pass

class AdvancedProxyApp(tk.Tk):
    """Advanced GUI application for the auditing proxy"""
    
    def __init__(self, port: int, verbose: bool):
        super().__init__()
        self.port = port
        self.verbose = verbose
        self.title(f"Advanced Auditing Proxy – Port {port}")
        self.geometry("1400x900")
        self.minsize(1200, 800)

        self.flows_data: Dict[str, Dict[str, Any]] = {}
        self.codec_info: Dict[str, Dict[str, str]] = {}

        self.gui_q: queue.Queue[Dict[str, Any]] = queue.Queue()
        self.mod_q: queue.Queue[Dict[str, Any]] = queue.Queue()
        self.mode_q: queue.Queue[str] = queue.Queue()

        self.setup_styles()
        
        self.create_widgets()
        
        self.start_proxy_thread()
        self.poll_gui_queue()
        self.update_status()

    def setup_styles(self):
        """Configures the interface styles"""
        self.style = ttk.Style()
        
        self.mono_font = tkFont.Font(family="Consolas", size=10)
        self.mono_font_small = tkFont.Font(family="Consolas", size=9)

    def create_widgets(self):
        """Creates all the interface widgets"""
        main_pane = ttk.PanedWindow(self, orient="vertical")
        main_pane.pack(fill="both", expand=True, padx=5, pady=5)

        self.create_flows_panel(main_pane)
        
        self.create_details_panel(main_pane)
        
        self.create_status_bar()
        
        self.create_action_buttons()

    def create_flows_panel(self, parent):
        """Creates the flows list panel"""
        flows_frame = ttk.LabelFrame(parent, text="Intercepted Flows", padding=5)
        parent.add(flows_frame, weight=1)

        cols = ("id", "time", "method", "status", "url", "size", "duration")
        self.tree = ttk.Treeview(flows_frame, columns=cols, show="headings", height=8)
        
        self.tree.heading("id", text="ID")
        self.tree.column("id", width=80, stretch=False)
        self.tree.heading("time", text="Time")
        self.tree.column("time", width=80, stretch=False)
        self.tree.heading("method", text="Method")
        self.tree.column("method", width=80, stretch=False)
        self.tree.heading("status", text="Status")
        self.tree.column("status", width=80, stretch=False)
        self.tree.heading("url", text="URL")
        self.tree.column("url", width=400)
        self.tree.heading("size", text="Size")
        self.tree.column("size", width=80, stretch=False)
        self.tree.heading("duration", text="Duration")
        self.tree.column("duration", width=80, stretch=False)
        
        tree_scroll = ttk.Scrollbar(flows_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")
        
        self.tree.bind("<<TreeviewSelect>>", self.on_flow_select)
        
        self.tree.tag_configure("initial_post", background="#ffe8a1")
        self.tree.tag_configure("error", background="#ffcccc")
        self.tree.tag_configure("websocket", background="#ccffcc")

    def create_details_panel(self, parent):
        """Creates the flow details panel"""
        details_frame = ttk.LabelFrame(parent, text="Selected Flow Details", padding=5)
        parent.add(details_frame, weight=3)
        
        self.notebook = ttk.Notebook(details_frame)
        self.notebook.pack(fill="both", expand=True)

        self.create_overview_tab()
        self.create_request_tab()
        self.create_response_tab()
        self.create_connection_tab()
        self.create_timing_tab()
        self.create_codec_tab()
        self.create_errors_tab()
        self.create_websocket_tab()

    def create_overview_tab(self):
        """Creates the overview tab"""
        overview_frame = ttk.Frame(self.notebook)
        self.notebook.add(overview_frame, text="📋 Overview")
        
        overview_pane = ttk.PanedWindow(overview_frame, orient="horizontal")
        overview_pane.pack(fill="both", expand=True, padx=5, pady=5)
        
        basic_frame = ttk.LabelFrame(overview_pane, text="Basic Information")
        overview_pane.add(basic_frame, weight=1)
        
        self.basic_info_text = scrolledtext.ScrolledText(
            basic_frame, wrap="word", font=self.mono_font_small, height=15
        )
        self.basic_info_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        flags_frame = ttk.LabelFrame(overview_pane, text="Flags and Metadata")
        overview_pane.add(flags_frame, weight=1)
        
        self.flags_info_text = scrolledtext.ScrolledText(
            flags_frame, wrap="word", font=self.mono_font_small, height=15
        )
        self.flags_info_text.pack(fill="both", expand=True, padx=5, pady=5)

    def create_request_tab(self):
        """Creates the request tab"""
        request_frame = ttk.Frame(self.notebook)
        self.notebook.add(request_frame, text="📤 Request")
        
        req_pane = ttk.PanedWindow(request_frame, orient="vertical")
        req_pane.pack(fill="both", expand=True, padx=5, pady=5)
        
        req_headers_frame = ttk.LabelFrame(req_pane, text="Request Headers")
        req_pane.add(req_headers_frame, weight=1)
        
        self.req_headers_text = scrolledtext.ScrolledText(
            req_headers_frame, wrap="none", font=self.mono_font, height=8
        )
        self.req_headers_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        req_body_frame = ttk.LabelFrame(req_pane, text="Request Body")
        req_pane.add(req_body_frame, weight=2)
        
        self.req_body_text = scrolledtext.ScrolledText(
            req_body_frame, wrap="word", font=self.mono_font
        )
        self.req_body_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        req_info_frame = ttk.LabelFrame(req_pane, text="HTTP Information")
        req_pane.add(req_info_frame, weight=0)
        
        self.req_info_text = scrolledtext.ScrolledText(
            req_info_frame, wrap="word", font=self.mono_font_small, height=4
        )
        self.req_info_text.pack(fill="both", expand=True, padx=5, pady=5)

    def create_response_tab(self):
        """Creates the response tab"""
        response_frame = ttk.Frame(self.notebook)
        self.notebook.add(response_frame, text="📥 Response")
        
        resp_pane = ttk.PanedWindow(response_frame, orient="vertical")
        resp_pane.pack(fill="both", expand=True, padx=5, pady=5)
        
        resp_headers_frame = ttk.LabelFrame(resp_pane, text="Response Headers")
        resp_pane.add(resp_headers_frame, weight=1)
        
        self.resp_headers_text = scrolledtext.ScrolledText(
            resp_headers_frame, wrap="none", font=self.mono_font, height=8
        )
        self.resp_headers_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        resp_body_frame = ttk.LabelFrame(resp_pane, text="Response Body")
        resp_pane.add(resp_body_frame, weight=2)
        
        self.resp_body_text = scrolledtext.ScrolledText(
            resp_body_frame, wrap="word", font=self.mono_font
        )
        self.resp_body_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        resp_info_frame = ttk.LabelFrame(resp_pane, text="HTTP Information")
        resp_pane.add(resp_info_frame, weight=0)
        
        self.resp_info_text = scrolledtext.ScrolledText(
            resp_info_frame, wrap="word", font=self.mono_font_small, height=4
        )
        self.resp_info_text.pack(fill="both", expand=True, padx=5, pady=5)

    def create_connection_tab(self):
        """Creates the connection details tab"""
        connection_frame = ttk.Frame(self.notebook)
        self.notebook.add(connection_frame, text="🔗 Connection")
        
        conn_pane = ttk.PanedWindow(connection_frame, orient="horizontal")
        conn_pane.pack(fill="both", expand=True, padx=5, pady=5)
        
        client_frame = ttk.LabelFrame(conn_pane, text="Client Connection")
        conn_pane.add(client_frame, weight=1)
        
        self.client_info_text = scrolledtext.ScrolledText(
            client_frame, wrap="word", font=self.mono_font_small
        )
        self.client_info_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        server_frame = ttk.LabelFrame(conn_pane, text="Server Connection")
        conn_pane.add(server_frame, weight=1)
        
        self.server_info_text = scrolledtext.ScrolledText(
            server_frame, wrap="word", font=self.mono_font_small
        )
        self.server_info_text.pack(fill="both", expand=True, padx=5, pady=5)

    def create_timing_tab(self):
        """Creates the timing information tab"""
        timing_frame = ttk.Frame(self.notebook)
        self.notebook.add(timing_frame, text="⏱️ Timing")
        
        self.timing_text = scrolledtext.ScrolledText(
            timing_frame, wrap="word", font=self.mono_font
        )
        self.timing_text.pack(fill="both", expand=True, padx=5, pady=5)

    def create_codec_tab(self):
        """Creates the codec (editing) tab"""
        codec_frame = ttk.Frame(self.notebook)
        self.notebook.add(codec_frame, text="🔧 Codec/Edit")
        
        codec_pane = ttk.PanedWindow(codec_frame, orient="horizontal")
        codec_pane.pack(fill="both", expand=True, padx=5, pady=5)
        
        req_edit_frame = ttk.LabelFrame(codec_pane, text="Edit Request")
        codec_pane.add(req_edit_frame, weight=1)
        
        self.req_edit_text = scrolledtext.ScrolledText(
            req_edit_frame, wrap="word", font=self.mono_font
        )
        self.req_edit_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.req_codec_label = ttk.Label(req_edit_frame, text="Codec: N/A")
        self.req_codec_label.pack(anchor="w", padx=5, pady=2)
        
        resp_edit_frame = ttk.LabelFrame(codec_pane, text="Edit Response")
        codec_pane.add(resp_edit_frame, weight=1)
        
        self.resp_edit_text = scrolledtext.ScrolledText(
            resp_edit_frame, wrap="word", font=self.mono_font
        )
        self.resp_edit_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.resp_codec_label = ttk.Label(resp_edit_frame, text="Codec: N/A")
        self.resp_codec_label.pack(anchor="w", padx=5, pady=2)

    def create_errors_tab(self):
        """Creates the errors tab"""
        errors_frame = ttk.Frame(self.notebook)
        self.notebook.add(errors_frame, text="❌ Errors")
        
        self.errors_text = scrolledtext.ScrolledText(
            errors_frame, wrap="word", font=self.mono_font
        )
        self.errors_text.pack(fill="both", expand=True, padx=5, pady=5)

    def create_websocket_tab(self):
        """Creates the WebSocket tab"""
        websocket_frame = ttk.Frame(self.notebook)
        self.notebook.add(websocket_frame, text="🔌 WebSocket")
        
        self.websocket_text = scrolledtext.ScrolledText(
            websocket_frame, wrap="word", font=self.mono_font
        )
        self.websocket_text.pack(fill="both", expand=True, padx=5, pady=5)

    def create_status_bar(self):
        """Creates the status bar"""
        self.status_var = tk.StringVar()
        self.status_var.set("Proxy started. Waiting for connections...")
        
        status_bar = ttk.Label(
            self, textvariable=self.status_var, 
            relief="sunken", anchor="w", padding=5
        )
        status_bar.pack(side="bottom", fill="x")

    def create_action_buttons(self):
        """Creates the action buttons"""
        btn_frame = ttk.Frame(self)
        btn_frame.pack(side="bottom", fill="x", pady=5)
        
        self.send_mod_btn = ttk.Button(
            btn_frame, text="▶️ Send Modified",
            command=self.send_modified
        )
        self.send_mod_btn.pack(side="left", padx=5)

        self.send_orig_btn = ttk.Button(
            btn_frame, text="➡️ Send Original",
            command=self.send_unmodified
        )
        self.send_orig_btn.pack(side="left", padx=5)
        
        ttk.Button(
            btn_frame, text="📋 Copy as cURL", 
            command=self.copy_as_curl
        ).pack(side="left", padx=5)
        
        ttk.Button(
            btn_frame, text="💾 Export HAR", 
            command=self.export_har
        ).pack(side="left", padx=5)
        
        ttk.Button(
            btn_frame, text="🗑️ Clear Session",
            command=self.clear_session
        ).pack(side="right", padx=5)

        ttk.Button(
            btn_frame, text="⏸️ Pause Capture",
            command=self.toggle_capture
        ).pack(side="right", padx=5)

        self.mode_var = tk.StringVar(value="interception")
        ttk.Checkbutton(
            btn_frame,
            text="Inspection Mode",
            variable=self.mode_var,
            onvalue="inspection",
            offvalue="interception",
            command=self.toggle_mode,
        ).pack(side="right", padx=5)
        # initialize button states and inform proxy
        self.toggle_mode()

    def start_proxy_thread(self):
        """Starts the proxy in a separate thread"""
        self.proxy_thread = threading.Thread(
            target=run_proxy,
            args=(self.gui_q, self.mod_q, self.mode_q, self.port, self.verbose),
            daemon=True,
        )
        self.proxy_thread.start()

    def poll_gui_queue(self):
        """Polls the data queue from the proxy"""
        try:
            while not self.gui_q.empty():
                flow_data = self.gui_q.get_nowait()
                self.add_flow_to_tree(flow_data)
        finally:
            self.after(100, self.poll_gui_queue)

    def add_flow_to_tree(self, flow_data: Dict[str, Any]):
        """Adds a flow to the flow tree"""
        iid = flow_data["id"]
        self.flows_data[iid] = flow_data
        
        tags = []
        if flow_data["is_initial_post"]:
            tags.append("initial_post")
        if flow_data["error_msg"]:
            tags.append("error")
        if flow_data["websocket_messages"] > 0:
            tags.append("websocket")
        
        req_size = len(flow_data["req_body_bytes"])
        resp_size = len(flow_data["resp_body_bytes"])
        total_size = req_size + resp_size
        size_str = f"{total_size}B" if total_size < 1024 else f"{total_size/1024:.1f}KB"
        
        self.tree.insert(
            "", "end", iid=iid, tags=tags,
            values=(
                iid[:8],
                flow_data["timestamp_start"],
                flow_data["req_method"],
                flow_data["resp_status"],
                flow_data["req_url"][:60] + "..." if len(flow_data["req_url"]) > 60 else flow_data["req_url"],
                size_str,
                flow_data["duration"],
            ),
        )
        
        self.tree.yview_moveto(1)

    def on_flow_select(self, event=None):
        """Handles the selection of a flow"""
        selected_items = self.tree.selection()
        if not selected_items:
            return
            
        iid = selected_items[0]
        flow_data = self.flows_data.get(iid)
        if not flow_data:
            return
        
        self.clear_all_views()
        
        self.populate_overview_tab(flow_data)
        self.populate_request_tab(flow_data)
        self.populate_response_tab(flow_data)
        self.populate_connection_tab(flow_data)
        self.populate_timing_tab(flow_data)
        self.populate_codec_tab(flow_data, iid)
        self.populate_errors_tab(flow_data)
        self.populate_websocket_tab(flow_data)
        
        self.status_var.set(f"Selected flow: {iid[:8]} - {flow_data['req_method']} {flow_data['req_url']}")

    def clear_all_views(self):
        """Clears all views"""
        text_widgets = [
            self.basic_info_text, self.flags_info_text,
            self.req_headers_text, self.req_body_text, self.req_info_text,
            self.resp_headers_text, self.resp_body_text, self.resp_info_text,
            self.client_info_text, self.server_info_text,
            self.timing_text, self.req_edit_text, self.resp_edit_text,
            self.errors_text, self.websocket_text
        ]
        
        for widget in text_widgets:
            widget.config(state="normal")
            widget.delete("1.0", tk.END)

    def populate_overview_tab(self, flow_data: Dict[str, Any]):
        """Populates the overview tab"""
        basic_info = f"""Flow ID: {flow_data['id']}
Type: {flow_data['type']}
Mode: {flow_data['mode']}

=== REQUEST ===
Method: {flow_data['req_method']}
URL: {flow_data['req_url']}
HTTP Version: {flow_data['req_http_version']}

=== RESPONSE ===
Status: {flow_data['resp_status']}
HTTP Version: {flow_data['resp_http_version']}

=== TIMING ===
Created: {datetime.datetime.fromtimestamp(flow_data['timestamp_created']).strftime('%H:%M:%S')}
Start: {flow_data['timestamp_start']}
End: {flow_data['timestamp_end']}
Duration: {flow_data['duration']}

=== SIZES ===
Request: {len(flow_data['req_body_bytes'])} bytes
Response: {len(flow_data['resp_body_bytes'])} bytes
Total: {len(flow_data['req_body_bytes']) + len(flow_data['resp_body_bytes'])} bytes
"""
        
        self.basic_info_text.insert("1.0", basic_info)
        self.basic_info_text.config(state="disabled")
        
        flags_info = f"""=== FLOW FLAGS ===
Intercepted: {'Yes' if flow_data['intercepted'] else 'No'}
Marked: {'Yes' if flow_data['marked'] else 'No'}
Is Replay: {flow_data['is_replay'] or 'No'}
Live: {'Yes' if flow_data['live'] else 'No'}
Modified: {'Yes' if flow_data['modified'] else 'No'}
Killable: {'Yes' if flow_data['killable'] else 'No'}

=== METADATA ===
{json.dumps(flow_data['metadata'], indent=2) if flow_data['metadata'] else 'None'}

=== COMMENT ===
{flow_data['comment'] or 'None'}

=== HASHES ===
Request MD5 Hash: {FlowAnalyzer.calculate_hash(flow_data['req_body_bytes'])}
Response MD5 Hash: {FlowAnalyzer.calculate_hash(flow_data['resp_body_bytes'])}
"""
        
        self.flags_info_text.insert("1.0", flags_info)
        self.flags_info_text.config(state="disabled")

    def populate_request_tab(self, flow_data: Dict[str, Any]):
        """Populates the request tab"""
        headers_text = "\n".join(f"{k}: {v}" for k, v in flow_data["req_headers"].items())
        self.req_headers_text.insert("1.0", headers_text)
        
        req_decoded, req_type, req_editable = Codec.auto_decode(
            flow_data["req_body_bytes"], flow_data["req_headers"]
        )
        
        content_type = flow_data["req_headers"].get("content-type", "")
        formatted_content = Codec.format_content(req_decoded, content_type)
        
        self.req_body_text.insert("1.0", formatted_content)
        if not req_editable:
            self.req_body_text.config(state="disabled")
        
        http_info = f"""HTTP Version: {flow_data['req_http_version']}
HTTP/1.0: {'Yes' if flow_data['req_is_http10'] else 'No'}
HTTP/1.1: {'Yes' if flow_data['req_is_http11'] else 'No'}
HTTP/2: {'Yes' if flow_data['req_is_http2'] else 'No'}
HTTP/3: {'Yes' if flow_data['req_is_http3'] else 'No'}
Stream: {flow_data['req_stream']}
Trailers: {len(flow_data['req_trailers'])} items
Detected Codec: {req_type}
"""
        
        self.req_info_text.insert("1.0", http_info)
        self.req_info_text.config(state="disabled")

    def populate_response_tab(self, flow_data: Dict[str, Any]):
        """Populates the response tab"""
        headers_text = "\n".join(f"{k}: {v}" for k, v in flow_data["resp_headers"].items())
        self.resp_headers_text.insert("1.0", headers_text)
        
        resp_decoded, resp_type, resp_editable = Codec.auto_decode(
            flow_data["resp_body_bytes"], flow_data["resp_headers"]
        )
        
        content_type = flow_data["resp_headers"].get("content-type", "")
        formatted_content = Codec.format_content(resp_decoded, content_type)
        
        self.resp_body_text.insert("1.0", formatted_content)
        if not resp_editable:
            self.resp_body_text.config(state="disabled")
        
        http_info = f"""HTTP Version: {flow_data['resp_http_version']}
HTTP/1.0: {'Yes' if flow_data['resp_is_http10'] else 'No'}
HTTP/1.1: {'Yes' if flow_data['resp_is_http11'] else 'No'}
HTTP/2: {'Yes' if flow_data['resp_is_http2'] else 'No'}
HTTP/3: {'Yes' if flow_data['resp_is_http3'] else 'No'}
Stream: {flow_data['resp_stream']}
Trailers: {len(flow_data['resp_trailers'])} items
Detected Codec: {resp_type}
"""
        
        self.resp_info_text.insert("1.0", http_info)
        self.resp_info_text.config(state="disabled")

    def populate_connection_tab(self, flow_data: Dict[str, Any]):
        """Populates the connection tab"""
        client_info = f"""=== CLIENT ===
IP: {flow_data['client_ip']}
Port: {flow_data['client_port']}

=== TLS/SSL ===
Information: {flow_data['tls_info']}
TLS Version: {flow_data['tls_version']}
Cipher: {flow_data['tls_cipher']}
"""
        
        self.client_info_text.insert("1.0", client_info)
        self.client_info_text.config(state="disabled")
        
        server_info = f"""=== SERVER ===
IP: {flow_data['server_ip']}
Port: {flow_data['server_port']}

=== TLS/SSL ===
Information: {flow_data['tls_info']}
TLS Version: {flow_data['tls_version']}
Cipher: {flow_data['tls_cipher']}
"""
        
        self.server_info_text.insert("1.0", server_info)
        self.server_info_text.config(state="disabled")

    def populate_timing_tab(self, flow_data: Dict[str, Any]):
        """Populates the timing tab"""
        timing_info = f"""=== TIMESTAMPS ===
Flow Creation: {datetime.datetime.fromtimestamp(flow_data['timestamp_created']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}
Request Start: {datetime.datetime.fromtimestamp(flow_data['timestamp_start_raw']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}
Response End: {datetime.datetime.fromtimestamp(flow_data['timestamp_end_raw']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if flow_data['timestamp_end_raw'] else 'N/A'}

=== DURATIONS ===
Total Duration: {flow_data['duration']}
Lifetime: {time.time() - flow_data['timestamp_created']:.3f}s

=== PERFORMANCE ANALYSIS ===
Request Size: {len(flow_data['req_body_bytes'])} bytes
Response Size: {len(flow_data['resp_body_bytes'])} bytes
Transfer Rate: {(len(flow_data['req_body_bytes']) + len(flow_data['resp_body_bytes'])) / max(float(flow_data['duration'].replace('s', '')), 0.001):.2f} bytes/s
"""
        
        self.timing_text.insert("1.0", timing_info)
        self.timing_text.config(state="disabled")

    def populate_codec_tab(self, flow_data: Dict[str, Any], iid: str):
        """Populates the codec/editing tab"""
        req_decoded, req_type, req_editable = Codec.auto_decode(
            flow_data["req_body_bytes"], flow_data["req_headers"]
        )
        
        self.req_edit_text.config(state="normal")
        self.req_edit_text.insert("1.0", req_decoded)
        if not req_editable:
            self.req_edit_text.config(state="disabled")
        
        self.req_codec_label.config(text=f"Detected Codec: {req_type}")
        
        resp_decoded, resp_type, resp_editable = Codec.auto_decode(
            flow_data["resp_body_bytes"], flow_data["resp_headers"]
        )
        
        self.resp_edit_text.config(state="normal")
        self.resp_edit_text.insert("1.0", resp_decoded)
        if not resp_editable:
            self.resp_edit_text.config(state="disabled")
        
        self.resp_codec_label.config(text=f"Detected Codec: {resp_type}")
        
        self.codec_info[iid] = {
            'req_type': req_type,
            'resp_type': resp_type
        }

    def populate_errors_tab(self, flow_data: Dict[str, Any]):
        """Populates the errors tab"""
        if flow_data["error_msg"]:
            error_info = f"""=== ERROR DETECTED ===
Message: {flow_data['error_msg']}
Timestamp: {flow_data['error_timestamp']}

=== CONTEXT ===
Method: {flow_data['req_method']}
URL: {flow_data['req_url']}
Response Status: {flow_data['resp_status']}
"""
        else:
            error_info = "No error detected in this flow."
        
        self.errors_text.insert("1.0", error_info)
        self.errors_text.config(state="disabled")

    def populate_websocket_tab(self, flow_data: Dict[str, Any]):
        """Populates the WebSocket tab"""
        if flow_data["websocket_messages"] > 0:
            ws_info = f"""=== WEBSOCKET DETECTED ===
Number of Messages: {flow_data['websocket_messages']}
Connection Closed: {'Yes' if flow_data['websocket_closed'] else 'No'}

=== CONNECTION DETAILS ===
Original URL: {flow_data['req_url']}
Protocol: WebSocket
"""
        else:
            ws_info = "This flow is not a WebSocket connection."
        
        self.websocket_text.insert("1.0", ws_info)
        self.websocket_text.config(state="disabled")

    def update_status(self):
        """Updates status information"""
        num_flows = len(self.flows_data)
        self.status_var.set(f"Proxy active on port {self.port} | {num_flows} flows captured")
        self.after(5000, self.update_status)

    def get_selected_flow_id(self):
        """Gets the ID of the selected flow"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select a flow from the list first.")
            return None
        return selected_items[0]

    def send_modified(self):
        """Sends the flow with modifications"""
        iid = self.get_selected_flow_id()
        if not iid:
            return

        try:
            req_text = self.req_edit_text.get("1.0", tk.END).strip()
            req_type = self.codec_info[iid]['req_type']
            modified_req_body = Codec.encode(req_text, req_type)

            resp_text = self.resp_edit_text.get("1.0", tk.END).strip()
            resp_type = self.codec_info[iid]['resp_type']
            modified_resp_body = Codec.encode(resp_text, resp_type)

            self.mod_q.put({
                "id": iid,
                "req_body_modified": modified_req_body,
                "resp_body_modified": modified_resp_body
            })
            
            self.finalize_send(iid, "sent with modifications")
        except Exception as e:
            messagebox.showerror("Encoding Error", f"Could not encode the payload:\n{e}")

    def send_unmodified(self):
        """Sends the flow without modifications"""
        iid = self.get_selected_flow_id()
        if not iid:
            return
        
        self.mod_q.put({"id": iid})
        self.finalize_send(iid, "sent without modifications")

    def finalize_send(self, iid: str, message: str):
        """Finalizes the send by removing the flow from the interface"""
        if iid in self.tree.get_children():
            self.tree.delete(iid)
        if iid in self.flows_data:
            del self.flows_data[iid]
        self.clear_all_views()
        self.status_var.set(f"Flow {iid[:8]} {message}.")

    def copy_as_curl(self):
        """Copies the flow as a cURL command"""
        iid = self.get_selected_flow_id()
        if not iid:
            return
        
        flow_data = self.flows_data.get(iid)
        if not flow_data:
            return

        try:
            curl_cmd = f"curl -X {flow_data['req_method']} '{flow_data['req_url']}'"
            
            for k, v in flow_data['req_headers'].items():
                curl_cmd += f" -H '{k}: {v}'"
            
            if flow_data['req_body_bytes']:
                req_decoded, _, _ = Codec.auto_decode(flow_data['req_body_bytes'], flow_data['req_headers'])
                curl_cmd += f" -d '{req_decoded}'"
            
            self.clipboard_clear()
            self.clipboard_append(curl_cmd)
            self.update()
            
            messagebox.showinfo("cURL Copied", "cURL command copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Error generating cURL: {e}")

    def export_har(self):
        """Exports the flows as a HAR file"""
        messagebox.showinfo("Feature", "HAR export will be implemented in a future version.")

    def toggle_capture(self):
        """Toggles flow capture"""
        messagebox.showinfo("Feature", "Pause/Resume capture will be implemented in a future version.")

    def toggle_mode(self):
        """Switches between inspection and interception modes"""
        mode = self.mode_var.get()
        if mode == "inspection":
            self.send_mod_btn.config(state="disabled")
            self.send_orig_btn.config(state="disabled")
            self.status_var.set("Inspection mode active. Traffic flows uninterrupted.")
        else:
            self.send_mod_btn.config(state="normal")
            self.send_orig_btn.config(state="normal")
            self.status_var.set("Interception mode active. Matching flows will be held.")
        self.mode_q.put(mode)

    def clear_session(self):
        """Clears all flows from the session"""
        if messagebox.askyesno("Clear Session", "This will remove all intercepted flows from the screen. Do you want to continue?"):
            for iid in self.tree.get_children():
                if iid in self.flows_data:
                    self.mod_q.put({"id": iid})
                self.tree.delete(iid)
            self.flows_data.clear()
            self.clear_all_views()
            self.status_var.set("Session cleared.")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Advanced Auditing Proxy")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Proxy port (default: 8080)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    
    args = parser.parse_args()
    
    app = AdvancedProxyApp(args.port, args.verbose)
    app.mainloop()

if __name__ == "__main__":
    main()