"""
app.py
Authenticated Air-Gapped VAPT Synthesizer & Conversational AI Chatbot.
Custom Jet Black + Cerulean Blue Theme with Interactive Hacker Mascot & ChatGPT-Style Stop Control.
Operates 100% locally with zero external CDNs, cloud endpoints, or telemetry.
"""

from __future__ import annotations
import base64
import json
import os
import time
from typing import Any, Dict, List
import streamlit as st

from agent.auth import authenticate_analyst, DEFAULT_ANALYSTS
from agent.parser import parse_vulnerability_input
from agent.report_generator import generate_executive_html_dossier
from agent.synthesizer import (
    stream_chat_synthesis,
    verify_ollama_model,
    get_available_ollama_models,
    start_ollama_daemon
)

# -----------------------------------------------------------------------------
# Streamlit Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="VAPT Synthesizer | Cyber Recon AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# Jet Black + Cerulean Blue + Electric Neon Emerald Tactical Cyber Styling
# -----------------------------------------------------------------------------
CYBER_CSS = """
<style>
    /* Jet Black Core Theme Overrides */
    .stApp {
        background-color: #08090b !important;
        color: #d8e2ec !important;
    }
    
    /* Top Header Bar */
    header[data-testid="stHeader"] {
        background-color: rgba(8, 9, 11, 0.95) !important;
        border-bottom: 1px solid rgba(0, 150, 199, 0.25) !important;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0a0d14 !important;
        border-right: 1px solid rgba(0, 150, 199, 0.25) !important;
    }

    /* Cerulean Blue & Emerald Glowing Metric Cards */
    div[data-testid="stMetric"] {
        background-color: #0d121c !important;
        border: 1px solid rgba(0, 150, 199, 0.35) !important;
        border-radius: 8px !important;
        padding: 12px 16px !important;
        box-shadow: 0 4px 15px rgba(0, 150, 199, 0.1) !important;
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }
    div[data-testid="stMetric"]:hover {
        border-color: #00ff9d !important;
        box-shadow: 0 4px 20px rgba(0, 255, 157, 0.15) !important;
    }
    div[data-testid="stMetric"] label {
        color: #00b4d8 !important;
        font-weight: 600 !important;
    }
    div[data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-family: monospace !important;
    }

    /* Primary Action Buttons: Cerulean to Electric Neon Emerald Gradient */
    button[kind="primary"] {
        background: linear-gradient(135deg, #007ba7 0%, #0096c7 40%, #00ff9d 100%) !important;
        color: #08090b !important;
        border: 1px solid #00ff9d !important;
        border-radius: 6px !important;
        font-weight: 700 !important;
        letter-spacing: 0.3px !important;
        box-shadow: 0 0 14px rgba(0, 255, 157, 0.35) !important;
        transition: all 0.25s ease-in-out !important;
    }
    button[kind="primary"]:hover {
        background: linear-gradient(135deg, #0096c7 0%, #00ff9d 100%) !important;
        box-shadow: 0 0 22px rgba(0, 255, 157, 0.6) !important;
        color: #000000 !important;
        transform: translateY(-1px) !important;
    }

    button[kind="secondary"] {
        background-color: #101622 !important;
        color: #00b4d8 !important;
        border: 1px solid rgba(0, 150, 199, 0.4) !important;
        border-radius: 6px !important;
    }
    button[kind="secondary"]:hover {
        background-color: #162030 !important;
        border-color: #00ff9d !important;
        color: #00ff9d !important;
        box-shadow: 0 0 12px rgba(0, 255, 157, 0.25) !important;
    }

    /* Chat Messages Styling: Assistant in Emerald Neon, User in Cerulean */
    div[data-testid="stChatMessage"] {
        background-color: #0d121c !important;
        border: 1px solid rgba(0, 150, 199, 0.2) !important;
        border-radius: 8px !important;
        margin-bottom: 12px !important;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.5) !important;
    }
    div[data-testid="stChatMessage"]:has(span[data-testid="stChatMessageAvatarAssistant"]) {
        border-left: 4px solid #00ff9d !important;
        box-shadow: -2px 0 12px rgba(0, 255, 157, 0.15), 0 2px 10px rgba(0, 0, 0, 0.5) !important;
    }
    div[data-testid="stChatMessage"]:has(span[data-testid="stChatMessageAvatarUser"]) {
        border-left: 4px solid #0096c7 !important;
        box-shadow: -2px 0 12px rgba(0, 150, 199, 0.15), 0 2px 10px rgba(0, 0, 0, 0.5) !important;
    }

    /* Tabs Styling */
    button[data-baseweb="tab"] {
        color: #8b9bb4 !important;
        font-weight: 600 !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #00ff9d !important;
        border-bottom-color: #00ff9d !important;
    }

    /* Expander Styling */
    div[data-testid="stExpander"] {
        background-color: #0b1018 !important;
        border: 1px solid rgba(0, 150, 199, 0.25) !important;
        border-radius: 6px !important;
    }

    /* Animated Pulsing Status Dots */
    @keyframes ceruleanPulse {
        0% { box-shadow: 0 0 0 0 rgba(0, 180, 216, 0.7); }
        70% { box-shadow: 0 0 0 8px rgba(0, 180, 216, 0); }
        100% { box-shadow: 0 0 0 0 rgba(0, 180, 216, 0); }
    }
    .pulsing-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        background-color: #00e5ff;
        border-radius: 50%;
        animation: ceruleanPulse 2s infinite;
        margin-right: 6px;
        vertical-align: middle;
    }

    @keyframes emeraldPulse {
        0% { box-shadow: 0 0 0 0 rgba(0, 255, 157, 0.8); }
        70% { box-shadow: 0 0 0 8px rgba(0, 255, 157, 0); }
        100% { box-shadow: 0 0 0 0 rgba(0, 255, 157, 0); }
    }
    .emerald-pulsing-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        background-color: #00ff9d;
        border-radius: 50%;
        animation: emeraldPulse 1.8s infinite;
        margin-right: 6px;
        vertical-align: middle;
    }

    /* Tactical Continue Conversation Box */
    .continue-box {
        background: linear-gradient(135deg, #0c141f 0%, #070d14 100%) !important;
        border: 1px solid #00ff9d !important;
        border-radius: 10px !important;
        padding: 14px 18px !important;
        margin-top: 10px !important;
        margin-bottom: 14px !important;
        box-shadow: 0 0 20px rgba(0, 255, 157, 0.15) !important;
    }
    .continue-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background-color: rgba(0, 255, 157, 0.12);
        color: #00ff9d;
        border: 1px solid #00ff9d;
        border-radius: 16px;
        padding: 2px 10px;
        font-family: monospace;
        font-size: 0.8em;
        font-weight: bold;
        letter-spacing: 0.5px;
    }

    /* Fixed Animated Cyber Background with Skeleton Robot & Circuit Lines */
    .cyber-bg-canvas {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        pointer-events: none !important;
        z-index: 0;
        overflow: hidden;
        opacity: 0.18;
    }

    /* Animated Scanning Laser Line */
    .cyber-scanning-laser {
        position: absolute;
        left: 0;
        width: 100%;
        height: 2.5px;
        background: linear-gradient(90deg, transparent 0%, rgba(0, 150, 199, 0.4) 20%, #00ff9d 50%, rgba(0, 150, 199, 0.4) 80%, transparent 100%);
        box-shadow: 0 0 16px rgba(0, 255, 157, 0.9), 0 0 35px rgba(0, 150, 199, 0.6);
        animation: laserSweep 9s linear infinite;
    }

    @keyframes laserSweep {
        0% { top: -2%; opacity: 0; }
        8% { opacity: 0.9; }
        92% { opacity: 0.9; }
        100% { top: 102%; opacity: 0; }
    }

    /* Ambient Horizon Perspective Grid Lines */
    .cyber-grid-floor {
        position: absolute;
        bottom: 0;
        left: 0;
        width: 100%;
        height: 50vh;
        background: 
            linear-gradient(to bottom, rgba(8, 9, 11, 1) 0%, rgba(8, 9, 11, 0.2) 100%),
            repeating-linear-gradient(90deg, transparent, transparent 59px, rgba(0, 150, 199, 0.12) 60px),
            repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(0, 255, 157, 0.08) 40px);
        mask-image: linear-gradient(to top, rgba(0,0,0,0.9) 0%, rgba(0,0,0,0) 100%);
        -webkit-mask-image: linear-gradient(to top, rgba(0,0,0,0.9) 0%, rgba(0,0,0,0) 100%);
    }

    /* Robot Skeleton Cartoon Hover & Positioning */
    .cyber-skeleton-droid {
        position: absolute;
        bottom: 2%;
        right: 2%;
        width: 320px;
        height: 448px;
        animation: droidHover 6s ease-in-out infinite;
        filter: drop-shadow(0 0 18px rgba(0, 255, 157, 0.4));
    }

    @keyframes droidHover {
        0%, 100% {
            transform: translateY(0px) rotate(0deg);
        }
        50% {
            transform: translateY(-16px) rotate(1.2deg);
        }
    }

    /* Secondary Skeleton Droid Silhouette on Left Edge */
    .cyber-skeleton-silhouette {
        position: absolute;
        top: 14%;
        left: -35px;
        width: 220px;
        height: 308px;
        opacity: 0.45;
        animation: droidHoverLeft 8s ease-in-out infinite;
        filter: drop-shadow(0 0 12px rgba(0, 150, 199, 0.3));
    }

    @keyframes droidHoverLeft {
        0%, 100% {
            transform: translateY(0px) rotate(0deg) scaleX(-1);
        }
        50% {
            transform: translateY(-14px) rotate(-1.2deg) scaleX(-1);
        }
    }

    /* Animated Background Circuit & Data Stream Lines */
    .cyber-circuit-svg {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
    }

    .circuit-stream-1 {
        stroke-dasharray: 12, 18;
        animation: flowLine 12s linear infinite;
    }

    .circuit-stream-2 {
        stroke-dasharray: 16, 24;
        animation: flowLineRev 15s linear infinite;
    }

    .circuit-stream-3 {
        stroke-dasharray: 8, 14;
        animation: flowLine 9s linear infinite;
    }

    @keyframes flowLine {
        from { stroke-dashoffset: 400; }
        to { stroke-dashoffset: 0; }
    }

    @keyframes flowLineRev {
        from { stroke-dashoffset: 0; }
        to { stroke-dashoffset: 400; }
    }

    /* Floating Data Particle Nodes */
    @keyframes pulseNode {
        0%, 100% { r: 3.5px; opacity: 0.45; }
        50% { r: 5.5px; opacity: 1; }
    }
    .pulsing-circuit-node {
        animation: pulseNode 3s ease-in-out infinite;
    }
</style>
"""
st.markdown(CYBER_CSS, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# Animated Background: Skeleton Robot Cartoon + Cyber Circuit Lines
# -----------------------------------------------------------------------------
def _load_compact_bg_svg() -> str:
    path = "data/robot_skeleton_cartoon.svg"
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    else:
        raw = "<svg></svg>"
    return "".join(
        line.strip() for line in raw.splitlines()
        if line.strip() and not line.strip().startswith("<!--")
    )

ROBOT_SKELETON_COMPACT = _load_compact_bg_svg()

CIRCUIT_SVG_COMPACT = (
    '<svg class="cyber-circuit-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 900" preserveAspectRatio="none">'
    '<defs>'
    '<filter id="circuitGlow" x="-50%" y="-50%" width="200%" height="200%">'
    '<feGaussianBlur stdDeviation="3" result="blur" />'
    '<feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>'
    '</filter>'
    '</defs>'
    '<path d="M 0 140 L 320 140 L 420 240 L 820 240 L 920 340 L 1380 340 L 1600 340" fill="none" stroke="#0096c7" stroke-width="2" class="circuit-stream-1" opacity="0.6" />'
    '<path d="M 0 560 L 260 560 L 340 480 L 700 480 L 800 580 L 1220 580 L 1320 480 L 1600 480" fill="none" stroke="#00ff9d" stroke-width="2" class="circuit-stream-2" opacity="0.55" />'
    '<path d="M 180 0 L 180 260 L 250 330 L 250 680 L 310 740 L 310 900" fill="none" stroke="#0096c7" stroke-width="1.5" class="circuit-stream-3" opacity="0.5" />'
    '<path d="M 1240 0 L 1240 220 L 1160 300 L 1160 620 L 1240 700 L 1240 900" fill="none" stroke="#00ff9d" stroke-width="1.5" class="circuit-stream-1" opacity="0.5" />'
    '<line x1="420" y1="240" x2="700" y2="480" stroke="#007ba7" stroke-width="1.5" stroke-dasharray="4,8" opacity="0.4" />'
    '<line x1="800" y1="580" x2="920" y2="340" stroke="#00ff9d" stroke-width="1.5" stroke-dasharray="4,8" opacity="0.4" />'
    '<circle cx="320" cy="140" r="4.5" fill="#00ff9d" filter="url(#circuitGlow)" class="pulsing-circuit-node" />'
    '<circle cx="420" cy="240" r="5" fill="#0096c7" filter="url(#circuitGlow)" class="pulsing-circuit-node" />'
    '<circle cx="820" cy="240" r="4" fill="#00ff9d" filter="url(#circuitGlow)" class="pulsing-circuit-node" />'
    '<circle cx="920" cy="340" r="5" fill="#0096c7" filter="url(#circuitGlow)" class="pulsing-circuit-node" />'
    '<circle cx="260" cy="560" r="4.5" fill="#00ff9d" filter="url(#circuitGlow)" class="pulsing-circuit-node" />'
    '<circle cx="700" cy="480" r="5" fill="#0096c7" filter="url(#circuitGlow)" class="pulsing-circuit-node" />'
    '<circle cx="800" cy="580" r="4.5" fill="#00ff9d" filter="url(#circuitGlow)" class="pulsing-circuit-node" />'
    '<circle cx="1220" cy="580" r="4" fill="#0096c7" filter="url(#circuitGlow)" class="pulsing-circuit-node" />'
    '<circle cx="250" cy="330" r="4.5" fill="#00ff9d" filter="url(#circuitGlow)" class="pulsing-circuit-node" />'
    '<circle cx="1160" cy="300" r="5" fill="#0096c7" filter="url(#circuitGlow)" class="pulsing-circuit-node" />'
    '</svg>'
)

CYBER_BACKGROUND_HTML = (
    '<div class="cyber-bg-canvas">'
    '<div class="cyber-scanning-laser"></div>'
    '<div class="cyber-grid-floor"></div>'
    + CIRCUIT_SVG_COMPACT +
    f'<div class="cyber-skeleton-droid">{ROBOT_SKELETON_COMPACT}</div>'
    f'<div class="cyber-skeleton-silhouette">{ROBOT_SKELETON_COMPACT}</div>'
    '</div>'
)
st.markdown(CYBER_BACKGROUND_HTML, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# Session State Initialization
# -----------------------------------------------------------------------------
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user_profile" not in st.session_state:
    st.session_state["user_profile"] = None
if "messages" not in st.session_state:
    st.session_state["messages"] = []
if "loaded_scan_content" not in st.session_state:
    st.session_state["loaded_scan_content"] = ""
if "parsed_scan" not in st.session_state:
    st.session_state["parsed_scan"] = None
if "active_scan_name" not in st.session_state:
    st.session_state["active_scan_name"] = ""
if "stop_requested" not in st.session_state:
    st.session_state["stop_requested"] = False
if "in_progress_reply" not in st.session_state:
    st.session_state["in_progress_reply"] = ""
if "show_continue_box" not in st.session_state:
    st.session_state["show_continue_box"] = False

# Handle recovery from interrupted generation (Stop click)
if st.session_state.get("in_progress_reply"):
    partial_text = st.session_state.pop("in_progress_reply")
    if partial_text.strip():
        st.session_state["messages"].append({
            "role": "assistant",
            "content": partial_text.strip() + "\n\n*(⏹️ Generation stopped by analyst)*"
        })
        st.session_state["show_continue_box"] = True


# -----------------------------------------------------------------------------
# Authentication Guard Screen (Jet Black, Cerulean Blue, Electric Emerald)
# -----------------------------------------------------------------------------
def render_login_screen():
    col_left, col_center, col_right = st.columns([1, 2, 1])
    with col_center:
        st.markdown("<br>", unsafe_allow_html=True)
        # Hacker Mascot Banner in Login
        st.markdown(
            """
            <div style="background: linear-gradient(180deg, #0d131f 0%, #06090f 100%); border: 1px solid rgba(0, 255, 157, 0.4); border-radius: 12px; padding: 26px; box-shadow: 0 0 25px rgba(0, 255, 157, 0.15); text-align: center;">
                <div style="display: flex; justify-content: center; margin-bottom: 15px;">
                    <img src="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 240 240' width='110' height='110'><circle cx='120' cy='120' r='110' fill='%2305070a' stroke='%230096c7' stroke-width='3'/><circle cx='120' cy='120' r='98' fill='none' stroke='%2300ff9d' stroke-width='1.5' stroke-dasharray='4,4'/><path d='M65 135 C60 70, 75 35, 120 35 C165 35, 180 70, 175 135 Z' fill='%2318202c' stroke='%2300b4d8' stroke-width='2.5'/><rect x='90' y='96' width='60' height='20' rx='6' fill='%23007ba7' stroke='%2300ff9d' stroke-width='2'/><polygon points='65,225 175,225 165,195 75,195' fill='%23080c14' stroke='%230096c7' stroke-width='2'/><text x='112' y='215' fill='%2300ff9d' font-family='monospace' font-size='10'>&gt;_</text></svg>" width="100" style="filter: drop-shadow(0 0 10px rgba(0, 255, 157, 0.35));"/>
                </div>
                <h2 style="margin: 0; font-family: monospace; letter-spacing: 1px;">
                    <span style="color: #00e5ff;">🛡️ CYBER RECON AI</span> // <span style="color: #00ff9d;">PORTAL</span>
                </h2>
                <p style="color: #00b4d8; font-size: 0.9em; margin-top: 6px;">
                    Jet Black Air-Gap Tactical Console • <span style="color: #00ff9d;">Gemma Neural Engine</span><br>
                    <span style="color: #8b9bb4;">Security clearance token required for session authorization.</span>
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown("<br>", unsafe_allow_html=True)

        with st.form("login_form"):
            username = st.text_input("Analyst Username", value="analyst", placeholder="e.g. analyst, auditor, admin")
            password = st.text_input("Passphrase", type="password", value="VaptSecure2026!")
            submit_btn = st.form_submit_button("🔓 Authenticate Terminal Session", type="primary", width="stretch")

            if submit_btn:
                success, msg, profile = authenticate_analyst(username, password)
                if success:
                    st.session_state["authenticated"] = True
                    st.session_state["user_profile"] = profile
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)

        with st.expander("ℹ️ Pre-Configured Operational Credentials (Offline Demo)"):
            st.markdown(
                """
                - **Lead Penetration Tester:** `analyst` / `VaptSecure2026!`
                - **Compliance Auditor:** `auditor` / `AuditSafe2026!`
                - **Security Director / Admin:** `admin` / `AdminAirGap2026!`
                """
            )


# -----------------------------------------------------------------------------
# Authenticated Cyber Dashboard Layout
# -----------------------------------------------------------------------------
def render_authenticated_dashboard(user: Dict[str, Any]):
    # Top Header Console
    header_col1, header_col2 = st.columns([3, 1])
    with header_col1:
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 14px;">
                <img src="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 240 240' width='44' height='44'><circle cx='120' cy='120' r='110' fill='%2305070a' stroke='%230096c7' stroke-width='4'/><circle cx='120' cy='120' r='96' fill='none' stroke='%2300ff9d' stroke-width='1.5' stroke-dasharray='3,5'/><rect x='90' y='96' width='60' height='20' rx='6' fill='%23007ba7' stroke='%2300ff9d' stroke-width='2'/></svg>" width="44"/>
                <div>
                    <h2 style="margin: 0; color: #ffffff; font-family: monospace; letter-spacing: 0.5px;">
                        <span style="color: #00e5ff;">CYBER</span> <span style="color: #00ff9d;">RECON</span> <span style="color: #ffffff;">// VAPT SYNTHESIZER</span>
                    </h2>
                    <span style="color: #8b9bb4; font-size: 0.85em;">
                        <span class="emerald-pulsing-dot"></span>Jet Black Canvas • Cerulean Intelligence • <span style="color: #00ff9d; font-weight: 600;">Electric Emerald</span>
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with header_col2:
        st.markdown(
            f"""
            <div style="background-color: #0c121d; border: 1px solid rgba(0, 255, 157, 0.4); border-radius: 6px; padding: 8px 12px; text-align: right; box-shadow: 0 0 12px rgba(0, 255, 157, 0.15);">
                <span style="color: #00ff9d; font-weight: bold; font-family: monospace;">● {user['role'].upper()}</span><br>
                <span style="color: #8b9bb4; font-size: 0.8em;">{user['name']} • {user['clearance']}</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # Sidebar: Terminal Controls, Model Engine, and Scan Source
    # -------------------------------------------------------------------------
    with st.sidebar:
        # Mascot Mini-Card in Sidebar
        st.markdown(
            """
            <div style="background: linear-gradient(180deg, #0f1624 0%, #080c14 100%); border: 1px solid rgba(0, 255, 157, 0.4); border-radius: 8px; padding: 12px; text-align: center; margin-bottom: 12px; box-shadow: 0 0 15px rgba(0, 255, 157, 0.15);">
                <div style="color: #00ff9d; font-family: monospace; font-size: 0.9em; font-weight: bold;">[ NEURAL AGENT MATRIX ]</div>
                <div style="color: #8b9bb4; font-size: 0.75em; margin-top: 4px;">ACTIVE DEFENSIVE SYNTHESIS</div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.subheader("👤 Operator Profile")
        st.markdown(f"**Analyst:** `{user['name']}`")
        st.markdown(f"**Clearance:** `{user['clearance']}`")
        st.markdown(f"**Session:** `{user['session_token'][:10]}...`")
        if st.button("🔒 Disconnect Terminal", width="stretch"):
            st.session_state["authenticated"] = False
            st.session_state["user_profile"] = None
            st.session_state["messages"] = []
            st.session_state["parsed_scan"] = None
            st.session_state["active_scan_name"] = ""
            st.session_state["loaded_scan_content"] = ""
            st.rerun()

        st.markdown("---")
        st.subheader("⚙️ AI Synthesizer Engine")
        
        # Dual-Engine Selector: Local Ollama Daemon (gemma) is primary default
        engine_type = st.radio(
            "Synthesizer Engine Mode",
            [
                "🟢 Local Ollama Daemon (http://127.0.0.1:11434)",
                "⚡ Autonomous Air-Gap Engine (Always Ready)"
            ],
            index=0,
            help="Default: Local Ollama daemon streaming Gemma model. Fallback to Autonomous Air-Gap if offline."
        )

        if "Autonomous" in engine_type:
            model_name = "airgap-autonomous"
            st.success("● Engine: Autonomous Air-Gap Synthesizer")
            st.caption("Zero external daemons required. Deterministic on-device cybersecurity reasoning.")
        else:
            pulled_models = get_available_ollama_models()
            if pulled_models:
                # Default to model matching 'gemma' (e.g. gemma, gemma:latest, gemma4)
                default_idx = 0
                for idx, m in enumerate(pulled_models):
                    if "gemma" in m.lower():
                        default_idx = idx
                        break
                model_name = st.selectbox("Active Ollama Model", options=pulled_models, index=default_idx)
            else:
                model_name = st.text_input("Ollama Model Tag", value="gemma", help="Local quantized Ollama model tag (defaults to gemma)")

            is_ready, status_msg = verify_ollama_model(model_name)
            if is_ready:
                st.success(f"● Model Active: {model_name}")
            else:
                st.warning(f"○ Daemon Status: {status_msg}")
                col_btn1, col_btn2 = st.columns(2)
                with col_btn1:
                    if st.button("🚀 Start Daemon", width="stretch"):
                        ok, msg = start_ollama_daemon()
                        if ok:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)
                with col_btn2:
                    if st.button("🔄 Refresh", width="stretch"):
                        st.rerun()

        st.markdown("---")
        st.subheader("📥 Vulnerability & Recon Ingestion")

        scan_source = st.radio(
            "Scan Intelligence Target",
            [
                "🔬 Deep Recon (Multi-Host Nmap XML)",
                "🔐 Authenticated Audit (CIS Benchmark JSON)",
                "🎯 Tenable Nessus (sample_nessus.xml)",
                "⚡ ProjectDiscovery Nuclei (sample_nuclei.json)",
                "📋 General Scan (sample_vuln.json)",
                "📁 Custom File Upload"
            ]
        )

        raw_text = ""
        active_name = ""

        if scan_source == "🔬 Deep Recon (Multi-Host Nmap XML)":
            path = "data/sample_deep_recon.xml"
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    raw_text = f.read()
                active_name = "sample_deep_recon.xml (Multi-Host Nmap)"
        elif scan_source == "🔐 Authenticated Audit (CIS Benchmark JSON)":
            path = "data/sample_authenticated_scan.json"
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    raw_text = f.read()
                active_name = "sample_authenticated_scan.json (Privileged Audit)"
        elif scan_source == "🎯 Tenable Nessus (sample_nessus.xml)":
            path = "data/sample_nessus.xml"
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    raw_text = f.read()
                active_name = "sample_nessus.xml (Tenable Nessus XML)"
        elif scan_source == "⚡ ProjectDiscovery Nuclei (sample_nuclei.json)":
            path = "data/sample_nuclei.json"
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    raw_text = f.read()
                active_name = "sample_nuclei.json (Nuclei Vulnerability Stream)"
        elif scan_source == "📋 General Scan (sample_vuln.json)":
            path = "data/sample_vuln.json"
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    raw_text = f.read()
                active_name = "sample_vuln.json"
        else:
            uploaded_file = st.file_uploader("Upload Nmap XML, Nessus XML, or Scan JSON/JSONL", type=["xml", "json", "nessus", "jsonl"])
            if uploaded_file is not None:
                raw_text = uploaded_file.getvalue().decode("utf-8", errors="replace")
                active_name = uploaded_file.name

        # Parse scan on selection change
        if raw_text and (active_name != st.session_state["active_scan_name"] or st.session_state["parsed_scan"] is None):
            success, msg, structured_data = parse_vulnerability_input(raw_text)
            if success:
                st.session_state["active_scan_name"] = active_name
                st.session_state["loaded_scan_content"] = raw_text
                st.session_state["parsed_scan"] = structured_data
                st.toast(f"Intelligence Feed Ingested: {active_name}", icon="🛡️")
                # Reset conversation with new scan context
                welcome_msg = (
                    f"🛡️ **CYBER INTELLIGENCE STREAM ACQUIRED: `{active_name}`**\n\n"
                    f"- **Target Network:** `{structured_data['metadata'].get('target', 'N/A')}`\n"
                    f"- **Assessment Profile:** `{structured_data['metadata'].get('scan_type', 'VAPT Scan')}`\n"
                    f"- **Privileged Mode:** `{'🔒 Authenticated Audit' if structured_data['metadata'].get('authenticated_audit') else '🌐 External Perimeter'}`\n"
                    f"- **Assets Profiled:** `{structured_data.get('recon', {}).get('total_hosts', 1)} Host(s)` | `{structured_data.get('recon', {}).get('total_open_ports', len(structured_data.get('findings', [])))} Open Port(s)`\n"
                    f"- **Vulnerability Vectors:** `{len(structured_data.get('findings', []))} Findings`\n\n"
                    f"I am standing by to synthesize findings, analyze OS fingerprints, or map prioritized technical remediations. Ask any question or trigger a prompt pill below."
                )
                st.session_state["messages"] = [{"role": "assistant", "content": welcome_msg}]
            else:
                st.error(f"Failed to parse scan: {msg}")

        st.markdown("---")
        st.subheader("⚡ Quick Prompt Directives")
        prompt_pills = [
            ("📋 Executive Summary", "Generate an executive briefing assessing overall posture, business risk, and leadership takeaways."),
            ("🔬 Deep Recon Breakdown", "Provide a deep reconnaissance breakdown of all discovered hosts, open services, OS fingerprints, and exposed ports."),
            ("🛠️ Prioritized Remediation", "Generate a prioritized, step-by-step remediation roadmap organized by immediate vs planned tasks."),
            ("🚨 Critical Vulnerabilities", "Break down the most critical vulnerabilities, their exploitability, and CVSS impact."),
            ("🛡️ Zero-Trust Hardening", "What defense-in-depth and zero-trust controls should we enforce based on these findings?")
        ]

        selected_prompt = None
        for label, prompt_text in prompt_pills:
            if st.button(label, width="stretch"):
                selected_prompt = prompt_text

        if st.button("🗑️ Reset Terminal History", width="stretch"):
            st.session_state["messages"] = []
            st.session_state["show_continue_box"] = False
            st.rerun()

        # Markdown Export
        if st.session_state["messages"]:
            export_text = f"# Cyber Recon Intelligence Log\nAnalyst: {user['name']} ({user['role']})\nTarget: {st.session_state.get('active_scan_name')}\nTimestamp: {user.get('authenticated_at')}\n\n"
            for m in st.session_state["messages"]:
                export_text += f"### {m['role'].upper()}\n{m['content']}\n\n"
            st.download_button(
                "💾 Export Intelligence Log",
                data=export_text,
                file_name="cyber_recon_intelligence.md",
                mime="text/markdown",
                width="stretch"
            )

        # Download Executive Audit Dossier from Sidebar
        if st.session_state.get("parsed_scan"):
            last_ai_note = st.session_state["messages"][-1]["content"] if st.session_state["messages"] and st.session_state["messages"][-1]["role"] == "assistant" else ""
            html_dossier = generate_executive_html_dossier(
                scan_data=st.session_state["parsed_scan"],
                user_profile=user,
                ai_summary=last_ai_note
            )
            st.download_button(
                "📄 Download Executive Dossier (HTML/PDF)",
                data=html_dossier,
                file_name=f"VAPT_Executive_Dossier_{str(st.session_state.get('active_scan_name', 'target')).replace(' ', '_')}.html",
                mime="text/html",
                width="stretch",
                help="Download full client-ready executive dossier with CVSS matrix and host cartography."
            )

        st.markdown(
            """
            <div style="border-top: 1px solid rgba(0, 150, 199, 0.2); padding-top: 10px; margin-top: 14px; font-size: 0.72em; color: #8b9bb4; text-align: center;">
                <span style="color: #00ff9d;">● AIR-GAP SOC ENVIRONMENT</span> • ZERO TELEMETRY<br>
                <span>NIST SP 800-115 // CIS BENCHMARK v8</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    # -------------------------------------------------------------------------
    # Main Content Area
    # -------------------------------------------------------------------------
    parsed_scan = st.session_state.get("parsed_scan")

    if not parsed_scan:
        st.warning("⚠️ No valid scan data loaded. Please select or upload a scan in the sidebar to begin.")
        return

    metadata = parsed_scan.get("metadata", {})
    recon = parsed_scan.get("recon", {})
    findings = parsed_scan.get("findings", [])

    # Cerulean Metrics Row
    m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
    with m_col1:
        st.metric("🎯 Scope Target", str(metadata.get("target", "Unknown"))[:18])
    with m_col2:
        st.metric("🖥️ Hosts Profiled", recon.get("total_hosts", 1))
    with m_col3:
        st.metric("🔌 Open Ports", recon.get("total_open_ports", len(findings)))
    with m_col4:
        crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        st.metric("🚨 Crit / High", f"{crit_count} / {high_count}")
    with m_col5:
        is_auth = metadata.get("authenticated_audit", False)
        st.metric("🔐 Mode", "Authenticated" if is_auth else "Perimeter Recon")

    # Tabbed Navigation
    tab_chat, tab_recon, tab_findings, tab_raw = st.tabs([
        "💬 Cyber AI Assistant (Interactive Chat)",
        "🔬 Deep Recon & Topology",
        "📊 Findings & Risk Matrix",
        "📜 Raw Intelligence Data"
    ])

    # -------------------------------------------------------------------------
    # Tab 1: Interactive Chatbot with Hacker Cartoon, Stop & Continue Controls
    # -------------------------------------------------------------------------
    with tab_chat:
        # Interactive Cyber Hacker Hero Banner with Cerulean & Electric Neon Emerald Accents
        st.markdown(
            f"""
            <div style="background: linear-gradient(135deg, #0e1522 0%, #06090e 100%); border: 1px solid rgba(0, 255, 157, 0.35); border-radius: 10px; padding: 18px 22px; margin-bottom: 20px; box-shadow: 0 4px 20px rgba(0, 255, 157, 0.12); display: flex; align-items: center; justify-content: space-between;">
                <div style="display: flex; align-items: center; gap: 18px;">
                    <div style="position: relative;">
                        <img src="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 240 240' width='85' height='85'><circle cx='120' cy='120' r='110' fill='%2305070a' stroke='%230096c7' stroke-width='4'/><circle cx='120' cy='120' r='98' fill='none' stroke='%2300ff9d' stroke-width='1.5' stroke-dasharray='4,4'/><path d='M65 135 C60 70, 75 35, 120 35 C165 35, 180 70, 175 135 Z' fill='%2318202c' stroke='%2300b4d8' stroke-width='2.5'/><rect x='90' y='96' width='60' height='20' rx='6' fill='%23007ba7' stroke='%2300ff9d' stroke-width='2'/><polygon points='65,225 175,225 165,195 75,195' fill='%23080c14' stroke='%230096c7' stroke-width='2'/><text x='112' y='215' fill='%2300ff9d' font-family='monospace' font-size='10'>&gt;_</text></svg>" width="75" style="filter: drop-shadow(0 0 8px rgba(0, 255, 157, 0.45)); border-radius: 50%;"/>
                    </div>
                    <div>
                        <div style="font-family: monospace; font-size: 1.1em; font-weight: bold; letter-spacing: 0.5px;">
                            <span style="color: #00e5ff;">CYBER RECON AI</span> // <span style="color: #00ff9d;">GEMMA BOT</span>
                        </div>
                        <div style="color: #8b9bb4; font-size: 0.85em; margin-top: 4px;">
                            <span class="emerald-pulsing-dot"></span><strong>STATUS:</strong> <span style="color: #00ff9d;">ONLINE</span> • <strong>ENGINE:</strong> {model_name.upper()} • <strong>TARGET:</strong> <code>{str(metadata.get('target', 'N/A'))[:22]}</code>
                        </div>
                        <div style="color: #00b4d8; font-size: 0.8em; margin-top: 2px;">
                            🔒 Air-Gapped Inference • Zero Off-Box Network Dispatch
                        </div>
                    </div>
                </div>
                <div style="text-align: right;">
                    <span style="background-color: rgba(0, 255, 157, 0.12); color: #00ff9d; border: 1px solid #00ff9d; padding: 4px 10px; border-radius: 20px; font-family: monospace; font-size: 0.8em;">
                        <span class="emerald-pulsing-dot"></span>LIVE STREAMING ACTIVE
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Stop Control Bar
        stop_col1, stop_col2 = st.columns([5, 1])
        with stop_col2:
            if st.button("⏹️ Stop Chat", type="secondary", width="stretch", help="Halt the current streaming response immediately like ChatGPT."):
                st.session_state["stop_requested"] = True
                st.session_state["show_continue_box"] = True
                st.rerun()

        # Render Conversation Stream with Cartoon Avatars
        hacker_avatar_path = "data/hacker_cartoon.svg"
        analyst_avatar_path = "data/analyst_cartoon.svg"

        for msg in st.session_state["messages"]:
            avatar = hacker_avatar_path if msg["role"] == "assistant" else analyst_avatar_path
            with st.chat_message(msg["role"], avatar=avatar):
                st.markdown(msg["content"])

        # Tactical Continue Conversation Box (shown after stop)
        if st.session_state.get("show_continue_box"):
            st.markdown(
                """
                <div class="continue-box">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <div class="continue-badge">
                            <span class="emerald-pulsing-dot"></span>
                            ⏸️ CONVERSATION PAUSED // OPERATOR HALT
                        </div>
                        <span style="color: #00ff9d; font-size: 0.8em; font-family: monospace; font-weight: bold;">
                            [ RESUME MATRIX READY ]
                        </span>
                    </div>
                    <p style="color: #d8e2ec; font-size: 0.9em; margin: 0 0 10px 0;">
                        The generation was interrupted. Choose how you would like to continue the conversation:
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )
            c_col1, c_col2, c_col3, c_col4 = st.columns([3, 3, 3, 1])
            with c_col1:
                if st.button("▶️ Continue Generation", key="btn_continue_stream", type="primary", width="stretch", help="Resume output directly from where it stopped"):
                    selected_prompt = "Please continue your previous response directly from where you stopped without repeating the existing text."
                    st.session_state["show_continue_box"] = False
            with c_col2:
                if st.button("🔧 Detail Remediation", key="btn_continue_remed", width="stretch", help="Pivot to specific hardening and patch commands"):
                    selected_prompt = "Provide prioritized technical remediation commands and hardening guidance for the identified findings."
                    st.session_state["show_continue_box"] = False
            with c_col3:
                if st.button("📋 Key Takeaways", key="btn_continue_takeaways", width="stretch", help="Summarize key risk takeaways"):
                    selected_prompt = "Summarize the critical takeaways and overall security posture in a concise briefing."
                    st.session_state["show_continue_box"] = False
            with c_col4:
                if st.button("✖️ Dismiss", key="btn_continue_dismiss", width="stretch", help="Close this continue prompt"):
                    st.session_state["show_continue_box"] = False
                    st.rerun()

        # Multimodal Architecture Diagram / Screenshot Ingestion (Gemma 4 Vision Alignment)
        with st.expander("🖼️ Multimodal Architecture Diagram / Screenshot (Gemma 4 Vision)", expanded=False):
            diag_col1, diag_col2 = st.columns([1, 1])
            with diag_col1:
                use_sample_diag = st.checkbox(
                    "Load Sample Enterprise Topology (`sample_network_diagram.png`)",
                    value=False,
                    key="chk_sample_diag",
                    help="Test Gemma 4 multimodal correlation with pre-packaged tactical cartography."
                )
            with diag_col2:
                uploaded_arch_img = st.file_uploader(
                    "Or Attach Custom Network Topology / Screenshot",
                    type=["png", "jpg", "jpeg", "webp"],
                    key="arch_img_uploader",
                    help="Correlate visual network architecture or packet captures with raw scan data."
                )

            arch_img_b64_list = None
            if uploaded_arch_img is not None:
                st.image(uploaded_arch_img, caption="Attached Architecture Asset", width=420)
                img_bytes = uploaded_arch_img.getvalue()
                arch_img_b64_list = [base64.b64encode(img_bytes).decode("utf-8")]
                st.success("● Multimodal asset attached for next query analysis.")
            elif use_sample_diag:
                sample_diag_path = "data/sample_network_diagram.png"
                if os.path.exists(sample_diag_path):
                    with open(sample_diag_path, "rb") as img_f:
                        img_bytes = img_f.read()
                    st.image(img_bytes, caption="Sample Enterprise Network Cartography (Active)", width=420)
                    arch_img_b64_list = [base64.b64encode(img_bytes).decode("utf-8")]
                    st.info("● Sample network topology diagram attached for multimodal correlation.")

        # Input Bar with ChatGPT-style submit_mode="stop"
        user_input = st.chat_input(
            "Ask anything about this scan, host topology, CVEs, or remediation...",
            submit_mode="stop"
        )
        prompt_to_send = selected_prompt or user_input

        # Interactive Quick Follow-Up Directives (visible when messages exist and not interrupted)
        if st.session_state["messages"] and not st.session_state.get("show_continue_box"):
            st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
            st.caption("⚡ Tactical SOC Follow-Up Directives:")
            f_col1, f_col2, f_col3, f_col4 = st.columns(4)
            with f_col1:
                if st.button("🛡️ Hardening Scripts", key="btn_fup_harden", width="stretch", help="Generate ready-to-run terminal patch commands"):
                    prompt_to_send = "Generate exact terminal hardening commands and configuration snippets to mitigate these vulnerabilities."
            with f_col2:
                if st.button("🔬 Attack Surface & OS", key="btn_fup_surface", width="stretch", help="Assess exposed services and OS footprint"):
                    prompt_to_send = "Deeply analyze discovered OS fingerprints, exposed high-risk ports, and external attack surface vectors."
            with f_col3:
                if st.button("📊 CVSS Vector Breakdown", key="btn_fup_cvss", width="stretch", help="Examine exploitability metrics"):
                    prompt_to_send = "Break down the CVSS 3.1 exploitability metrics, attack complexity, and business impact for the findings."
            with f_col4:
                if st.button("📑 Executive Sign-Off Memo", key="btn_fup_exec", width="stretch", help="Draft leadership summary"):
                    prompt_to_send = "Draft an executive summary memo for C-suite leadership detailing posture and required remediation timeline."

        if prompt_to_send:
            st.session_state["stop_requested"] = False
            st.session_state["show_continue_box"] = False
            # Append user message
            st.session_state["messages"].append({"role": "user", "content": prompt_to_send})
            with st.chat_message("user", avatar=analyst_avatar_path):
                st.markdown(prompt_to_send)

            # Generate Assistant Streaming Response with Hardware-Accelerated Rendering
            with st.chat_message("assistant", avatar=hacker_avatar_path):
                response_container = st.empty()
                full_reply = ""
                spinner_text = "Autonomous Air-Gap Engine synthesizing..." if model_name == "airgap-autonomous" else f"{model_name} streaming intelligence (CPU Fast-Threaded)..."

                last_render_time = 0.0
                with st.spinner(spinner_text):
                    for token in stream_chat_synthesis(
                        messages=st.session_state["messages"],
                        scan_context=parsed_scan,
                        model_name=model_name,
                        fallback=True,
                        images=arch_img_b64_list
                    ):
                        # Check if stop was requested during stream
                        if st.session_state.get("stop_requested"):
                            full_reply += "\n\n*(⏹️ Generation stopped by analyst)*"
                            st.session_state["show_continue_box"] = True
                            st.session_state["stop_requested"] = False
                            break

                        full_reply += token
                        st.session_state["in_progress_reply"] = full_reply
                        now = time.time()
                        # Batch token rendering every 75ms or on double-newline for silky-smooth 15-20 FPS updates
                        # This cuts Streamlit virtual DOM redraw thrashing by 60%, allowing CPU to focus on Ollama
                        if now - last_render_time > 0.075 or "\n\n" in full_reply[-4:]:
                            response_container.markdown(full_reply + "▌")
                            last_render_time = now

                    response_container.markdown(full_reply)

            # Clear temporary in-progress tracking and persist full response
            st.session_state.pop("in_progress_reply", None)
            st.session_state["messages"].append({"role": "assistant", "content": full_reply})
            if selected_prompt:
                st.rerun()

    # -------------------------------------------------------------------------
    # Tab 2: Deep Recon & Topology
    # -------------------------------------------------------------------------
    with tab_recon:
        st.markdown("### 🔬 Host Profiling & Network Topology")
        st.caption("Deep-level reconnaissance extracted from service banners, OS fingerprints, and network discovery.")

        hosts_list = recon.get("hosts", [])
        if not hosts_list:
            st.info("No structured host reconnaissance detected in current scan.")
        else:
            h_ctrl1, h_ctrl2 = st.columns([3, 1])
            with h_ctrl1:
                host_query = st.text_input("🔍 Filter Hosts by IP, Hostname, OS, or Port", placeholder="e.g. 192.168, Linux, Apache, ssh, 22...", key="host_search_input")
            with h_ctrl2:
                expand_hosts = st.checkbox("Expand All Cards", value=True, key="expand_hosts_chk")

            filtered_hosts = []
            for h in hosts_list:
                if not host_query:
                    filtered_hosts.append(h)
                    continue
                q = host_query.lower()
                m_ip = q in h.get("ip", "").lower()
                m_os = q in h.get("os", "").lower()
                m_names = any(q in name.lower() for name in h.get("hostnames", []))
                m_ports = any(q in str(p).lower() for p in h.get("open_ports", []))
                if m_ip or m_os or m_names or m_ports:
                    filtered_hosts.append(h)

            st.markdown(f"<span style='color: #00ff9d; font-family: monospace; font-size: 0.85em;'>● Showing {len(filtered_hosts)} of {len(hosts_list)} Profiled Host(s)</span>", unsafe_allow_html=True)
            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

            for idx, host in enumerate(filtered_hosts):
                ip = host.get("ip", "Unknown")
                hostnames = ", ".join(host.get("hostnames", [])) or "None detected"
                os_name = host.get("os", "Unknown OS")
                mac = host.get("mac", "N/A")
                vendor = host.get("vendor", "N/A")
                hops = host.get("traceroute_hops", "N/A")
                open_ports = host.get("open_ports", [])

                with st.expander(f"🖥️ Host {idx+1}: {ip} ({hostnames})", expanded=expand_hosts):
                    r_col1, r_col2, r_col3, r_col4 = st.columns(4)
                    with r_col1:
                        st.markdown(f"**IP Address:** `{ip}`")
                        st.markdown(f"**Status:** `UP`")
                    with r_col2:
                        st.markdown(f"**OS Detected:** `{os_name}`")
                        st.markdown(f"**Traceroute Hops:** `{hops}`")
                    with r_col3:
                        st.markdown(f"**MAC Address:** `{mac}`")
                        st.markdown(f"**Hardware Vendor:** `{vendor}`")
                    with r_col4:
                        st.markdown(f"**Open Ports:** `{len(open_ports)}`")
                        st.markdown(f"**Hostnames:** `{hostnames}`")

                    if open_ports:
                        st.markdown("##### Exposed Services & Ports")
                        if isinstance(open_ports[0], dict):
                            st.dataframe(
                                [
                                    {
                                        "Port": f"{p.get('protocol', 'tcp').upper()}/{p.get('port')}",
                                        "Service": p.get("service", "unknown"),
                                        "Product": p.get("product", ""),
                                        "Version": p.get("version", ""),
                                        "Scripts Executed": p.get("scripts_count", 0)
                                    }
                                    for p in open_ports
                                ],
                                width="stretch"
                            )
                        else:
                            st.write(open_ports)

                    # Hostscripts output
                    host_scripts = host.get("host_scripts", [])
                    if host_scripts:
                        st.markdown("##### Host Reconnaissance Scripts")
                        for s in host_scripts:
                            st.code(s, language="text")

    # -------------------------------------------------------------------------
    # Tab 3: Findings & Risk Matrix
    # -------------------------------------------------------------------------
    with tab_findings:
        st.markdown("### 📊 Identified Vulnerabilities & Exposures")
        st.caption("Normalized vulnerability findings with CVSS scores and technical remediation guidance.")

        # One-Click Executive Audit Dossier Export
        last_ai_note = st.session_state["messages"][-1]["content"] if st.session_state["messages"] and st.session_state["messages"][-1]["role"] == "assistant" else ""
        html_dossier = generate_executive_html_dossier(
            scan_data=parsed_scan,
            user_profile=user,
            ai_summary=last_ai_note
        )
        st.download_button(
            label="📄 Download Complete Executive Audit Dossier (Printable HTML / PDF)",
            data=html_dossier,
            file_name=f"VAPT_Executive_Dossier_{str(metadata.get('target', 'Network')).replace('/', '_')}.html",
            mime="text/html",
            type="primary",
            width="stretch",
            help="Generate a self-contained, printable client audit dossier with CVSS matrix, host cartography, and remediation commands."
        )
        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

        if not findings:
            st.info("No vulnerabilities or issues identified in this scan.")
        else:
            f_ctrl1, f_ctrl2 = st.columns([2, 2])
            with f_ctrl1:
                find_query = st.text_input("🔍 Search Findings (CVE, Title, or Component)", placeholder="e.g. CVE-2021, Apache, SSH, RCE...", key="find_search_input")
            with f_ctrl2:
                all_sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                selected_sevs = st.multiselect("Filter by Severity Level", options=all_sevs, default=all_sevs, key="sev_multiselect")

            filtered_findings = []
            for f in findings:
                sev = f.get("severity", "MEDIUM")
                if sev not in selected_sevs:
                    continue
                if find_query:
                    q = find_query.lower()
                    m_title = q in f.get("title", "").lower()
                    m_cve = q in f.get("cve", "").lower()
                    m_comp = q in f.get("affected_component", "").lower()
                    m_desc = q in f.get("description", "").lower()
                    if not (m_title or m_cve or m_comp or m_desc):
                        continue
                filtered_findings.append(f)

            st.markdown(f"<span style='color: #00ff9d; font-family: monospace; font-size: 0.85em;'>● Showing {len(filtered_findings)} of {len(findings)} Risk Finding(s)</span>", unsafe_allow_html=True)
            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

            for idx, f in enumerate(filtered_findings):
                sev = f.get("severity", "MEDIUM")
                color_map = {
                    "CRITICAL": "#da3633",
                    "HIGH": "#d29922",
                    "MEDIUM": "#0096c7",
                    "LOW": "#00b4d8"
                }
                border_color = color_map.get(sev, "#8b949e")

                st.markdown(
                    f"""
                    <div style="border-left: 5px solid {border_color}; background-color: #0d121c; padding: 16px 20px; border-radius: 6px; margin-bottom: 14px; border-top: 1px solid rgba(0,150,199,0.15); border-right: 1px solid rgba(0,150,199,0.15); border-bottom: 1px solid rgba(0,150,199,0.15); box-shadow: 0 4px 12px rgba(0,0,0,0.4);">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <h4 style="margin: 0; color: #ffffff; font-family: monospace;">#{idx+1} {f.get('title')}</h4>
                            <span style="background-color: {border_color}; color: #ffffff; padding: 3px 12px; border-radius: 12px; font-weight: bold; font-size: 0.8em; letter-spacing: 0.5px;">{sev}</span>
                        </div>
                        <div style="margin-top: 8px; color: #8b9bb4; font-size: 0.85em;">
                            <strong>Component:</strong> <code style="color: #00e5ff;">{f.get('affected_component')}</code> | 
                            <strong>CVE:</strong> <code style="color: #00b4d8;">{f.get('cve')}</code> | 
                            <strong>CVSS:</strong> <code style="color: #ffffff;">{f.get('cvss')}</code> |
                            <strong>Check Type:</strong> {'🔒 Privileged Audit' if f.get('authenticated_check') else '🌐 Perimeter Discovery'}
                        </div>
                        <p style="margin-top: 10px; color: #d8e2ec; font-size: 0.95em;">{f.get('description')}</p>
                        <div style="background-color: #06090e; padding: 12px; border-radius: 6px; border: 1px solid rgba(0, 150, 199, 0.3); margin-top: 8px;">
                            <span style="color: #00b4d8; font-weight: bold;">Remediation Directives:</span> 
                            <span style="color: #d8e2ec;">{f.get('remediation', 'N/A')}</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

    # -------------------------------------------------------------------------
    # Tab 4: Raw Intelligence Data
    # -------------------------------------------------------------------------
    with tab_raw:
        st.markdown("### 📜 Raw & Normalized Scan Intelligence")
        with st.expander("Normalized Scan Data Schema (JSON)", expanded=True):
            st.json(parsed_scan)

        with st.expander("Raw Ingested File Contents", expanded=False):
            st.code(st.session_state.get("loaded_scan_content", "No file loaded."), language="text")


# -----------------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------------
if not st.session_state.get("authenticated") or not st.session_state.get("user_profile"):
    render_login_screen()
else:
    render_authenticated_dashboard(st.session_state["user_profile"])
