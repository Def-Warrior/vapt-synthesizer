import os
import time
from playwright.sync_api import sync_playwright

def record_vapt_synthesizer_demo():
    output_dir = os.path.realpath("/home/kali/Projects/vapt-synthesizer/demo")
    os.makedirs(output_dir, exist_ok=True)
    temp_rec_dir = os.path.join(output_dir, "temp_rec")
    os.makedirs(temp_rec_dir, exist_ok=True)

    final_webm_path = os.path.join(output_dir, "agentic_vapt_synthesizer_walkthrough.webm")
    final_mp4_path = os.path.join(output_dir, "agentic_vapt_synthesizer_walkthrough.mp4")

    print("[*] Launching Playwright browser with 1280x768 video recording...")
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--hide-scrollbars=false",
                "--force-device-scale-factor=1"
            ]
        )

        context = browser.new_context(
            viewport={"width": 1280, "height": 768},
            record_video_dir=temp_rec_dir,
            record_video_size={"width": 1280, "height": 768}
        )

        page = context.new_page()

        print("[*] Step 1: Navigating to Agentic VAPT Synthesizer at http://localhost:8501...")
        page.goto("http://localhost:8501", wait_until="networkidle", timeout=30000)
        time.sleep(3)

        # -------------------------------------------------------------
        # 1. Login Screen Demonstration
        # -------------------------------------------------------------
        print("[*] Step 2: Showcasing PBKDF2 Air-Gap Analyst Authentication Screen...")
        time.sleep(2)

        # Click Authenticate
        auth_btn = page.locator("button:has-text('Authenticate Terminal Session')")
        if auth_btn.count() > 0:
            print("[*] Authenticating as Lead Penetration Tester (Alex Vance)...")
            auth_btn.first.click()
            time.sleep(4)
        else:
            print("[!] Already authenticated.")

        page.wait_for_load_state("networkidle")
        time.sleep(2)

        # -------------------------------------------------------------
        # 2. Main Dashboard & Tactical Cartography Header
        # -------------------------------------------------------------
        print("[*] Step 3: Viewing Tactical Recon Cartography Header & Clearance Status...")
        time.sleep(3)

        # -------------------------------------------------------------
        # 3. Explore Tab 2: Deep Recon & Topology
        # -------------------------------------------------------------
        print("[*] Step 4: Exploring Tab 2: Deep Recon & Network Topology Cartography...")
        tab_recon = page.locator("button[role='tab']:has-text('Deep Recon')")
        if tab_recon.count() > 0:
            tab_recon.first.click()
            time.sleep(2.5)

            # Smoothly scroll down to showcase multi-host topology cards
            print("[*] Scrolling discovered hosts & OS fingerprinting cards...")
            for scroll_pos in [280, 560, 840, 1100]:
                page.evaluate(f"window.scrollTo({{ top: {scroll_pos}, behavior: 'smooth' }});")
                time.sleep(1.2)
            time.sleep(1.5)
            # Scroll back up smoothly
            page.evaluate("window.scrollTo({ top: 0, behavior: 'smooth' });")
            time.sleep(2)

        # -------------------------------------------------------------
        # 4. Explore Tab 3: Findings & Risk Matrix
        # -------------------------------------------------------------
        print("[*] Step 5: Exploring Tab 3: Findings & CVSS Risk Matrix...")
        tab_findings = page.locator("button[role='tab']:has-text('Findings')")
        if tab_findings.count() > 0:
            tab_findings.first.click()
            time.sleep(2.5)

            # Smoothly scroll down through vulnerability findings & CVSS badges
            print("[*] Scrolling vulnerability findings & remediation cards...")
            for scroll_pos in [300, 650, 950]:
                page.evaluate(f"window.scrollTo({{ top: {scroll_pos}, behavior: 'smooth' }});")
                time.sleep(1.2)
            time.sleep(1.5)
            page.evaluate("window.scrollTo({ top: 0, behavior: 'smooth' });")
            time.sleep(2)

        # -------------------------------------------------------------
        # 5. Ingestion Switching: Select Authenticated CIS Scan
        # -------------------------------------------------------------
        print("[*] Step 6: Demonstrating Multi-Scanner Ingestion (CIS Benchmark Audit)...")
        cis_radio = page.locator("label:has-text('Authenticated Audit (CIS Benchmark JSON)')")
        if cis_radio.count() > 0:
            cis_radio.first.click()
            time.sleep(3)

            # Switch back to Deep Recon Nmap XML
            nmap_radio = page.locator("label:has-text('Deep Recon (Multi-Host Nmap XML)')")
            if nmap_radio.count() > 0:
                nmap_radio.first.click()
                time.sleep(3)

        # -------------------------------------------------------------
        # 6. Tab 1: Conversational SOC Assistant & Dynamic Gemini Terminal
        # -------------------------------------------------------------
        print("[*] Step 7: Exploring Tab 1: Conversational SOC Assistant & Gemma 4 Streaming...")
        tab_chat = page.locator("button[role='tab']:has-text('Cyber AI Assistant')")
        if tab_chat.count() > 0:
            tab_chat.first.click()
            time.sleep(2.5)

        # Trigger quick directive
        directive_btn = page.locator("button:has-text('🚨 Critical Vulnerabilities')")
        if directive_btn.count() > 0:
            print("[*] Triggering Quick Directive: Critical Vulnerabilities...")
            directive_btn.first.click()
            time.sleep(3)
        else:
            term_input = page.locator("input[aria-label='Terminal Command Line']").first
            if term_input.count() > 0:
                term_input.fill("Analyze critical exposures across all discovered hosts.")
                run_btn = page.locator("button:has-text('⚡ Run')").first
                run_btn.click()
                time.sleep(3)

        # Wait for live streaming tokens
        print("[*] Capturing real-time token streaming from Gemma 4...")
        time.sleep(12)

        # Smooth scroll down to reveal dynamic terminal at the end of the chat
        print("[*] Revealing dynamic Gemini Terminal pinned at end of conversation...")
        page.evaluate("window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });")
        time.sleep(3)

        # Type follow-up in dynamic terminal
        bottom_input = page.locator("input[aria-label='Terminal Command Line']").last
        if bottom_input.count() > 0 and bottom_input.is_visible():
            print("[*] Typing interactive query in dynamic terminal...")
            bottom_input.click()
            bottom_input.fill("Mitigate OpenSSH 8.2p1 regreSSHion exposure.")
            time.sleep(1.5)
            run_btn_bot = page.locator("button:has-text('⚡ Run')").last
            if run_btn_bot.count() > 0:
                run_btn_bot.click()
                print("[*] Executed terminal command. Streaming follow-up response...")
                time.sleep(10)

        # -------------------------------------------------------------
        # 7. Tab 4: Raw Intelligence Data & Dossier Export
        # -------------------------------------------------------------
        print("[*] Step 8: Exploring Tab 4: Raw Intelligence & Dossier Export...")
        tab_raw = page.locator("button[role='tab']:has-text('Raw Intelligence')")
        if tab_raw.count() > 0:
            tab_raw.first.click()
            time.sleep(3)

        # Verify Executive Dossier Download button
        dossier_btn = page.locator("button:has-text('Download Executive Dossier')")
        if dossier_btn.count() > 0:
            print("[*] Executive Dossier Export confirmed.")
        time.sleep(3)

        # -------------------------------------------------------------
        # Finalize and Save Video
        # -------------------------------------------------------------
        print("[*] Finalizing recording and saving video file...")
        video_obj = page.video
        context.close()
        video_obj.save_as(final_webm_path)
        browser.close()

    print(f"[+] Video successfully saved: {final_webm_path}")
    print(f"[+] Size: {os.path.getsize(final_webm_path)} bytes")

    # Clean up temp recording directory
    import shutil
    shutil.rmtree(temp_rec_dir, ignore_errors=True)

    # Convert to MP4 format with ffmpeg if available
    try:
        import subprocess
        print("[*] Transcoding copy to standard MP4 (H.264) container...")
        subprocess.run([
            "/home/kali/.cache/ms-playwright/ffmpeg-1013/ffmpeg-linux",
            "-y",
            "-i", final_webm_path,
            "-c:v", "libx264",
            "-pix_fmt", "yuv420p",
            "-preset", "fast",
            "-crf", "22",
            final_mp4_path
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(final_mp4_path) and os.path.getsize(final_mp4_path) > 0:
            print(f"[+] MP4 version also created: {final_mp4_path} ({os.path.getsize(final_mp4_path)} bytes)")
    except Exception as e:
        print(f"[!] MP4 transcoding notice: {e} (WebM is fully functional)")

    return final_webm_path

if __name__ == "__main__":
    record_vapt_synthesizer_demo()
