import sys
import os
import platform
import shutil
import subprocess
import webbrowser
from . import config
from . import vcd_reader
from . import simulation
from . import html_view

def open_file_in_browser(file_path):
    """
    Opens the HTML file in the default browser, regardless of the OS (Windows/Linux/WSL).
    """
    # Check if we are running in WSL (Windows Subsystem for Linux)
    is_wsl = "microsoft-standard" in platform.uname().release
    
    # CASE 1: WSL (Windows Subsystem for Linux)
    if is_wsl:
        # Try 'wslview' first (requires wslu installed)
        if shutil.which("wslview"):
            subprocess.run(["wslview", file_path])
            return
        # Try 'explorer.exe' (Built-in Windows tool accessible from WSL)
        elif shutil.which("explorer.exe"):
            subprocess.run(["explorer.exe", file_path])
            return

    # CASE 2: Standard Windows, Mac, or Desktop Linux
    # Python's webbrowser module works well here
    try:
        # Convert to absolute path to be safe
        abs_path = os.path.abspath(file_path)
        # On some Linux systems, we need 'file://' prefix
        if platform.system() == "Linux":
            abs_path = "file://" + abs_path
            
        webbrowser.open_new_tab(abs_path)
        
    except Exception as e:
        print(f"⚠️  Could not open browser automatically: {e}")
        print(f"👉 Please open '{file_path}' manually.")

def main():
    # 1. Setup
    cfg = config.load_config()
    
    # 2. Extract Data
    raw_trace = vcd_reader.extract_trace(cfg["vcd_path"], cfg["signal_map"])
    
    # 3. Simulate Pipeline
    print("🧠 Simulating pipeline logic...")
    sim_result = simulation.process_trace(raw_trace)
    
    # 4. Render HTML
    print("🎨 Generating HTML...")
    html_str = html_view.generate_html(sim_result)
    
    # 5. Save
    output_file = "pipeline_animation.html"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_str)
        
    print(f"✅ Successfully generated '{output_file}'.")
    
    # 6. Open Automatically (Universal Method)
    open_file_in_browser(output_file)

    # Missing Signals Summary
    all_missing = [k for v in sim_result["missing_report"].values() for k in v]
    print("\n" + "="*50)
    print(" VCD Signal Analysis Summary")
    print("="*50)
    if not all_missing:
        print("✅ Success! All required signals were found.")
    else:
        print(f"⚠️  Warning: {len(all_missing)} required signal(s) were not found.")
        for k in all_missing[:5]: print(f"    - '{k}'")
        if len(all_missing) > 5: print("    - ...")
    print("="*50 + "\n")



if __name__ == "__main__":
    main()