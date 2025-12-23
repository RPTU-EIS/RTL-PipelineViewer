import webbrowser  # <--- FIX: Added this missing import
from . import config
from . import vcd_reader
from . import simulation
from . import html_view

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
    
    # 5. Save & Open
    output_file = "pipeline_animation.html"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_str)
        
    print(f"✅ Successfully generated '{output_file}'.")
    
    # This line caused the error before because the import was missing
    webbrowser.open_new_tab(output_file)

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