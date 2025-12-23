import config
import vcd_reader
import simulation
import html_view
import webbrowser

def main():
    # 1. Setup
    cfg = config.load_config()
    
    # 2. Extract Data
    print("⏳ Extracting signals...")
    raw_trace = vcd_reader.extract_trace(cfg["vcd_path"], cfg["signal_map"])
    
    # 3. Simulate Pipeline
    print(" Simulating pipeline logic...")
    sim_result = simulation.process_logic(raw_trace)
    
    # 4. Render HTML
    print("🎨 Generating HTML...")
    html_str = html_view.generate_html(sim_result)
    
    # 5. Save & Open
    output_file = "pipeline_vis.html"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_str)
        
    print(f"✅ Done! Opening {output_file}...")
    webbrowser.open(output_file)

if __name__ == "__main__":
    main()