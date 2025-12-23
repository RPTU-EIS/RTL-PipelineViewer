import argparse
import json
import os
import sys

def load_config():
    parser = argparse.ArgumentParser(description="Generate an HTML animation for a pipelined RISC-V processor from a VCD file.")
    parser.add_argument("vcd_file", nargs='?', default=None, help="Optional: Path to the VCD file to process.")
    parser.add_argument("-c", "--config", default="pipeline", help="Optional: Name of the JSON config file (default: pipeline).")
    args = parser.parse_args()

    # --- 1. Resolve VCD File ---
    vcd_file = args.vcd_file

    # FIX: If no argument provided, ask the user interactively
    if vcd_file is None:
        print("ℹ️  No VCD file provided in command line.")
        while True:
            user_input = input("Please enter the VCD filename (e.g., task1.vcd): ").strip()
            if user_input:
                vcd_file = user_input
                break
            print("❌ Input cannot be empty.")

    # 2. Define the default folder (Relative to where you run the script)
    # Since you run from root, "examples" points to the folder outside src
    vcd_dir = "examples"

    # 3. Smart Search Logic
    possible_paths = [
        vcd_file,                                      # 1. Check current folder (Root)
        os.path.join(vcd_dir, vcd_file),               # 2. Check examples/ folder
        vcd_file + ".vcd",                             # 3. Check current + .vcd
        os.path.join(vcd_dir, vcd_file + ".vcd")       # 4. Check examples/ + .vcd
    ]

    final_vcd_path = None
    for p in possible_paths:
        if os.path.exists(p):
            final_vcd_path = p
            break

    if not final_vcd_path:
        print(f"❌ Error: Could not find '{vcd_file}' in the current directory or inside '{vcd_dir}/'.")
        print(f"   Checked locations: {possible_paths}")
        sys.exit(1)
        
    print(f"📂 Processing: {final_vcd_path}")

    # --- 4. Resolve Config File ---
    config_input = args.config
    if not config_input.endswith(".json"):
        config_input += ".json"
    
    # Since 'configs' is also in the root, simple paths work
    if os.path.exists(config_input):
        config_file = config_input
    elif os.path.exists(os.path.join("configs", config_input)):
        config_file = os.path.join("configs", config_input)
    elif os.path.exists(os.path.join("configs", os.path.basename(config_input))):
        config_file = os.path.join("configs", os.path.basename(config_input))
    else:
        config_file = config_input # Let it fail in the try-block below

    print(f"⚙️  Using Configuration: {config_file}")

    # --- 5. Load JSON ---
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # Expand Templates (REG_{i})
        if "REG_TEMPLATE" in data:
            templ = data.pop("REG_TEMPLATE")
            for i in range(32):
                key = f"x{i}"
                if isinstance(templ, list):
                    data[key] = [s.replace("{i}", str(i)) for s in templ]
                else:
                    data[key] = [str(templ).replace("{i}", str(i))]
        
        return {
            "vcd_path": final_vcd_path,
            "signal_map": data,
            "config_path": config_file
        }

    except Exception as e:
        print(f"❌ Error loading config: {e}")
        sys.exit(1)