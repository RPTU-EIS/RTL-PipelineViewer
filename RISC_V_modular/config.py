import argparse
import json
import os
import sys

def load_config():
    parser = argparse.ArgumentParser(description="Generate an HTML animation for a pipelined RISC-V processor from a VCD file.")
    parser.add_argument("vcd_file", nargs='?', default=None, help="Optional: Path to the VCD file to process.")
    parser.add_argument("-c", "--config", default="pipeline", help="Optional: Name of the JSON config file (default: pipeline).")
    args = parser.parse_args()

    # --- Resolve VCD File ---
    vcd_file = args.vcd_file
    if vcd_file:
        if not vcd_file.lower().endswith(".vcd") and os.path.exists(vcd_file + ".vcd"):
            vcd_file = vcd_file + ".vcd"
        if not os.path.exists(vcd_file):
            print(f"❌ Error: VCD file '{vcd_file}' not found.")
            sys.exit(1)
    else:
        # Interactive prompt if not provided
        while True:
            vcd_file = input("Enter the name of the VCD file (e.g., dump.vcd): ").strip()
            if not vcd_file.lower().endswith(".vcd") and os.path.exists(vcd_file + ".vcd"):
                vcd_file = vcd_file + ".vcd"
            if os.path.exists(vcd_file):
                break
            else:
                print(f"❌ File '{vcd_file}' not found. Please try again.\n")

    # --- Resolve Config File ---
    config_input = args.config
    if not config_input.endswith(".json"):
        config_input += ".json"
    
    if os.path.exists(config_input):
        config_file = config_input
    elif os.path.exists(os.path.join("configs", config_input)):
        config_file = os.path.join("configs", config_input)
    elif os.path.exists(os.path.join("configs", os.path.basename(config_input))):
        config_file = os.path.join("configs", os.path.basename(config_input))
    else:
        config_file = config_input 

    print(f"⚙️  Using Configuration: {config_file}")

    # --- Load JSON ---
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
            "vcd_path": vcd_file,
            "signal_map": data,
            "config_path": config_file
        }

    except Exception as e:
        print(f"❌ Error loading config: {e}")
        sys.exit(1)