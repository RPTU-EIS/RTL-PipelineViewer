import argparse
import json
import os
import sys

def load_config():
    # 1. Parse Arguments
    parser = argparse.ArgumentParser(description="RISC-V Pipeline Visualizer")
    parser.add_argument("vcd_file", nargs='?', default=None, help="Path to VCD file")
    parser.add_argument("-c", "--config", default="pipeline", help="JSON config name")
    args = parser.parse_args()

    # 2. Resolve VCD Path
    vcd_file = args.vcd_file
    if not vcd_file:
        print("❌ Error: No VCD file provided.")
        sys.exit(1)
    if not vcd_file.lower().endswith(".vcd"):
        vcd_file += ".vcd"
    
    # 3. Resolve JSON Config Path
    config_input = args.config
    if not config_input.endswith(".json"):
        config_input += ".json"
    
    if os.path.exists(config_input):
        config_path = config_input
    elif os.path.exists(os.path.join("configs", config_input)):
        config_path = os.path.join("configs", config_input)
    else:
        config_path = config_input # Let it fail naturally later if missing

    # 4. Load & Parse JSON
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            signal_map = json.load(f)
    except Exception as e:
        print(f"❌ Error loading config: {e}")
        sys.exit(1)

    # 5. Expand Templates (REG_{i})
    if "REG_TEMPLATE" in signal_map:
        templ = signal_map.pop("REG_TEMPLATE")
        for i in range(32):
            key = f"x{i}"
            if isinstance(templ, list):
                signal_map[key] = [s.replace("{i}", str(i)) for s in templ]
            else:
                signal_map[key] = [str(templ).replace("{i}", str(i))]

    return {
        "vcd_path": vcd_file,
        "signal_map": signal_map
    }