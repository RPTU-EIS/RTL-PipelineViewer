import argparse
import json
import os
import sys

def load_config():
    parser = argparse.ArgumentParser(description="Generate an HTML animation for a pipelined RISC-V processor from a VCD file.")
    parser.add_argument("vcd_file", nargs='?', default=None, help="Optional: Path to the VCD file to process.")
    parser.add_argument("-c", "--config", default="pipeline", help="Optional: Name of the JSON config file (default: pipeline).")
    args = parser.parse_args()

    vcd_file = args.vcd_file
    vcd_dir = "examples" # Folder where examples live

    # --- INTERACTIVE SELECTION MODE ---
    if vcd_file is None:
        print("\nℹ️  No VCD file provided.")
        
        # 1. Scan the examples folder
        available_files = []
        if os.path.exists(vcd_dir):
            available_files = [f for f in os.listdir(vcd_dir) if f.endswith(".vcd")]
        
        # 2. Display options
        if available_files:
            print(f"📂 Found the following examples in '{vcd_dir}/':")
            for idx, f in enumerate(available_files, 1):
                print(f"   [{idx}] {f}")
            print("   [Other] Type a path manually")
        
        # 3. Ask user
        while True:
            user_input = input("\nSelect a file (enter number or name): ").strip()
            
            if not user_input:
                print("❌ Input cannot be empty.")
                continue
            
            # Check if user typed a number (1, 2, etc.)
            if user_input.isdigit():
                idx = int(user_input) - 1
                if 0 <= idx < len(available_files):
                    vcd_file = available_files[idx]
                    break
                else:
                    print("❌ Invalid number. Please try again.")
            else:
                # User typed a filename manually
                vcd_file = user_input
                break

    # --- RESOLVE PATHS ---
    # Smart Search Logic
    possible_paths = [
        vcd_file,                                      # 1. Exact path
        os.path.join(vcd_dir, vcd_file),               # 2. Inside examples/
        vcd_file + ".vcd",                             # 3. Add extension
        os.path.join(vcd_dir, vcd_file + ".vcd")       # 4. Inside examples/ + extension
    ]

    final_vcd_path = None
    for p in possible_paths:
        if os.path.exists(p):
            final_vcd_path = p
            break

    if not final_vcd_path:
        print(f"\n❌ Error: Could not find '{vcd_file}'")
        print(f"   Checked: {possible_paths}")
        sys.exit(1)
        
    print(f"\n📂 Processing: {final_vcd_path}")

    # --- RESOLVE JSON CONFIG ---
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

    # --- LOAD JSON ---
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
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