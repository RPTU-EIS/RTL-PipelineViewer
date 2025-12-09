
from vcdvcd import VCDVCD
import pandas as pd
from collections import defaultdict
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32
import os
import re
import json 
import webbrowser
import sys
import argparse 
import pprint

# Initialize Capstone for RISC-V 32-bit disassembly
md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
md.detail = True
missing_signals_by_label = {}



#  New functions for loading config files ---
def load_signal_map(config_path: str) -> dict:
    """Load a JSON signal map and expand templates."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Signal map must be an object/dict at the top level.")
    return expand_templates_in_signal_map(data)

def expand_templates_in_signal_map(signal_map: dict) -> dict:
    """Expand REG_TEMPLATE → REG_0..REG_31."""
    out = dict(signal_map)  # shallow copy
    if "REG_TEMPLATE" in out:
        templ = out.pop("REG_TEMPLATE")
        for i in range(32):
            key = f"x{i}" # Use 'x0', 'x1', etc. as the key
            if isinstance(templ, list):
                out[key] = [s.replace("{i}", str(i)) for s in templ]
            else: # Handle if template is a single string
                out[key] = [str(templ).replace("{i}", str(i))]
    return out


# --- Configuration ---
# VCD_FILE = "dump5.vcd" / Now we introduce the file
CLOCK_SIGNAL = None 

parser = argparse.ArgumentParser(description="Generate an HTML animation for a pipelined RISC-V processor from a VCD file.")
parser.add_argument("vcd_file", nargs='?', default=None, help="Optional: Path to the VCD file to process.")

args = parser.parse_args()



VCD_FILE = args.vcd_file

if VCD_FILE:
    # 🟢 Automatically add .vcd if missing and file exists
    if not VCD_FILE.lower().endswith(".vcd") and os.path.exists(VCD_FILE + ".vcd"):
        VCD_FILE = VCD_FILE + ".vcd"

    # 🟠 If still not found, print a clear message and exit
    if not os.path.exists(VCD_FILE):
        print(f"❌ Error: VCD file '{VCD_FILE}' not found.")
        print("Hint: make sure the file exists in the same directory or add the full path.")
        sys.exit(1)
else:
    # 🟣 No argument given → interactive prompt
    while True:
        VCD_FILE = input("Enter the name of the VCD file (e.g., dump.vcd): ").strip()
        if not VCD_FILE.lower().endswith(".vcd") and os.path.exists(VCD_FILE + ".vcd"):
            VCD_FILE = VCD_FILE + ".vcd"
        if os.path.exists(VCD_FILE):
            print(f"✅ Found VCD file: {VCD_FILE}")
            break
        else:
            print(f"❌ File '{VCD_FILE}' not found. Please try again.\n")



try:
    vcd = VCDVCD(VCD_FILE, store_tvs=True)
except FileNotFoundError:
    print(f"❌ Error: VCD file '{VCD_FILE}' not found. Please check the file is in the same directory.")
    exit()


# --- START: New Organized Terminal Output ---
print("\n" + "="*50)
print(" VCD to Pipelined HTML Animation Generator")
print("="*50)
print(f"📂 VCD File:         {VCD_FILE}")
print(f"📊 Total Signals:    {len(vcd.signals)}")

print("\n" + "-"*50)
print(" Step 1: Mapping Signals...")
print("-" * 50)


# --- Utility to resolve signals from multiple fallback paths ---
def resolve_signal(signal_names, vcd):
    if isinstance(signal_names, str):
        signal_names = [signal_names]
    for name in signal_names:
        if name in vcd.signals:
            return name
    return None

def resolve_signals_with_log(signal_dict, vcd, label="", vcd_filename="(unknown)"):
    resolved = {}
    print(f"\n🔎 Looking for {label} signals:")
    found, missing = 0, 0
    all_vcd_signals = list(vcd.signals)  

    for key, candidates in signal_dict.items():
        selected = resolve_signal(candidates, vcd)
        resolved[key] = selected
        if selected:
            print(f"✅ {key} → {selected}")
            found += 1
        else:
            print(f"⚠️ {key} not found in VCD file: {vcd_filename}")
            # Substring-based suggestions (case-insensitive)
            suggestions = [
                sig for sig in all_vcd_signals
                if key.lower() in sig.lower()
            ]

            if suggestions:
                print(f"   🔍 Possible signals found in VCD that resemble '{key}':")
                for s in suggestions[:5]:  # Limit to 5 suggestions
                    print(f"       • {s}")
            else:
                print(f"   ℹ️ No similar signals found for '{key}' in VCD.")

            missing += 1

    print(f"🧾 {label} summary: {found} found, {missing} missing\n")
    if label not in missing_signals_by_label:
        missing_signals_by_label[label] = []
    for key, selected in resolved.items():
        if not selected:
            missing_signals_by_label[label].append(key)
    return resolved



# --- Hardcoded Config Path ---
CONFIG_FILE = "configs/pipeline_extension.json"

# --- Load Signal Map ---
try:
    print(f"\nAttempting to load signal map from: {CONFIG_FILE}")
    all_signals_raw = load_signal_map(CONFIG_FILE)
    print(f"✅ Successfully loaded '{CONFIG_FILE}'")

    # Organize signals from the loaded file
    stage_signals_raw = {k.replace("STAGE_", ""): v for k, v in all_signals_raw.items() if k.startswith("STAGE_")}
    instruction_signals_raw = {k.replace("INSTR_", ""): v for k, v in all_signals_raw.items() if k.startswith("INSTR_")}

    stall_signals_raw = {k.replace("STALL_", ""): v for k, v in all_signals_raw.items() if k.startswith("STALL_")}
    control_signals_raw = {
        "branch_taken": all_signals_raw.get("BRANCH_TAKEN"),
        "branch_target": all_signals_raw.get("BRANCH_TARGET"),
        "flush_if": all_signals_raw.get("FLUSH_IF"),
        "flush_id": all_signals_raw.get("FLUSH_ID")
    }
    
    def to_camel(name: str) -> str:
        parts = name.lower().split('_')
        return parts[0] + ''.join(p.capitalize() for p in parts[1:])

    ex_signals_raw = {to_camel(k.replace("EX_", "")): v for k, v in all_signals_raw.items() if k.startswith("EX_")}
    mem_signals_raw = {  # keys become camelCase like the EX_* path above
        (lambda n: ''.join([n.split('_')[0].lower()] + [p.capitalize() for p in n.split('_')[1:]]))(k.replace("MEM_", "")) : v
        for k, v in all_signals_raw.items() if k.startswith("MEM_")
    }
    wb_signals_raw = {
        k.replace("WB_", "").lower(): v
        for k, v in all_signals_raw.items()
        if k.startswith("WB_")
    }
    hazard_signals_raw = {}
    for k, v in all_signals_raw.items():
        if not k.startswith("HAZARD_"):
            continue
        name = k.replace("HAZARD_", "")
        if "FORWARD" in name:
            hazard_signals_raw[to_camel(name)] = v
        else:
            hazard_signals_raw[name.lower()] = v
    register_signals_raw = {k: v for k, v in all_signals_raw.items() if k.startswith("x")}

except Exception as e:
    print(f"❌ Error: Failed to load the required config file '{CONFIG_FILE}'.")
    print(f"   Reason: {e}")
    print("   Please ensure the file exists and is a valid JSON.")
    sys.exit(1)





# Now, resolve the signals using the maps we either loaded or fell back to
stage_signals = resolve_signals_with_log(stage_signals_raw, vcd, "Stage", vcd_filename=VCD_FILE)
instruction_signals = resolve_signals_with_log(instruction_signals_raw, vcd, "Instruction", vcd_filename=VCD_FILE)
ex_signals = resolve_signals_with_log(ex_signals_raw, vcd, "EX", vcd_filename=VCD_FILE)
mem_signals = resolve_signals_with_log(mem_signals_raw, vcd, "MEM", vcd_filename=VCD_FILE)
stall_signals = resolve_signals_with_log(stall_signals_raw, vcd, "Stall", vcd_filename=VCD_FILE)
control_signals = resolve_signals_with_log(control_signals_raw, vcd, "Control")
wb_signals = resolve_signals_with_log(wb_signals_raw, vcd, "WB", vcd_filename=VCD_FILE)
hazard_signals = resolve_signals_with_log(hazard_signals_raw, vcd, "Hazard", vcd_filename=VCD_FILE)
register_signals = resolve_signals_with_log(register_signals_raw, vcd, "Register", vcd_filename=VCD_FILE)







output_html = "pipeline_animation.html" # Output filename for the animation HTML



# --- Auto-detect clock ---
if CLOCK_SIGNAL is None:
    candidates = [sig for sig in vcd.signals if "clk" in sig.lower() or "clock" in sig.lower()]
    if not candidates:
        raise RuntimeError("No clock signal found. Please specify CLOCK_SIGNAL.")
    CLOCK_SIGNAL = candidates[0]
print(f"Using clock signal: {CLOCK_SIGNAL}")

# --- Detect cycles ---
clock_tv = vcd[CLOCK_SIGNAL].tv
rising_edges = []
prev_val = '0'
for t, val in sorted(clock_tv, key=lambda x: x[0]):
    if prev_val == '0' and val == '1':
        rising_edges.append(t)
    prev_val = val
num_cycles = len(rising_edges)
print(f"Detected {num_cycles} clock cycles.")




def extract_signal_at_cycles(signal_name, default_val=None, base=10):
    
    
    tv_sorted = sorted(vcd[signal_name].tv, key=lambda x: x[0])
    values = []
    last_val = None
    tv_idx = 0
    for rise_time in rising_edges:
        while tv_idx < len(tv_sorted) and tv_sorted[tv_idx][0] <= rise_time:
            last_val = tv_sorted[tv_idx][1]
            tv_idx += 1
        
        if last_val is not None and 'x' not in last_val.lower():
            try:
                if last_val.startswith('b'):
                    val = int(last_val[1:], 2)
                elif last_val.startswith('h'):
                    val = int(last_val[1:], 16)
                elif all(c in '01' for c in last_val):  # <-- NEW: plain binary string
                    val = int(last_val, 2)
                else:
                    val = int(last_val, base)

                values.append(val)
            except (ValueError, TypeError) as e:
                print(f"⚠️ Failed to parse value '{last_val}' for signal '{signal_name}' at cycle {rise_time}: {e}")
                values.append(default_val)
        else:
            print(f"⚠️ Skipping unknown or uninitialized value '{last_val}' for '{signal_name}' at cycle {rise_time}")
            values.append(default_val)
    return values



instr_vals = extract_signal_at_cycles("PipelinedRV32I.core.IDBarrier.io_outInstr_REG", default_val=0, base=2)



def safe_extract_signal(signal_dict, signal_name, default_val=0, base=2):
    if signal_name not in signal_dict:
        print(f"⚠️ Signal '{signal_name}' not found in VCD. Using default.")
        return [default_val] * num_cycles
    return extract_signal_at_cycles(signal_dict[signal_name], default_val, base)



# Helper to extract signal values at each rising edge
def extract_signals_group(signal_dict, default_val, base, store_to, postprocess_fn=None):
    for key, signal_name in signal_dict.items():
        values = extract_signal_at_cycles(signal_name, default_val=default_val, base=base)
        for cycle_idx, val in enumerate(values):
            if postprocess_fn:
                val = postprocess_fn(val)
            store_to[cycle_idx][key] = val

mem_values_by_cycle = [{} for _ in range(num_cycles)]
extract_signals_group(mem_signals, default_val=None, base=2, store_to=mem_values_by_cycle)

# Delay MEM to line up with pipeline like you do for EX/WB/hazards
delayed_mem_values_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1, num_cycles):
    delayed_mem_values_by_cycle[i] = mem_values_by_cycle[i-1]

print(f"\n✅ List of available signals in VCD: {VCD_FILE}\n")
for signal in vcd.signals:
    print(signal)



# --- Extract Signal Data ---
ex_values_by_cycle = [{} for _ in range(num_cycles)]
extract_signals_group(ex_signals, default_val=None, base=2, store_to=ex_values_by_cycle)

opcode_values_by_cycle = [None] * num_cycles
if hazard_signals.get("opcode"):
    opcode_values_raw = extract_signal_at_cycles(hazard_signals["opcode"], default_val=None, base=2)
    for i, val in enumerate(opcode_values_raw):
        opcode_values_by_cycle[i] = val

wb_values_by_cycle = [{} for _ in range(num_cycles)]
extract_signals_group(wb_signals, default_val=None, base=2, store_to=wb_values_by_cycle)

hazard_data_raw_by_cycle = [{} for _ in range(num_cycles)]
extract_signals_group(hazard_signals, default_val=0, base=2, store_to=hazard_data_raw_by_cycle)

def postprocess_register(val):
    return f"0x{val:08x}" if isinstance(val, int) else '0x00000000'

register_values_by_cycle = [{} for _ in range(num_cycles)]
extract_signals_group(register_signals, default_val=0, base=16, store_to=register_values_by_cycle, postprocess_fn=postprocess_register)

stall_values_raw = [{} for _ in range(num_cycles)]
extract_signals_group(stall_signals, default_val=0, base=2, store_to=stall_values_raw)

control_values_raw = [{} for _ in range(num_cycles)]
extract_signals_group(control_signals, default_val=0, base=2, store_to=control_values_raw)






# --- Apply Delays for Correct Cycle Synchronization ---
delayed_instr_vals = [None] + instr_vals[:-1]

delayed_ex_values_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1, num_cycles):
    delayed_ex_values_by_cycle[i] = ex_values_by_cycle[i-1]

delayed_wb_values_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1, num_cycles):
    delayed_wb_values_by_cycle[i] = wb_values_by_cycle[i-1]

delayed_hazard_data_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1, num_cycles):
    delayed_hazard_data_by_cycle[i] = hazard_data_raw_by_cycle[i-1]

delayed_register_values_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1, num_cycles):
    delayed_register_values_by_cycle[i] = register_values_by_cycle[i-1]
if num_cycles > 0:
    delayed_register_values_by_cycle[0] = {f"x{i}": "0x00000000" for i in range(32)}

delayed_opcode_by_cycle_2c = [None] * num_cycles
for i in range(2, num_cycles):
    delayed_opcode_by_cycle_2c[i] = opcode_values_by_cycle[i-2]


stall_values_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1, num_cycles):
    stall_values_by_cycle[i] = stall_values_raw[i-1]
if num_cycles > 0:
    stall_values_by_cycle[0] = {}

control_values_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1,num_cycles):
    control_values_by_cycle[i] = control_values_raw[i-1]





def convert_hex_immediates_to_decimal(disasm: str) -> str:
    def replace_hex(match):
        hex_str = match.group(0)
        value = int(hex_str, 16)
        if value >= 0x800: value -= 0x1000
        return str(value)
    return re.sub(r'0x[0-9a-fA-F]+', replace_hex, disasm)

# New: Register read/write indicators


reg_highlight_data_by_cycle = []
opcodes_that_use_rs2 = {0x33, 0x23, 0x63}  # R-type, store, branch



for i in range(num_cycles):
    current_hazard_data = delayed_hazard_data_by_cycle[i]
    current_wb_data     = delayed_wb_values_by_cycle[i]

    rs1 = current_hazard_data.get("rs1_addr")
    rs2 = current_hazard_data.get("rs2_addr")
    rd  = current_wb_data.get("rd")
    raw_opcode = current_hazard_data.get("opcode")

    
    try:
        if isinstance(raw_opcode, str) and all(c in "01" for c in raw_opcode):
            opcode = int(raw_opcode, 2)
        elif isinstance(raw_opcode, int):
            opcode = raw_opcode
        else:
            opcode = int(str(raw_opcode), 10) 
    except (ValueError, TypeError):
        opcode = None

    rs2_final = rs2 if opcode in opcodes_that_use_rs2 else None

    reg_highlight_data_by_cycle.append({
        "id_rs1": rs1,
        "id_rs2": rs2_final,
        "wb_rd": rd
    })
   



# --- Collect PC → Instruction Hex and Disassemble ---
actual_pc_to_instr_raw = {}
actual_pc_to_instr_hex_display = {}
actual_pc_to_disassembled_instr = {}
for stage_name, pc_signal_name in stage_signals.items():
    instr_signal_name = instruction_signals.get(stage_name)
    if pc_signal_name not in vcd.signals or instr_signal_name not in vcd.signals: continue
    pc_tv = sorted(vcd[pc_signal_name].tv, key=lambda x: x[0])
    instr_tv = sorted(vcd[instr_signal_name].tv, key=lambda x: x[0])
    all_signal_times = sorted(list(set([t for t, _ in pc_tv] + [t for t, _ in instr_tv])))
    current_pc_val, current_instr_raw_val = None, None
    pc_idx, instr_idx = 0, 0
    for t in all_signal_times:
        while pc_idx < len(pc_tv) and pc_tv[pc_idx][0] <= t:
            try: current_pc_val = int(pc_tv[pc_idx][1], 2)    # <--- NEW: Parse as Binary
            except (ValueError, TypeError): current_pc_val = None
            pc_idx += 1
        while instr_idx < len(instr_tv) and instr_tv[instr_idx][0] <= t:
            current_instr_raw_val = instr_tv[instr_idx][1]
            instr_idx += 1
        if current_pc_val is not None and current_instr_raw_val is not None and 'x' not in current_instr_raw_val.lower():
            actual_pc_to_instr_raw[current_pc_val] = current_instr_raw_val
            instr_hex = ""
            try:
                if len(current_instr_raw_val) == 32 and all(c in '01' for c in current_instr_raw_val):
                    instr_hex = f"{int(current_instr_raw_val, 2):08x}"
                elif all(c in '0123456789abcdef' for c in current_instr_raw_val.lower()):
                    instr_hex = f"{int(current_instr_raw_val, 16):08x}"
            except (ValueError, TypeError): instr_hex = ""
            actual_pc_to_instr_hex_display[current_pc_val] = instr_hex
            if current_pc_val not in actual_pc_to_disassembled_instr and instr_hex:
                try:
                    instr_bytes = bytes.fromhex(instr_hex)[::-1]
                    disassembled = list(md.disasm(instr_bytes, current_pc_val))
                    if disassembled:
                        insn = disassembled[0]
                        asm = f"{insn.mnemonic} {insn.op_str}"
                        actual_pc_to_disassembled_instr[current_pc_val] = {"asm": convert_hex_immediates_to_decimal(asm)}
                except Exception as e:
                    actual_pc_to_disassembled_instr[current_pc_val] = {"asm": f"ASM Error: {e}"}

# --- Build Timeline Data ---
# --- NEW: Build Timeline Data with Stall Handling (Latch Freeze) ---
cycle_stage_pc = [{stage: None for stage in stage_signals} for _ in range(num_cycles)]

# 1. Extract raw PC values from VCD first (as you did before)
raw_stage_pcs = defaultdict(list)
for stage, signal_name in stage_signals.items():
    if signal_name not in vcd.signals: 
        raw_stage_pcs[stage] = [None] * num_cycles
        continue
        
    signal_tv = sorted(vcd[signal_name].tv, key=lambda x: x[0])
    tv_idx = 0
    last_val = None
    
    for rise_time in rising_edges:
        while tv_idx < len(signal_tv) and signal_tv[tv_idx][0] <= rise_time:
            val = signal_tv[tv_idx][1]
            if 'x' not in val.lower() and 'z' not in val.lower():
                try: last_val = int(val, 2)                       # <--- NEW: Parse as Binary
                except: pass
            tv_idx += 1
        raw_stage_pcs[stage].append(last_val)

# 2. Process Cycles: Pipeline Flow Inference with "Hybrid Ghost & Smart Stall"
stage_order_reversed = ["WB", "MEM", "EX", "ID", "IF"]
cycle_stage_pc = [{stage: None for stage in stage_signals} for _ in range(num_cycles)]

# 1. Define the missing variable to fix NameError
forced_flush_mask = defaultdict(lambda: defaultdict(bool))

for i in range(num_cycles):
    current_stalls = stall_values_by_cycle[i]
    current_controls = control_values_by_cycle[i]
    
    for stage in stage_order_reversed:
        # Detect Signals
        is_signal_stalled = False
        if stage == "IF" and current_stalls.get("IF") == 1: is_signal_stalled = True
        elif stage == "ID" and current_stalls.get("ID") == 1: is_signal_stalled = True

        is_signal_flushed = False
        if current_controls.get("flush_" + stage.lower()) == 1:
            is_signal_flushed = True
        
        raw_val = raw_stage_pcs[stage][i]
        prev_val_in_stage = cycle_stage_pc[i-1][stage] if i > 0 else None
        
        upstream_stage = {"ID": "IF", "EX": "ID", "MEM": "EX", "WB": "MEM"}.get(stage)
        downstream_stage = {"IF": "ID", "ID": "EX", "EX": "MEM", "MEM": "WB"}.get(stage)

        if i == 0:
            cycle_stage_pc[i][stage] = raw_val
            continue

        did_move_downstream = False
        if downstream_stage:
            instr_in_downstream = cycle_stage_pc[i][downstream_stage]
            if prev_val_in_stage is not None and prev_val_in_stage == instr_in_downstream:
                did_move_downstream = True

        # --- LOGIC START ---

        # PRIORITY 1: FLUSH (With Ghost Recovery)
        if is_signal_flushed and i > 0:
             forced_flush_mask[i][stage] = True
             
             # Step 1: Default behavior (Propagate from upstream or hold previous)
             candidate = None
             if upstream_stage:
                 candidate = cycle_stage_pc[i-1][upstream_stage]
             else:
                 candidate = prev_val_in_stage 

             # Step 2: SPECIAL FIX FOR IF STAGE
             # When IF is flushed, the 'prev_val' is the OLD instruction (PC 32).
             # We want the NEW instruction (PC 36) that was just fetched and killed.
             # So we must discard the old value to force the Ghost Logic to run.
             if stage == "IF":
                 candidate = None 

             # Step 3: Ghost Recovery (Calculate the invisible PC)
             if candidate is None:
                 # Find the Anchor (EX Stage)
                 # Try the processed value first, then fallback to raw input
                 anchor_ex = cycle_stage_pc[i].get("EX") 
                 if anchor_ex is None and "EX" in raw_stage_pcs:
                     anchor_ex = raw_stage_pcs["EX"][i]

                 if anchor_ex is not None:
                     ghost_pc = None
                     # Math: IF is always EX + 8
                     if stage == "ID": ghost_pc = anchor_ex + 4
                     if stage == "IF": ghost_pc = anchor_ex + 8
                     
                     if ghost_pc is not None:
                         candidate = ghost_pc
                         
                         # FORCE INJECTION: Add dummy data if this PC is missing from VCD
                         if candidate not in actual_pc_to_instr_raw:
                                 # 1. Raw binary placeholder
                                 actual_pc_to_instr_raw[candidate] = "00000000"
                                 
                                 # 2. Hex display placeholder
                                 actual_pc_to_instr_hex_display[candidate] = "Ghost"
                                 
                                 # 3. Disassembly Object (Must be a DICT, not a string)
                                 actual_pc_to_disassembled_instr[candidate] = {
                                     "asm": "Flushed Instruction",
                                     "op_str": "",
                                     "mnemonic": "FLUSH"
                                 }

             cycle_stage_pc[i][stage] = candidate

        # PRIORITY 2: STALL (Your Original Smart Logic)
        elif is_signal_stalled:
            if did_move_downstream and upstream_stage:
                cycle_stage_pc[i][stage] = cycle_stage_pc[i-1][upstream_stage]
            elif raw_val is not None and raw_val != 0:
                 cycle_stage_pc[i][stage] = raw_val
            else:
                 cycle_stage_pc[i][stage] = prev_val_in_stage
        
        # PRIORITY 3: NORMAL FLOW
        else:
            cycle_stage_pc[i][stage] = raw_val

    
        # Special Case: IF/ID Hardware Freeze Peek
        if stage == "IF" and downstream_stage:
            current_if = cycle_stage_pc[i]["IF"]
            current_id = cycle_stage_pc[i]["ID"]
            if current_if is not None and current_if == current_id and i < num_cycles - 1:
                next_cycle_raw_if = raw_stage_pcs["IF"][i+1]
                if next_cycle_raw_if is not None and next_cycle_raw_if != current_if:
                    cycle_stage_pc[i]["IF"] = next_cycle_raw_if


# --- Assign Real PCs (Raw Hardware Addresses) ---
# We map the actual PC to itself so the HTML rows correspond to real memory addresses.
vcd_actual_to_synthetic_pc_map = {}
all_pcs_from_vcd = sorted(list(actual_pc_to_instr_raw.keys()))

for actual_pc in all_pcs_from_vcd:
    # --- FIX 1: STRICTLY HIDE ROW 0 ---
    # This prevents the 0x00000000 row from ever being generated
    if actual_pc == 0:
        continue
    vcd_actual_to_synthetic_pc_map[actual_pc] = actual_pc


# --- Prepare Data for HTML/JS ---

pipeline_data_for_js = defaultdict(lambda: [None] * num_cycles)
bubble_data_for_js = defaultdict(lambda: [None] * num_cycles)

for cycle_idx in range(num_cycles):
    
    # 1. Get Hazard Data 
    current_hazard_data = delayed_hazard_data_by_cycle[cycle_idx]
    current_controls = control_values_by_cycle[cycle_idx]
    forwardA = current_hazard_data.get("forwardA", 0)
    forwardB = current_hazard_data.get("forwardB", 0)
    
    hazard_sources = set()
    if forwardA == 1 or forwardB == 1: hazard_sources.add(cycle_stage_pc[cycle_idx].get("MEM"))
    if forwardA == 2 or forwardB == 2: hazard_sources.add(cycle_stage_pc[cycle_idx].get("WB"))
    
    # --- BUBBLE LOGIC START ---
    if cycle_idx > 0:
        # A. Propagate Bubbles (EX -> MEM -> WB)
        for synth_pc, history in bubble_data_for_js.items():
            prev_status = history[cycle_idx - 1]
            if prev_status == "EX":
                history[cycle_idx] = "MEM"
            elif prev_status == "MEM":
                history[cycle_idx] = "WB"

        # B. Create New Bubble in EX (Stall Detection)
        prev_cycle_stalls = stall_values_by_cycle[cycle_idx - 1]
        if prev_cycle_stalls.get("ID") == 1:
            upstream_pc = cycle_stage_pc[cycle_idx].get("ID")
            if upstream_pc is None: upstream_pc = cycle_stage_pc[cycle_idx-1].get("ID")
            
            if upstream_pc in vcd_actual_to_synthetic_pc_map:
                synth_pc = vcd_actual_to_synthetic_pc_map[upstream_pc]
                bubble_data_for_js[synth_pc][cycle_idx] = "EX"
    # --- BUBBLE LOGIC END ---

    # 2. Iterate through stages
    for stage in ["IF", "ID", "EX", "MEM", "WB"]:
        actual_pc = cycle_stage_pc[cycle_idx].get(stage)
        
        # --- CASE A: VALID INSTRUCTION ---
        if actual_pc in vcd_actual_to_synthetic_pc_map:
            synth_pc = vcd_actual_to_synthetic_pc_map[actual_pc]
            asm_text = actual_pc_to_disassembled_instr.get(actual_pc, {}).get("asm", "N/A_ASM")
            
            # --- INSTRUCTION TYPE ANALYSIS ---
            mnemonic = (asm_text.split()[0] if isinstance(asm_text, str) and asm_text else "").lower()
            is_store = any(op in mnemonic for op in ["sw", "sh", "sb"])
            is_branch = any(op in mnemonic for op in ["beq", "bne", "blt", "bge", "jal", "jr", "ret"])

            tooltip = f"Stage: {stage}\nPC: 0x{actual_pc:08x}\nInstruction: {asm_text}"
            display = stage
            hazard_info = {"forwardA": 0, "forwardB": 0, "source_pc_mem": None, "source_pc_wb": None}
            is_source = actual_pc in hazard_sources
            if is_source: tooltip += "\n--- Hazard Source ---"

            # --- STAGE-SPECIFIC LOGIC ---
            if stage == "EX":
                hazard_info["forwardA"] = forwardA
                hazard_info["forwardB"] = forwardB
                if forwardA == 1 or forwardB == 1:
                    hazard_info["source_pc_mem"] = vcd_actual_to_synthetic_pc_map.get(cycle_stage_pc[cycle_idx].get("MEM"))
                if forwardA == 2 or forwardB == 2:
                    hazard_info["source_pc_wb"] = vcd_actual_to_synthetic_pc_map.get(cycle_stage_pc[cycle_idx].get("WB"))

                ex_data = delayed_ex_values_by_cycle[cycle_idx]
                op_a, op_b, res = ex_data.get("operandA"), ex_data.get("operandB"), ex_data.get("aluResult")
                
                # --- NEW LOGIC: SEPARATE DISPLAY FOR BRANCH/JUMP ---
                is_branch_instr = any(op in mnemonic for op in ["beq", "bne", "blt", "bge", "bltu", "bgeu"])
                is_jump_instr = any(op in mnemonic for op in ["jal", "jalr", "j", "jr", "ret"])

                if is_branch_instr:
                    is_flushing_now = (current_controls.get("flush_if") == 1 or current_controls.get("flush_id") == 1)
                    
                    # --- PEEK AHEAD FIX ---
                    next_cycle_idx = cycle_idx + 1 if cycle_idx + 1 < num_cycles else cycle_idx
                    next_controls = control_values_by_cycle[next_cycle_idx]
                    
                    target = next_controls.get("branch_target")
                    if target is None: target = current_controls.get("branch_target")
                    target_val = target if target is not None else 0
                    target_display = f"0x{target_val & 0xFFFFFFFF:08x}"

                    if is_flushing_now:
                        display = f"<strong>Taken</strong><br>⟶ {target_display}"
                        tooltip += f"\nDecision: Taken (Flush Detected)\nTarget: {target_display}"
                    else:
                        display = f"<strong>Not Taken</strong><br>⟶ Next PC"
                        tooltip += f"\nDecision: Not Taken\nNext: PC + 4"

                elif is_jump_instr:
                    next_cycle_idx = cycle_idx + 1 if cycle_idx + 1 < num_cycles else cycle_idx
                    target = control_values_by_cycle[next_cycle_idx].get("branch_target")
                    if target is None: target = current_controls.get("branch_target") or res
                    
                    target_val = target if target is not None else 0
                    target_display = f"0x{target_val & 0xFFFFFFFF:08x}"
                    
                    display = f"<strong>Jump</strong><br>⟶ {target_display}"
                    tooltip += f"\nOperation: Unconditional Jump\nTarget: {target_display}"

                else:
                    # --- STANDARD ALU DISPLAY (Arithmetic) ---
                    operator_map = {"addi": "+", "add": "+", "sub": "-", "and": "&", "or": "|", "xor": "^", "sll": "<<", "srl": ">>"}
                    operator_plain = operator_map.get(mnemonic, mnemonic.upper())
                    
                    if (op_a is not None) and (op_b is not None) and (res is not None):
                        res_signed = res if res < 0x80000000 else res - 0x100000000
                        op_a_signed = op_a if op_a < 0x80000000 else op_a - 0x100000000
                        op_b_signed = op_b if op_b < 0x80000000 else op_b - 0x100000000
                        
                        display = f"EX<br>{op_a_signed} {operator_plain} {op_b_signed} → {res_signed}"
                        tooltip += f"\n--- ALU ---\n{op_a_signed} {operator_plain} {op_b_signed} = {res_signed}"
            
            elif stage == "MEM":
                 if is_branch:
                     display = "---"
                 else:
                     mem_data = delayed_mem_values_by_cycle[cycle_idx]
                     addr, wdata = mem_data.get("addr"), mem_data.get("wdata")
                     rdata = mem_data.get("rdata")
                     hazard_data = delayed_hazard_data_by_cycle[cycle_idx]
                     mem_rd = hazard_data.get("rd_mem_addr")

                     display = "MEM<br>"
                     if is_store:
                         display += f"M[{addr}] = {wdata}"
                         tooltip += f"\n--- Store ---\nAddr: {addr}\nData: {wdata}"
                     else: 
                         is_load_instr = any(op in mnemonic for op in ["lw", "lh", "lb"])
                         if is_load_instr:
                             display += f"Load M[{addr}]"
                             if mem_rd is not None and mem_rd != 0:
                                 val_fmt = str(rdata) if rdata is not None else "?"
                                 display += f"<br>x{mem_rd} = {val_fmt}"
                         else:
                             display += "—"

            elif stage == "WB":
                 if is_store or is_branch:
                     display = '---'
                     hazard_info["is_skipped"] = True
                 else:
                     wb_slot = delayed_wb_values_by_cycle[cycle_idx]
                     wb_data = wb_slot.get("wb_data") or wb_slot.get("data")
                     wb_rd   = wb_slot.get("rd") or wb_slot.get("wb_rd")
                     if wb_data is not None and wb_rd:
                         display = f"WB<br>x{wb_rd} = {wb_data}"
                         tooltip += f"\nWB: x{wb_rd} = {wb_data}"

            # --- VISUAL STALL/FLUSH DETECTION ---
            is_stalled = False
            if cycle_idx > 0:
                prev_cycle_pc_in_same_stage = cycle_stage_pc[cycle_idx - 1].get(stage)
                if prev_cycle_pc_in_same_stage is not None and prev_cycle_pc_in_same_stage == actual_pc:
                    is_stalled = True
                    # Exception: Startup
                    if stage == "IF" and cycle_idx < 3: 
                        if stall_values_by_cycle[cycle_idx].get("IF") == 0: is_stalled = False
                    # Exception: Downstream movement
                    downstream_map = {"IF": "ID", "ID": "EX", "EX": "MEM", "MEM": "WB"}
                    downstream = downstream_map.get(stage)
                    if downstream:
                        pc_in_downstream = cycle_stage_pc[cycle_idx].get(downstream)
                        if pc_in_downstream == actual_pc: is_stalled = False

            # --- FIX 2: FLUSH OVERRIDES STALL (Window of 2 cycles) ---
            # If a flush occurred in this cycle OR the previous 2 cycles, suppress visual stalls.
            # This handles the "Flush Penalty" where the pipeline is refilling.
            suppress_stall_window = False
            for offset in [0, 1, 2]: # Look at T, T-1, T-2
                check_idx = cycle_idx - offset
                if check_idx >= 0:
                    c_ctrl = control_values_by_cycle[check_idx]
                    if c_ctrl.get("flush_if") == 1 or c_ctrl.get("flush_id") == 1:
                        suppress_stall_window = True
                        break
            
            if suppress_stall_window:
                is_stalled = False

            # Normal Flush Visual
            is_flushed = False
            if stage == "IF" and (current_controls.get("flush_if") == 1 or forced_flush_mask[cycle_idx]["IF"]): is_flushed = True
            if stage == "ID" and (current_controls.get("flush_id") == 1 or forced_flush_mask[cycle_idx]["ID"]): is_flushed = True
            
            if is_flushed: is_stalled = False 

            pipeline_data_for_js[synth_pc][cycle_idx] = {
                "stage": stage, "tooltip": tooltip, "display_text": display,
                "hazard_info": hazard_info, "is_hazard_source": is_source,
                "is_stalled": is_stalled,"is_flushed": is_flushed 
            }
        
        
        

pipeline_data_for_js_serializable = {str(pc): data for pc, data in pipeline_data_for_js.items()}

instruction_labels_for_js = []
filtered_synth_pc_to_actual_pc = {} 

# Iterate over the raw PCs directly
sorted_real_pcs = sorted(vcd_actual_to_synthetic_pc_map.keys())

for real_pc in sorted_real_pcs:
    hex_display = actual_pc_to_instr_hex_display.get(real_pc, "N/A_HEX")
    asm_display = actual_pc_to_disassembled_instr.get(real_pc, {}).get("asm", "N/A_ASM")

    # Skip empty/invalid instructions
    if asm_display == "N/A_ASM" or hex_display in ["00000000", "N/A_HEX"]:
        continue

    # Replace nop for visual simplicity
    asm_display = "nop" if asm_display == "addi zero, zero, 0" else asm_display
    
    # Create an object with ID and Label
    label_text = f"PC_0x{real_pc:08x} | {hex_display} ({asm_display})"
    instruction_labels_for_js.append({"id": real_pc, "label": label_text})




mem_activity_by_cycle = []
for cycle_idx in range(num_cycles):
    mem_data = delayed_mem_values_by_cycle[cycle_idx] if cycle_idx < len(delayed_mem_values_by_cycle) else {}
    # Fallbacks — some projects store addr/wdata/rdata under different keys; use best-effort lookups
    addr = mem_data.get("addr") or mem_data.get("dmem_addr") or mem_data.get("io_dmem_addr") or mem_data.get("io_addr")
    wdata = mem_data.get("wdata") or mem_data.get("wd") or mem_data.get("wdat") or mem_data.get("dmem_wData")
    rdata = mem_data.get("rdata") or wb_slot.get("data")
    wr_en = mem_data.get("wrEn") or mem_data.get("wr_en") or mem_data.get("memWr") or mem_data.get("io_memWr")
    rd_en = mem_data.get("rdEn") or mem_data.get("rd_en") or mem_data.get("memRd") or mem_data.get("io_memRd")

    # Normalize simple bool/int
    try:
        wr_flag = bool(int(wr_en)) if wr_en is not None else False
    except Exception:
        wr_flag = bool(wr_en)


    try:
        rd_flag = bool(int(rd_en)) if rd_en is not None else False
    except Exception:
        rd_flag = bool(rd_en)

    # Determine type
    is_store = wr_flag
    #is_load = 1 if rdata != 0 else 0 

    
    # CLEANUP: If writing, force Read Data to None/N/A in the JSON
    display_rdata = "—" if is_store else rdata
    # CLEANUP: If reading, force Write Data to None/N/A
    display_wdata = wdata if is_store else "—"

    mem_activity_by_cycle.append({
        "cycle": cycle_idx,
        "addr": addr,
        "wdata": display_wdata,  # Use the cleaned value
        "rdata": display_rdata,  # Use the cleaned value
        "wr_en": wr_flag,
        "rd_en": False, # Or derive from signals if available
        "is_store": is_store,
        "is_load": not is_store # Simplification
    })

# Add it to the HTML context (JSON serializable)
mem_activity_js = json.dumps(mem_activity_by_cycle)



# --- NEW: Build a styled warning box for missing signals ---
missing_signals_html = ""
all_missing_keys = [key for keys in missing_signals_by_label.values() for key in keys]

if all_missing_keys:
    # Use an f-string to build the main box structure
    missing_signals_html = """
    <div id="missing-signals-container" class="missing-signals-box">
        <span class="close-btn" onclick="this.parentElement.style.display='none'">&times;</span>
        <div class="missing-signals-header">
            <span style="font-size: 20px; margin-right: 10px;">⚠️</span>
            <strong>Missing Signals Detected</strong>
        </div>
        <p>The animation may not work as expected because the following signals were not found in your VCD file. Please check the signal names in your hardware design.</p>
        <div class="missing-signals-list">
    """
    
    # Add a list for each category
    for category, keys in missing_signals_by_label.items():
        if not keys:
            continue
        # Start the new wrapper div
        missing_signals_html += '<div class="signal-category-block">'
        missing_signals_html += f"<h4>Category: <code>{category}</code></h4><ul>"
        for k in keys:
            missing_signals_html += f"<li><code>{k}</code></li>"
        missing_signals_html += "</ul>"
        # Close the wrapper div
        missing_signals_html += '</div>'


print("\n" + "="*50)
print(" 🕵️‍♂️ GHOST INSTRUCTION DEBUGGER")
print("="*50)
# Use one of your known EX PCs (binary 28)
debug_ex_pc = 28 # (00011100 binary)
debug_id_pc = debug_ex_pc + 4
debug_if_pc = debug_ex_pc + 8

print(f"Checking neighborhood of EX PC: {debug_ex_pc}")
print(f"Expect ID at: {debug_id_pc}")
print(f"Expect IF at: {debug_if_pc} (This is the missing one)")

for pc in [debug_ex_pc, debug_id_pc, debug_if_pc]:
    status = "✅ FOUND" if pc in actual_pc_to_instr_raw else "❌ MISSING"
    hex_str = actual_pc_to_instr_hex_display.get(pc, "N/A")
    print(f"   PC {pc} (0x{pc:x}) : {status} -> Instr: {hex_str}")

print("\nIf PC+8 is MISSING, the VCD parser never saw it stabilize.")
print("If PC+8 is FOUND, the 'Step B' logic fix above will solve it.")
print("="*50 + "\n")

# --- DEBUG TOOL: CONTROL SIGNAL INSPECTOR ---
print("\n" + "="*95)
print(f" 🕵️‍♂️ CONTROL SIGNAL INSPECTOR ")
print("="*95)
print(f"{'Cyc':<4} | {'Br_Taken':<8} | {'Br_Target':<12} | {'Flush_IF':<8} | {'Flush_ID':<8} | {'EX_PC':<10} | {'Instruction in EX'}")
print("-" * 95)

for i in range(num_cycles):
    # 1. Get Control Values for this cycle
    ctrl = control_values_by_cycle[i]
    taken = ctrl.get("branch_taken")
    target = ctrl.get("branch_target")
    flush_if = ctrl.get("flush_if")
    flush_id = ctrl.get("flush_id")

    # 2. Get the PC currently in the EX stage (where branches are resolved)
    # We try to get the calculated PC first, fallback to raw if needed
    ex_pc = cycle_stage_pc[i].get("EX")
    
    # 3. Get the instruction mnemonic for context
    instr_str = ""
    if ex_pc is not None and ex_pc in actual_pc_to_disassembled_instr:
        instr_str = actual_pc_to_disassembled_instr[ex_pc].get("asm", "")

    # 4. Format Target (handle None or 0)
    target_str = f"0x{target:x}" if target is not None else "None"
    if target == 0: target_str = "0"

    # 5. Filter: Only print if there is activity (Branch taken OR Flush OR Instruction in EX)
    #    This prevents printing hundreds of empty cycles.
    has_activity = (taken == 1) or (flush_if == 1) or (flush_id == 1) or (ex_pc is not None)
    
    if has_activity:
        # Highlight rows where Branch is Taken with a pointer <--
        pointer = " 🟢 TAKEN" if taken == 1 else ""
        if flush_if == 1 or flush_id == 1: pointer += " 🔴 FLUSH"
        
        print(f"{i:<4} | {str(taken):<8} | {target_str:<12} | {str(flush_if):<8} | {str(flush_id):<8} | {str(ex_pc):<10} | {instr_str:<20}{pointer}")

print("="*95 + "\n")


# --- HTML Generation ---
color_map_js = json.dumps({"IF":"#ff9933","ID":"#5cd65c","EX":"#4b9aefd7","MEM":"#cf66ffb9","WB":"#ff2525c6"})




html_content = """
<html><head><title>Pipeline & Register Animation</title>
<style>
body {{ font-family: sans-serif; margin: 20px; }} h2, h3 {{ text-align: center; }}
.header-container {{
    display: flex;
    flex-direction: column;
    align-items: center; /* This will horizontally center all content in the container */
    width: 100%;
}}
.controls {{ text-align: center; margin-bottom: 20px; display: flex; justify-content: center; align-items: center; gap: 10px; flex-wrap: wrap; }}
.controls button {{ padding: 10px 20px; font-size: 16px; cursor: pointer; }} #cycleCounter {{ font-size: 18px; font-weight: bold; }}
.speed-control-container {{ display: flex; align-items: center; gap: 5px; }}
#speedValue {{ font-family: monospace; font-size: 14px; min-width: 50px; text-align: left; }}
.content-wrapper {{ display: flex; justify-content: center; align-items: flex-start; gap: 50px; flex-wrap: wrap; }}
.pipeline-grid, .register-grid {{ display: grid; border: 1px solid #ccc; width: fit-content; }}
.pipeline-grid {{ grid-template-columns: 380px repeat(5, 120px); }}
.register-grid {{ grid-template-columns: 110px 210px 95px 95px;}}
.grid-cell span {{    font-size: 16px; font-weight: bold;}}
//.grid-cell.stage-cell {{
    font-size: 30px;
    font-weight: 500;
    line-height: 1.5;
    font-family: "Courier New", monospace;
    padding: 10px;
    text-align: center;
    white-space: normal;
}}
.register-grid .grid-cell {{
    height: 20px;             
    line-height: 40px;        
    overflow: hidden;          
}}
.register-grid .grid-cell {{
    display: flex;
    align-items: center;
    justify-content: center;
}}
.grid-header, .grid-cell {{ padding: 8px; border: 1px solid #eee; text-align: center; white-space: nowrap; }}
.grid-header {{ background-color: #ddd; font-weight: bold; }}
.instruction-label {{ text-align: left; font-weight: bold; font-family: monospace; font-size: 14px; }}
.stage-cell {{ height: 50px; position: relative; }}
.stage-content {{ width: 95%; height: 95%; border-radius: 5px; display: flex; flex-direction: column; align-items: center; justify-content: center; font-size: 12px; color: #333; cursor: help; transition: all 0.2s ease-in-out; margin: auto; line-height: 1.2; padding: 2px; }}
.tooltip-text {{ visibility: hidden; background-color: #555; color: #fff; text-align: left; border-radius: 6px; padding: 8px; position: absolute; z-index: 10; bottom: 125%; left: 50%; transform: translateX(-50%); opacity: 0; transition: opacity 0.3s; width: max-content; white-space: pre-wrap; }}
.stage-content:hover .tooltip-text {{ visibility: visible; opacity: 1; }}
.legend {{ margin: 20px auto; display: flex; justify-content: center; gap: 20px; padding: 10px; border: 1px solid #ddd; border-radius: 8px; width: fit-content; flex-wrap: wrap; }}
.legend-item {{ display: inline-flex; align-items: center; gap: 8px; }}
.legend-color-box {{ width: 20px; height: 20px; border-radius: 4px; border: 2px solid; }}
.register-name-cell {{ font-family: monospace; text-align: left !important; padding-left: 10px !important; }}
.register-value-cell {{ font-family: monospace; }}
.register-value-cell.changed {{ background-color: #FFD700; transition: background-color 0.1s ease-in; }}
.hazard-source-highlight {{ border: 3px solid #FF4500 !important; box-shadow: 0 0 10px rgba(255, 69, 0, 0.7);background-color: #ffe5e5; }}
.forwarding-destination-highlight {{ border: 3px solid #007BFF !important; box-shadow: 0 0 10px rgba(0, 123, 255, 0.7); background-color: #cce5ff !important; }}
.highlighted-search {{
    background-color: yellow !important;
    border: 2px solid orange !important;
}}
#arrow-svg {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 5; }}
.arrow {{ stroke: #FF4500; stroke-width: 2.5; fill: none; stroke-dasharray: 5; animation: dash 0.5s linear infinite; marker-end: url(#arrowhead); }}
@keyframes dash {{ to {{ stroke-dashoffset: -10; }} }}


.missing-signals-box {{
    max-width: 900px;
    margin: 10px auto 25px auto; /* Center the box and add space */
    padding: 20px;
    border: 1px solid #ffb300;
    background-color: #fff8e1;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
    position: relative;
    color: #5b4d24;
}}
.missing-signals-header {{
    display: flex;
    align-items: center;
    font-size: 18px;
    font-weight: bold;
    margin-bottom: 10px;
    color: #c58600;
}}
.missing-signals-box p {{
    margin: 0 0 15px 0;
    font-size: 14px;
    line-height: 1.5;
}}
.missing-signals-list {{
    column-count: 3; /* Arrange signals in columns for compactness */
    column-gap: 20px;
}}
.missing-signals-list h4 {{
    margin-top: 0;
    margin-bottom: 5px;
    font-size: 14px;
}}
.missing-signals-list ul {{
    list-style-type: none;
    padding-left: 0;
    margin: 0 0 15px 0;
}}
.missing-signals-list li {{
    margin-bottom: 5px;
}}
.missing-signals-list li code {{
    font-family: monospace;
    background-color: #f0e9d1;
    padding: 3px 6px;
    border-radius: 4px;
    font-size: 13px;
}}

.signal-category-block {{
    break-inside: avoid;
    -webkit-column-break-inside: avoid; /* For older browser compatibility */
    page-break-inside: avoid;       /* For older browser compatibility */
    padding: 5px; /* Adds a little internal spacing */
}}
.close-btn {{
    position: absolute;
    top: 10px;
    right: 15px;
    font-size: 24px;
    font-weight: bold;
    color: #c58600;
    cursor: pointer;
    line-height: 1;
}}
.close-btn:hover {{
    color: #5b4d24;

.stage-content {{
    font-family: monospace;
    font-size: 13px;
}}

.stag0e-content br + span {{
    opacity: 0.9;
}}
}}
#memActivityTable thead tr {{
        background-color: #1e3a8a; /* Deep blue */
        color: white;
    }}
    #memActivityTable th {{
        font-weight: 600;
        text-align: center;
    }}

.stalled-stage {{
    background-image: repeating-linear-gradient(
      45deg,
      rgba(255, 0, 0, 0.2),
      rgba(255, 0, 0, 0.2) 10px,
      rgba(255, 0, 0, 0.3) 10px,
      rgba(255, 0, 0, 0.3) 20px
    );
    border: 2px solid red !important;
    animation: pulse-stall 1s infinite;
}}
.bubble-stage {{
    background-color: #e0e0e0 !important;
    border: 2px dashed #999 !important;
    color: #666;
    font-style: italic;
    opacity: 0.7;
}}

@keyframes pulse-stall {{
    0% {{ transform: scale(1); }}
    50% {{ transform: scale(1.02); }}
    100% {{ transform: scale(1); }}
}}
.flushed-stage {{
    background-color: #ffcccc !important;
    text-decoration: line-through;
    opacity: 0.6;
}}

</style>
</head>
<body>
<h2>Pipeline Animation with Register State</h2>

<div style="font-size: 14px; margin-bottom: 10px;">

{missing_signals_html}
</div>
</div>

<div class="controls">
    <button id="prevBtn">Previous</button>
    <span id="cycleCounter">Cycle 0 / {{num_cycles}}</span>
    <button id="nextBtn">Next</button>
    <button id="playPauseBtn">Play</button>
    
    <button id="restartBtn">Restart</button>
    <button id="toggleArrowsBtn">Hide Forwarding</button>  
    <button id="toggleHazardsBtn">Show Hazards</button>  
    <button id="toggleSignedBtn">Show Signed</button>
    <button id="toggleMemActivityBtn">Show MEM Activity</button>

    <div class="speed-control-container">
        <label for="speedControl">Speed:</label>
        <input type="range" id="speedControl" min="100" max="1000" value="500" step="50">
        <span id="speedValue">500ms</span>
        </div>
        

         </div>

        <div class="legend">
            <input type="text" id="searchBox" placeholder="Search PC, instruction or register ">
            <button onclick="resetPipelineFilter()" style="padding: 4px 10px;">Reset</button>
            <div class="legend-item"><div class="legend-color-box" style="border-color: #FF4500; background-color: #fff2e6;"></div><span>Hazard Source</span></div>
            <div class="legend-item"><div class="legend-color-box" style="border-color: #007BFF; background-color: #cce5ff;"></div><span>Forwarding Destination</span></div>
         </div>

    <!-- MEM Activity Panel -->
    <div id="mem-activity-panel" style="display: none; margin-top: 20px; max-width: 1000px; margin-left: auto; margin-right: auto;">
        <h3>Memory Activity (current cycle)</h3>
        <table id="memActivityTable" style="width:100%; border-collapse: collapse;">
            <thead>
                <tr>
                    <th style="border: 1px solid #ddd; padding: 8px;">Cycle</th>
                
                    <th style="border: 1px solid #ddd; padding: 8px;">Address</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">Write Data</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">Read Data</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">WrEn</th>
                
                </tr>
            </thead>
            <tbody id="memActivityTbody">
                <!-- Filled dynamically -->
            </tbody>
        </table>
    </div>

    <div class="content-wrapper">
        <div class="pipeline-container">
            <h3>Pipeline Stages</h3>
            <div style="position: relative;">
                <div id="pipelineDisplay" class="pipeline-grid" style="display: grid;"></div>
                <svg id="arrow-svg"></svg>
            </div>
        </div>
        <div class="register-container">
            <h3>Register File State</h3>
            <div id="registerTable" class="register-grid">
                <div class="grid-header">Register</div>
                <div class="grid-header">Value</div>
                <div class="grid-header">Read (EX)</div>
                <div class="grid-header">Write (WB)</div>
            </div>
        </div>

    
        
    
       
</div>


<script>
    const pipelineData = {pipeline_data_js};
    const instructionLabels = {instruction_labels_js};
    const registerData = {register_data_js};
    const numCycles = {num_cycles};
    const colorMap = {color_map_js};
    const vcd_actual_to_synthetic_pc_map = {vcd_actual_to_synthetic_pc_map_js};
    const regHighlightData = {reg_highlight_data_js};
    const abiNames = ["zero","ra","sp","gp","tp","t0","t1","t2","s0/fp","s1","a0","a1","a2","a3","a4","a5","a6","a7","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11","t3","t4","t5","t6"];
    let currentCycle = 0, animationInterval = null, animationSpeed = 500, showArrows = true;
    let showHazards = false;

    const pipelineDisplay = document.getElementById('pipelineDisplay');
    const registerTable = document.getElementById('registerTable');
    const arrowSvg = document.getElementById('arrow-svg');
    const cycleCounter = document.getElementById('cycleCounter');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const playPauseBtn = document.getElementById('playPauseBtn');
    const restartBtn = document.getElementById('restartBtn');
    const speedControl = document.getElementById('speedControl');
    const speedValue = document.getElementById('speedValue');
    const searchBox = document.getElementById('searchBox');

    const memActivity = {mem_activity_js};   // inserted by Python string.format
    const bubbleData = {bubble_data_js};
    const memActivityPanel = document.getElementById('mem-activity-panel');
    const memActivityTbody = document.getElementById('memActivityTbody');
    const toggleMemActivityBtn = document.getElementById('toggleMemActivityBtn');

    // --- MODIFICATION: Refactored to build the static grid once ---
    function populateStaticGrid() {{
        const filterText = searchBox.value.toLowerCase();
        
        // Pipeline Headers
        ['Instruction', 'IF', 'ID', 'EX', 'MEM', 'WB'].forEach(text => {{
            const header = document.createElement('div');
            header.className = 'grid-header'; 
            header.textContent = text;
            pipelineDisplay.appendChild(header);
        }});

        // Instruction Rows
        // We now iterate over objects: {{id: 28, label: "..."}}
        instructionLabels.forEach((item) => {{
            const pcId = item.id; // This is now the REAL address (e.g., 28, 32)
            const text = item.label;

            const labelDiv = document.createElement('div');
            labelDiv.className = 'grid-cell instruction-label';
            labelDiv.id = `instr-label-${{pcId}}`;
            labelDiv.textContent = text;
            pipelineDisplay.appendChild(labelDiv);

            for (let i = 0; i < 5; i++) {{
                const stageCell = document.createElement('div');
                stageCell.className = 'grid-cell stage-cell';
                // IDs are now like: stage-cell-28-0, stage-cell-32-1
                stageCell.id = `stage-cell-${{pcId}}-${{i}}`; 
                pipelineDisplay.appendChild(stageCell);
            }}
        }});
        // Register Table

        for (let i = 0; i < 32; i++) {{
            const nameCell = document.createElement('div');
            nameCell.className = 'grid-cell register-name-cell';
            nameCell.textContent = `x${{i}} (${{abiNames[i]}})`;
            registerTable.appendChild(nameCell);

            const valueCell = document.createElement('div');
            valueCell.className = 'grid-cell register-value-cell';
            valueCell.id = `reg-val-${{i}}`;
            registerTable.appendChild(valueCell);

            const readCell = document.createElement('div');
            readCell.className = 'grid-cell';
            readCell.id = `reg-read-${{i}}`;
            registerTable.appendChild(readCell);

            const writeCell = document.createElement('div');
            writeCell.className = 'grid-cell';
            writeCell.id = `reg-write-${{i}}`;
            registerTable.appendChild(writeCell);
        }}
    }}

    function updateDisplay() {{
        cycleCounter.textContent = `Cycle ${{currentCycle}} / ${{numCycles - 1}}`;
        updatePipelineDisplay();
        updateRegisterTable();

        if (memActivityPanel.style.display !== 'none') {{
            renderMemActivityForCycle(currentCycle);
        }}  

        prevBtn.disabled = currentCycle === 0;
        nextBtn.disabled = currentCycle === numCycles - 1;
        // Use timeout to ensure DOM is updated before calculating arrow positions
        setTimeout(updateArrows, 0);

        

     }}

        function updatePipelineDisplay() {{
            document.querySelectorAll('.stage-cell').forEach(c => c.innerHTML = '');
            document.querySelectorAll('.instruction-label').forEach(l => l.classList.remove('hazard-source-highlight'));
            
            Object.entries(pipelineData).forEach(([synthPc, cycleData]) => {{
                // 1. Draw the Main Instruction (The Stall)
                const instrCycleData = cycleData[currentCycle];
                if (instrCycleData) {{
                    if (showHazards && instrCycleData.is_hazard_source) {{
                        const label = document.getElementById(`instr-label-${{synthPc}}`);
                        if (label) label.classList.add('hazard-source-highlight');
                    }}
                    const stageIdx = {{IF:0, ID:1, EX:2, MEM:3, WB:4}}[instrCycleData.stage];
                    const stageCell = document.getElementById(`stage-cell-${{synthPc}}-${{stageIdx}}`);
                    
                    if (stageCell) {{
                        const contentDiv = document.createElement('div');
                        contentDiv.className = 'stage-content';
                        contentDiv.style.backgroundColor = colorMap[instrCycleData.stage];
                        contentDiv.id = `content-${{synthPc}}-${{instrCycleData.stage}}`;

                        if (instrCycleData.is_stalled) {{
                            contentDiv.classList.add('stalled-stage');
                            contentDiv.innerHTML = "<strong>STALL</strong><br>" + instrCycleData.display_text;
                        }} else {{
                            contentDiv.innerHTML = instrCycleData.display_text;
                        }}

                        if (instrCycleData.is_flushed) {{
                            contentDiv.classList.add('flushed-stage');
                            contentDiv.innerHTML += "<br><strong>(FLUSHED)</strong>";
                        }}

                        if (instrCycleData.stage === "EX") {{
                            const hasForwarding = (instrCycleData.hazard_info.forwardA !== 0) || (instrCycleData.hazard_info.forwardB !== 0);
                            if (showArrows && hasForwarding) contentDiv.classList.add('forwarding-destination-highlight');
                        }}
                        
                        const tooltipSpan = document.createElement('span');
                        tooltipSpan.className = 'tooltip-text';
                        tooltipSpan.textContent = instrCycleData.tooltip;
                        contentDiv.appendChild(tooltipSpan);
                        stageCell.appendChild(contentDiv);
                    }}
                }}

                // 2. Draw the Bubble (The Gap) - NEW LOGIC
                const bubbleStage = bubbleData[synthPc] ? bubbleData[synthPc][currentCycle] : null;
                if (bubbleStage) {{
                    const stageIdx = {{IF:0, ID:1, EX:2, MEM:3, WB:4}}[bubbleStage];
                    const stageCell = document.getElementById(`stage-cell-${{synthPc}}-${{stageIdx}}`);
                    
                    if (stageCell) {{
                        const contentDiv = document.createElement('div');
                        contentDiv.className = 'stage-content bubble-stage';
                        contentDiv.innerHTML = "Bubble<br>(NOP)";
                        
                        const tooltipSpan = document.createElement('span');
                        tooltipSpan.className = 'tooltip-text';
                        tooltipSpan.textContent = "Pipeline Bubble\\nInserted due to stall in previous stage";
                        contentDiv.appendChild(tooltipSpan);
                        
                        stageCell.appendChild(contentDiv);
                    }}
                }}
            }});
        }}

        function filterPipelineInstruction() {{
            const query = searchBox.value.toLowerCase().trim();
            if (!query) return;

            let matchFound = false;

            instructionLabels.forEach((item) => {{
                const pcId = item.id; // Raw PC
                const label = item.label;
                
                const labelLower = label.toLowerCase();
                const rowIds = [`instr-label-${{pcId}}`];
                for (let i = 0; i < 5; i++) {{
                    rowIds.push(`stage-cell-${{pcId}}-${{i}}`);
                }}

                const match = labelLower.includes(query);
                matchFound = matchFound || match;

                rowIds.forEach(id => {{
                    const elem = document.getElementById(id);
                    if (elem) {{
                        elem.style.display = match ? '' : 'none';
                    }}
                }});
            }});

            if (!matchFound) {{
                alert("❌ No matching instruction or PC found.");
            }}
        }}


            // 🟡 Add listener for Enter key
            searchBox.addEventListener('keydown', (e) => {{
            if (e.key === 'Enter') {{
            filterPipelineInstruction();
            }}
            }});


            // 🟡 Add reset function (optional)
            function resetPipelineFilter() {{
                instructionLabels.forEach((item) => {{
                    const pcId = item.id;
                    const rowIds = [`instr-label-${{pcId}}`];
                    for (let i = 0; i < 5; i++) {{
                        rowIds.push(`stage-cell-${{pcId}}-${{i}}`);
                    }}
                    rowIds.forEach(id => {{
                        const elem = document.getElementById(id);
                        if (elem) elem.style.display = '';
                    }});
                }});
            }}

    
        function updateRegisterTable() {{
            const currentRegs = registerData[currentCycle] || {{}};
            const prevRegs = currentCycle > 0 ? registerData[currentCycle - 1] : {{}};
            const highlights = regHighlightData[currentCycle] || {{}};

            for (let i = 0; i < 32; i++) {{
                const valCell = document.getElementById(`reg-val-${{i}}`);
                const currentVal = currentRegs[`x${{i}}`] || '0x00000000';
                const prevVal = prevRegs[`x${{i}}`] || '0x00000000';

                // Show decimal as *binary* if hex digits are only 0/1; otherwise as hex
                let displayValue = currentVal;
                if (typeof currentVal === 'string' && currentVal.startsWith('0x')) {{
                    const digits = currentVal.slice(2);
                    let dec = Number.NaN;

                    if (/^[01]+$/.test(digits)) {{
                        dec = parseInt(digits, 2);
                    }} else if (/^[0-9a-fA-F]+$/.test(digits)) {{
                        dec = parseInt(digits, 16);
                    }}

                    if (!Number.isNaN(dec)) {{
                        displayValue = `${{currentVal}} (${{dec}})`;
                    }}
                }}

                valCell.textContent = displayValue;
                const readCell = document.getElementById(`reg-read-${{i}}`);
                const writeCell = document.getElementById(`reg-write-${{i}}`);
                readCell.textContent = '';
                writeCell.textContent = '';

                // ✅ Only show dots from cycle 3 onward
                if (currentCycle >= 3) {{
                    if (highlights.id_rs1 === i || highlights.id_rs2 === i) {{
                        readCell.innerHTML = '<span style="color: #007BFF; font-size: 20px;">●</span>';
                    }}
                    if (i !== 0 && highlights.wb_rd === i) {{
                        writeCell.innerHTML = '<span style="color: #FF4500; font-size: 20px;">●</span>';
                    }}
                }}

                valCell.classList.toggle('changed', currentVal !== prevVal);
            }}
        }}



    
    // --- NEW: Function to draw a single arrow ---
    function drawArrow(fromElem, toElem) {{
        if (!fromElem || !toElem) return;
        const svgRect = arrowSvg.getBoundingClientRect();
        const fromRect = fromElem.getBoundingClientRect();
        const toRect = toElem.getBoundingClientRect();

        const startX = fromRect.left + fromRect.width / 2 - svgRect.left;
        const startY = fromRect.top + fromRect.height / 2 - svgRect.top;
        const endX = toRect.left + toRect.width / 2 - svgRect.left;
        const endY = toRect.top - svgRect.top; // Point to the TOP of the cell

        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        // A bezier curve for a nice arc
        const d = `M ${{startX}},${{startY}} C ${{startX}},${{startY - 40}} ${{endX}},${{endY - 40}} ${{endX}},${{endY}}`;
        path.setAttribute('d', d);


        if (type === "branch") {{
            path.setAttribute('stroke', '#28a745'); // Green
            path.setAttribute('marker-end', 'url(#arrowhead-branch)');
            path.setAttribute('stroke-dasharray', '0'); // Solid line
        }} else {{
            path.setAttribute('stroke', '#FF4500'); // Red
            path.setAttribute('marker-end', 'url(#arrowhead-hazard)');
            path.setAttribute('class', 'arrow'); // Keep existing dash animation
        }}
        path.setAttribute('stroke-width', '2.5');
        path.setAttribute('fill', 'none');
        
        arrowSvg.appendChild(path);
    }}

    // --- NEW: Function to update all arrows for the current cycle ---
    function updateArrows() {{
        if (!showArrows) {{ arrowSvg.innerHTML = ''; return; }}
        
        // Define markers: Red for Hazard, Green for Branch
        arrowSvg.innerHTML = `
            <defs>
                <marker id="arrowhead-hazard" markerWidth="5" markerHeight="3.5" refX="0" refY="1.75" orient="auto">
                    <polygon points="0 0, 5 1.75, 0 3.5" fill="#FF4500" />
                </marker>
                <marker id="arrowhead-branch" markerWidth="5" markerHeight="3.5" refX="0" refY="1.75" orient="auto">
                    <polygon points="0 0, 5 1.75, 0 3.5" fill="#28a745" />
                </marker>
            </defs>`;

        Object.entries(pipelineData).forEach(([synthPc, cycleData]) => {{
            const instrCycleData = cycleData[currentCycle];
            
            if (instrCycleData && instrCycleData.stage === 'EX') {{
                const hazardInfo = instrCycleData.hazard_info;
                const toElem = document.getElementById(`content-${{synthPc}}-EX`);

                // 1. Hazard Arrows (Red)
                if (hazardInfo.source_pc_mem !== null) 
                    drawArrow(document.getElementById(`content-${{hazardInfo.source_pc_mem}}-MEM`), toElem, "hazard");
                if (hazardInfo.source_pc_wb !== null) 
                    drawArrow(document.getElementById(`content-${{hazardInfo.source_pc_wb}}-WB`), toElem, "hazard");

                // 2. Branch Arrow (Green)
                // Draws from EX stage to the Target Instruction in IF stage (next cycle prediction)
                if (hazardInfo.branch_target_synth !== null && hazardInfo.branch_target_synth !== undefined) {{
                    // The target instruction will appear in IF. 
                    // NOTE: We target the ROW of the target instruction.
                    // Since we don't know if it's in IF *this* cycle (it's usually fetched next cycle),
                    // we point to the Instruction Label or a placeholder cell.
                    
                    // Try to find the label of the target PC
                    const targetLabel = document.getElementById(`instr-label-${{hazardInfo.branch_target_synth}}`);
                    
                    if (targetLabel) {{
                        drawArrow(toElem, targetLabel, "branch");
                    }}
                }}
            }}
        }});
    }}

    function renderMemActivityForCycle(cycle) {{
        memActivityTbody.innerHTML = '';
        const entry = memActivity[cycle];
        
        if (!entry) {{ 
            memActivityTbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No data</td></tr>'; 
            return; 
        }}
        
        const tr = document.createElement('tr');
        
        // Cycle
        let td = document.createElement('td'); td.style.border='1px solid #ddd'; td.style.padding='8px'; td.style.textAlign='center'; 
        td.textContent = entry.cycle; tr.appendChild(td);
        
        // Address
        td = document.createElement('td'); td.style.border='1px solid #ddd'; td.style.padding='8px'; td.style.textAlign='center'; 
        td.textContent = (entry.addr !== undefined && entry.addr !== null) ? entry.addr : 'N/A'; tr.appendChild(td);
        
        // Write Data (Handle "—" logic passed from Python)
        td = document.createElement('td'); td.style.border='1px solid #ddd'; td.style.padding='8px'; td.style.textAlign='center'; 
        td.textContent = (entry.wdata !== undefined && entry.wdata !== null) ? entry.wdata : '—'; tr.appendChild(td);
        
        // Read Data (Handle "—" logic passed from Python)
        td = document.createElement('td'); td.style.border='1px solid #ddd'; td.style.padding='8px'; td.style.textAlign='center'; 
        // Check for the explicit exclusion from Python, otherwise show val
        td.textContent = (entry.rdata !== undefined && entry.rdata !== null) ? entry.rdata : '—'; tr.appendChild(td);
        
        // WrEn
        td = document.createElement('td'); td.style.border='1px solid #ddd'; td.style.padding='8px'; td.style.textAlign='center'; 
        td.textContent = entry.wr_en ? '1' : '0'; tr.appendChild(td);
        
        memActivityTbody.appendChild(tr);
    }}



    function nextCycle() {{ if (currentCycle < numCycles - 1) {{ currentCycle++; updateDisplay(); }} else {{ stopAnimation(); }} }}
    function prevCycle() {{ if (currentCycle > 0) {{ currentCycle--; updateDisplay(); }} }}
    function startAnimation() {{
        if (animationInterval) return;
        playPauseBtn.textContent = 'Pause';
        animationInterval = setInterval(nextCycle, animationSpeed);
    }}
    function stopAnimation() {{
        clearInterval(animationInterval);
        animationInterval = null;
        playPauseBtn.textContent = 'Play';
    }}
    function restartAnimation() {{ stopAnimation(); currentCycle = 0; updateDisplay(); }}

    prevBtn.addEventListener('click', prevCycle);
    nextBtn.addEventListener('click', nextCycle);
    restartBtn.addEventListener('click', restartAnimation);
    playPauseBtn.addEventListener('click', () => animationInterval ? stopAnimation() : startAnimation());
    searchBox.addEventListener('keydown', (e) => {{
    if (e.key === 'Enter') {{
    filterPipelineInstruction();
    }}
    }});
    speedControl.addEventListener('input', () => {{
        animationSpeed = speedControl.value;
        speedValue.textContent = `${{animationSpeed}}ms`;
        if (animationInterval) {{ stopAnimation(); startAnimation(); }}
    }});
    document.addEventListener('keydown', (e) => {{
        if (e.key === 'ArrowRight') nextCycle();
        if (e.key === 'ArrowLeft') prevCycle();
    }});
    document.getElementById('toggleArrowsBtn').addEventListener('click', () => {{
        showArrows = !showArrows;
        document.getElementById('toggleArrowsBtn').textContent = showArrows ? 'Hide Forwaring' : 'Show Forwaring';
        updateDisplay(); // re-render (clears or draws arrows accordingly)
    }});
    document.getElementById('toggleHazardsBtn').addEventListener('click', () => {{
        showHazards = !showHazards;
        document.getElementById('toggleHazardsBtn').textContent = showHazards ? 'Hide Hazards' : 'Show Hazards';
        updateDisplay(); // re-render pipeline with or without hazard highlights
    }});

    toggleMemActivityBtn.addEventListener('click', () => {{
        const shown = memActivityPanel.style.display !== 'none';
        memActivityPanel.style.display = shown ? 'none' : 'block';
        toggleMemActivityBtn.textContent = shown ? 'Show MEM Activity' : 'Hide MEM Activity';
        if (!shown) {{
            renderMemActivityForCycle(currentCycle);
        }}
    }});

    // Initial setup
    populateStaticGrid();
    updateDisplay();



    document.getElementById('toggleSignedBtn').addEventListener('click', () => {{{{
    const signedElems = document.querySelectorAll('.alu-signed');
    const unsignedElems = document.querySelectorAll('.alu-unsigned');

    signedElems.forEach(el => {{{{
        el.style.display = el.style.display === 'none' ? '' : 'none';
    }}}});
    unsignedElems.forEach(el => {{{{
        el.style.display = el.style.display === 'none' ? '' : 'none';
    }}}});

    const btn = document.getElementById('toggleSignedBtn');
    btn.textContent = btn.textContent === 'Show Signed' ? 'Show Unsigned' : 'Show Signed';
}}}});


</script>
</body>
</html>
""".format(
    num_cycles=num_cycles,
    pipeline_data_js=json.dumps(pipeline_data_for_js_serializable),
    instruction_labels_js=json.dumps(instruction_labels_for_js),
    register_data_js=json.dumps(delayed_register_values_by_cycle),
    color_map_js=color_map_js,
    vcd_actual_to_synthetic_pc_map_js=json.dumps(vcd_actual_to_synthetic_pc_map),
    reg_highlight_data_js=json.dumps(reg_highlight_data_by_cycle),
    missing_signals_html=missing_signals_html,
    mem_activity_js=mem_activity_js,
    bubble_data_js=json.dumps(bubble_data_for_js)
 
)

# --- Write the final HTML file ---
print(f"Writing output to {output_html}")
with open(output_html, "w",  encoding="utf-8") as f:
    f.write(html_content)

print(f"✅ Successfully generated '{output_html}'. Open this file in your web browser to view the animation.")
webbrowser.open_new_tab(output_html)





all_missing_keys = [key for keys in missing_signals_by_label.values() for key in keys]

print("\n" + "="*50)
print(" VCD Signal Analysis Summary")
print("="*50)

if not all_missing_keys:
    print("✅ Success! All required signals were found in the VCD file.")
    print("The generated HTML animation should be fully functional.")
else:
    print(f"⚠️  Warning: A total of {len(all_missing_keys)} required signal(s) were not found.")
    print("The generated HTML animation may be incomplete or behave unexpectedly.")
    print("Please review the detailed log above for specifics on missing signals like:")
    # Print up to 5 examples of missing signals
    for key in all_missing_keys[:5]:
        print(f"    - '{key}'")
    if len(all_missing_keys) > 5:
        print("    - ... and more.")
    print("\nCheck your hardware design's signal names to resolve these issues.")

print("="*50 + "\n")



