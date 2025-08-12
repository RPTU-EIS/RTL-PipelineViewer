#!/usr/bin/env python
"""
Pipeline visualization generator: Interactive Animation View with Hazard Detection.

This script generates an HTML file that visualizes the pipeline activity
as an interactive animation, allowing users to step through each clock cycle.
It now includes logic to detect and display forwarding hazards based on VCD signals.

It reuses VCD parsing logic and prepares data to be consumed by JavaScript
for dynamic rendering.

Outputs:
  - pipeline_animation.html (HTML file with interactive animation)
"""

from vcdvcd import VCDVCD
import pandas as pd
from collections import defaultdict
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32
import os
import re
import json # Import json for embedding data

# Initialize Capstone for RISC-V 32-bit disassembly
md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
md.detail = True

# --- Configuration ---
VCD_FILE = "dump.vcd" # Your VCD file
CLOCK_SIGNAL = None # Auto-detects if None
stage_signals = { # PC signals for each pipeline stage
    "IF": "HazardDetectionRV32I.core.IFBarrier.io_pc_out",
    "ID": "HazardDetectionRV32I.core.IDBarrier.pcReg",
    "EX": "HazardDetectionRV32I.core.EXBarrier.pcReg",
    "MEM": "HazardDetectionRV32I.core.MEMBarrier.pcReg",
    "WB": "HazardDetectionRV32I.core.WBBarrier.pcReg"
}
instruction_signals = { # Instruction signals for each pipeline stage (hex value)
    "IF": "HazardDetectionRV32I.core.IFBarrier.io_inst_out",
    "ID": "HazardDetectionRV32I.core.IDBarrier.instReg",
    "EX": "HazardDetectionRV32I.core.EXBarrier.instReg",
    "MEM": "HazardDetectionRV32I.core.MEMBarrier.instReg",
    "WB": "HazardDetectionRV32I.core.WBBarrier.instReg"
}
ex_signals = {
    "operandA": "HazardDetectionRV32I.core.EX.io_operandA",
    "operandB": "HazardDetectionRV32I.core.EX.io_operandB",
    "aluResult": "HazardDetectionRV32I.core.EX.io_aluResult",
    "UOP": "HazardDetectionRV32I.core.EX.io_uop"
}
wb_signals = {
    "rd": "HazardDetectionRV32I.core.WB.io_rd",
    "wb_data": "HazardDetectionRV32I.core.WB.io_check_res" # Assuming a signal for data written back
}

# --- NEW: Signals for Hazard Detection and Forwarding Unit ---
hazard_signals = {
    # Register addresses for operands in ID/EX stage
    "rs1_addr": "HazardDetectionRV32I.core.IDBarrier.io_outRS1",
    "rs2_addr": "HazardDetectionRV32I.core.IDBarrier.io_outRS2",

    # Destination register addresses from MEM and WB stages
    "rd_mem_addr": "HazardDetectionRV32I.core.EXBarrier.io_outRD",
    "rd_wb_addr": "HazardDetectionRV32I.core.MEMBarrier.io_outRD",

    # Forwarding unit outputs
    "forwardA": "HazardDetectionRV32I.core.FU.io_forwardA",
    "forwardB": "HazardDetectionRV32I.core.FU.io_forwardB",
}

output_html = "pipeline_animation.html" # Output filename for the animation HTML

# --- Load VCD ---
print(f"Loading VCD file: {VCD_FILE}")
try:
    vcd = VCDVCD(VCD_FILE, store_tvs=True)
except FileNotFoundError:
    print(f"❌ Error: VCD file '{VCD_FILE}' not found. Please ensure it's in the same directory.")
    exit()

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

# --- Extract EX and WB data (delayed) ---
ex_values_by_cycle = [{} for _ in range(num_cycles)]
wb_values_by_cycle = [{} for _ in range(num_cycles)]
hazard_data_raw_by_cycle = [{} for _ in range(num_cycles)] # To store hazard signals before delay

# Helper to extract signal values at each rising edge
def extract_signal_at_cycles(signal_name, default_val=None, base=10):
    if signal_name not in vcd.signals:
        print(f"⚠️ Signal {signal_name} not found in VCD. Using default value {default_val}.")
        return [default_val] * num_cycles
    
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
                values.append(int(last_val, base))
            except ValueError:
                values.append(default_val)
        else:
            values.append(default_val)
    return values

for key, signal_name in ex_signals.items():
    vals = extract_signal_at_cycles(signal_name, default_val=None, base=2)
    for cycle_idx, val in enumerate(vals):
        ex_values_by_cycle[cycle_idx][key] = val

for key, signal_name in wb_signals.items():
    vals = extract_signal_at_cycles(signal_name, default_val=None, base=2)
    for cycle_idx, val in enumerate(vals):
        wb_values_by_cycle[cycle_idx][key] = val

# Extract hazard signals (before delaying them)
for key, signal_name in hazard_signals.items():
    vals = extract_signal_at_cycles(signal_name, default_val=0, base=2) # Default to 0 for register addresses/forwarding codes
    for cycle_idx, val in enumerate(vals):
        hazard_data_raw_by_cycle[cycle_idx][key] = val

# Delay EX and WB values for correct association
delayed_ex_values_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1, num_cycles):
    delayed_ex_values_by_cycle[i] = ex_values_by_cycle[i-1]

delayed_wb_values_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1, num_cycles):
    delayed_wb_values_by_cycle[i] = wb_values_by_cycle[i-1]

# NEW: Delay hazard data by one cycle
delayed_hazard_data_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1, num_cycles):
    delayed_hazard_data_by_cycle[i] = hazard_data_raw_by_cycle[i-1]

# Calculate RD_wb_2 (2-cycle delayed WB RD)
# This assumes rd_wb_addr is the RD from the WB stage
rd_wb_addr_values = extract_signal_at_cycles(hazard_signals["rd_wb_addr"], default_val=0, base=2)
delayed_rd_wb_2_cycles_ago = [0] * num_cycles # Default to 0 if no value
for i in range(2, num_cycles):
    delayed_rd_wb_2_cycles_ago[i] = rd_wb_addr_values[i-2]


def convert_hex_immediates_to_decimal(disasm: str) -> str:
    """
    Converts all 0xNNN style immediates in a disassembled instruction to signed decimal.
    For example: 'addi tp, zero, 0x77f' → 'addi tp, zero, 2047'
    """
    def replace_hex(match):
        hex_str = match.group(0)
        value = int(hex_str, 16)
        # Convert to signed 12-bit or 32-bit if needed
        if value >= 0x800:  # signed 12-bit immediate check (for RV32I typical format)
            value -= 0x1000
        return str(value)
    return re.sub(r'0x[0-9a-fA-F]+', replace_hex, disasm)

# --- Collect PC → Instruction Hex (Binary/Raw) and Disassemble ---
actual_pc_to_instr_raw = {}
actual_pc_to_instr_hex_display = {}
actual_pc_to_disassembled_instr = {}

for stage_name, pc_signal_name in stage_signals.items():
    instr_signal_name = instruction_signals.get(stage_name)
    if pc_signal_name not in vcd.signals or instr_signal_name not in vcd.signals:
        continue

    pc_tv = sorted(vcd[pc_signal_name].tv, key=lambda x: x[0])
    instr_tv = sorted(vcd[instr_signal_name].tv, key=lambda x: x[0])

    all_signal_times_for_stage = sorted(list(set([t for t, _ in pc_tv] + [t for t, _ in instr_tv])))

    current_pc_val = None
    current_instr_raw_val = None
    pc_idx = 0
    instr_idx = 0

    for t in all_signal_times_for_stage:
        while pc_idx < len(pc_tv) and pc_tv[pc_idx][0] <= t:
            try:
                current_pc_val = int(pc_tv[pc_idx][1], 16)
            except ValueError:
                current_pc_val = None
            pc_idx += 1
        
        while instr_idx < len(instr_tv) and instr_tv[instr_idx][0] <= t:
            current_instr_raw_val = instr_tv[instr_idx][1]
            instr_idx += 1
        
        if current_pc_val is not None and current_instr_raw_val is not None and 'x' not in current_instr_raw_val.lower():
            actual_pc_to_instr_raw[current_pc_val] = current_instr_raw_val
            instr_hex_for_bytes = ""
            instr_display_str = current_instr_raw_val

            try:
                if len(current_instr_raw_val) == 32 and all(c in '01' for c in current_instr_raw_val):
                    instr_hex_for_bytes = f"{int(current_instr_raw_val, 2):08x}"
                    instr_display_str = instr_hex_for_bytes
                elif all(c in '0123456789abcdef' for c in current_instr_raw_val.lower()):
                    instr_hex_for_bytes = f"{int(current_instr_raw_val, 16):08x}"
                    instr_display_str = instr_hex_for_bytes
                else:
                    instr_hex_for_bytes = ""
                    instr_display_str = "INVALID_INSTR_FORMAT"
            except ValueError:
                instr_hex_for_bytes = ""
                instr_display_str = "CONVERSION_ERROR"

            actual_pc_to_instr_hex_display[current_pc_val] = instr_display_str

            if current_pc_val not in actual_pc_to_disassembled_instr:
                disassembled_text = "N/A_ASM"
                operand_info_lines = []
                if instr_hex_for_bytes:
                    try:
                        instr_bytes = bytes.fromhex(instr_hex_for_bytes)
                        instr_bytes_le = instr_bytes[::-1]
                        disassembled = list(md.disasm(instr_bytes_le, current_pc_val))
                        if disassembled:
                            insn = disassembled[0]
                            disassembled_text = f"{insn.mnemonic} {insn.op_str}"
                            disassembled_text = convert_hex_immediates_to_decimal(disassembled_text)
                            if insn.mnemonic in {"addi", "andi", "ori", "xori", "slti", "sltiu", "slli", "srli", "srai"}:
                                if len(insn.operands) == 3:
                                    rd  = insn.reg_name(insn.operands[0].reg)
                                    rs1 = insn.reg_name(insn.operands[1].reg)
                                    imm = insn.operands[2].imm
                                    operand_info_lines = [f"rd = {rd}", f"rs1 = {rs1}", f"imm = {imm}"]
                            elif insn.mnemonic in {"add", "sub", "sll", "slt", "sltu", "xor", "srl", "sra", "or", "and"}:
                                if len(insn.operands) == 3:
                                    rd  = insn.reg_name(insn.operands[0].reg)
                                    rs1 = insn.reg_name(insn.operands[1].reg)
                                    rs2 = insn.reg_name(insn.operands[2].reg)
                                    operand_info_lines = [f"rd = {rd}", f"rs1 = {rs1}", f"rs2 = {rs2}"]
                        else:
                            disassembled_text = "N/A_ASM"
                    except Exception as e:
                        disassembled_text = f"N/A_ASM (Error: {e})"
                actual_pc_to_disassembled_instr[current_pc_val] = {"asm": disassembled_text, "operands": operand_info_lines}

print(f"Collected {len(actual_pc_to_instr_raw)} PC → Instruction raw mappings, "
      f"{len(actual_pc_to_instr_hex_display)} hex mappings, and "
      f"{len(actual_pc_to_disassembled_instr)} disassemblies from VCD.")

# --- Build timeline (cycle_stage_pc) ---
cycle_stage_pc = [{stage: None for stage in stage_signals} for _ in range(num_cycles)]

for stage, signal_name in stage_signals.items():
    if signal_name not in vcd.signals:
        print(f"⚠️ Warning: Signal {signal_name} for stage {stage} not found in VCD.")
        continue
    signal_tv = sorted(vcd[signal_name].tv, key=lambda x: x[0])
    last_valid_pc_seen = None
    for _, val in signal_tv:
        if 'x' not in val.lower():
            try:
                last_valid_pc_seen = int(val, 16)
                break
            except ValueError:
                pass
    tv_idx = 0
    for cycle_idx, rise_time in enumerate(rising_edges):
        while tv_idx < len(signal_tv) and signal_tv[tv_idx][0] <= rise_time:
            val = signal_tv[tv_idx][1]
            if 'x' not in val.lower():
                try:
                    last_valid_pc_seen = int(val, 16)
                except ValueError:
                    pass
            tv_idx += 1
        cycle_stage_pc[cycle_idx][stage] = last_valid_pc_seen

print("Successfully populated cycle_stage_pc matrix.")

# --- Collect all unique actual PC values from VCD and assign re-indexed (synthetic) PCs ---
vcd_unique_actual_pcs_ordered = []
vcd_actual_to_synthetic_pc_map = {}
synthetic_pc_counter = 0

TARGET_INSTR_HEX_BINARY_FOR_SYNTH_0 = "00000013"
initial_actual_pc_for_target_instr = None
for actual_pc, instr_raw_val in actual_pc_to_instr_raw.items():
    try:
        if len(instr_raw_val) == 32 and all(c in '01' for c in instr_raw_val):
            observed_hex_str = f"{int(instr_raw_val, 2):08x}"
        elif all(c in '0123456789abcdef' for c in instr_raw_val.lower()):
            observed_hex_str = f"{int(instr_raw_val, 16):08x}"
        else:
            continue
        if observed_hex_str == TARGET_INSTR_HEX_BINARY_FOR_SYNTH_0:
            initial_actual_pc_for_target_instr = actual_pc
            break
    except ValueError:
        continue

if initial_actual_pc_for_target_instr is not None:
    vcd_actual_to_synthetic_pc_map[initial_actual_pc_for_target_instr] = 0x0
    vcd_unique_actual_pcs_ordered.append(initial_actual_pc_for_target_instr)
    synthetic_pc_counter = 4
    print(f"✅ Explicitly mapped actual PC 0x{initial_actual_pc_for_target_instr:08x} (for instruction 0x{TARGET_INSTR_HEX_BINARY_FOR_SYNTH_0}) to hex PC 0x00000000.")
else:
    print(f"⚠️ Warning: Instruction 0x{TARGET_INSTR_HEX_BINARY_FOR_SYNTH_0} not found in VCD instruction signals.  PC(hex) 0x00000000 will be assigned to the first observed PC.")

for cycle_idx in range(num_cycles):
    for stage_name in stage_signals.keys():
        actual_pc_in_stage = cycle_stage_pc[cycle_idx][stage_name]
        if actual_pc_in_stage is not None and actual_pc_in_stage not in vcd_actual_to_synthetic_pc_map:
            vcd_actual_to_synthetic_pc_map[actual_pc_in_stage] = synthetic_pc_counter
            vcd_unique_actual_pcs_ordered.append(actual_pc_in_stage)
            synthetic_pc_counter += 4

print(f"Assigned re-assigned PCs to {len(vcd_unique_actual_pcs_ordered)} unique actual PCs from VCD.")

# --- Prepare data for HTML/JS animation ---
# This will store the pipeline state for each instruction across all cycles
# Format: {synthetic_pc: {cycle_idx: {stage: 'STAGE_NAME', tooltip: 'TOOLTIP_TEXT', display_text: 'SHORT_DISPLAY', hazard_info: {...}}}}
pipeline_data_for_js = defaultdict(lambda: [None] * num_cycles)

for cycle_idx in range(num_cycles):
    for stage, actual_pc in cycle_stage_pc[cycle_idx].items():
        if actual_pc is not None and actual_pc in vcd_actual_to_synthetic_pc_map:
            synthetic_pc = vcd_actual_to_synthetic_pc_map[actual_pc]
            
            tooltip_content = f"Stage: {stage}\n"
            tooltip_content += f"PC: 0x{actual_pc:08x}\n"
            dis_info = actual_pc_to_disassembled_instr.get(actual_pc, {})
            disassembled_text = dis_info.get("asm", "N/A_ASM")
            tooltip_content += f"Instruction (ASM): {disassembled_text}\n"

            display_text = stage # Default short display
            hazard_info = {"forwardA": 0, "forwardB": 0} # Default no forwarding

            if stage == "EX":
                ex_data = delayed_ex_values_by_cycle[cycle_idx]
                
                # Use the DELAYED hazard data for the current cycle
                current_hazard_data = delayed_hazard_data_by_cycle[cycle_idx] 
                forwardA_val = current_hazard_data.get("forwardA", 0)
                forwardB_val = current_hazard_data.get("forwardB", 0)
                rs1_addr = current_hazard_data.get("rs1_addr")
                rs2_addr = current_hazard_data.get("rs2_addr")
                rd_mem_addr = current_hazard_data.get("rd_mem_addr")
                rd_wb_addr = current_hazard_data.get("rd_wb_addr")
                rd_wb_2_ago = delayed_rd_wb_2_cycles_ago[cycle_idx] # Our calculated 2-cycle delayed RD_wb

                hazard_info["forwardA"] = forwardA_val
                hazard_info["forwardB"] = forwardB_val

                if forwardA_val != 0 or forwardB_val != 0:
                    tooltip_content += "\n--- Forwarding Detected ---\n"
                    if forwardA_val == 1:
                        tooltip_content += f"ForwardA: MEM/EX (RS1: x{rs1_addr} from MEM RD: x{rd_mem_addr})\n"
                    elif forwardA_val == 2:
                        tooltip_content += f"ForwardA: WB/EX (RS1: x{rs1_addr} from WB RD: x{rd_wb_addr})\n"
                    elif forwardA_val == 3:
                        tooltip_content += f"ForwardA: WB/EX (RS1: x{rs1_addr} from WB RD (2 cycles ago): x{rd_wb_2_ago})\n"
                    elif forwardA_val == 0 and rs1_addr is not None and rs1_addr != 0:
                        # If rs1 is used but no forwarding, it might be a stall or no dependency
                        tooltip_content += f"ForwardA: None for RS1 (x{rs1_addr})\n"

                    if forwardB_val == 1:
                        tooltip_content += f"ForwardB: MEM/EX (RS2: x{rs2_addr} from MEM RD: x{rd_mem_addr})\n"
                    elif forwardB_val == 2:
                        tooltip_content += f"ForwardB: WB/EX (RS2: x{rs2_addr} from WB RD: x{rd_wb_addr})\n"
                    elif forwardB_val == 3:
                        tooltip_content += f"ForwardB: WB/EX (RS2: x{rs2_addr} from WB RD (2 cycles ago): x{rd_wb_2_ago})\n"
                    elif forwardB_val == 0 and rs2_addr is not None and rs2_addr != 0:
                        tooltip_content += f"ForwardB: None for RS2 (x{rs2_addr})\n"
                
                if ex_data and all(k in ex_data for k in ["operandA", "operandB", "aluResult"]):
                    operator = disassembled_text.split()[0].upper() if isinstance(disassembled_text, str) else "?"
                    tooltip_content += f"ALU Operation: {ex_data['operandA']} {operator} {ex_data['operandB']}\n"
                    tooltip_content += f"ALU Result: {ex_data['aluResult']}"
                    display_text = f"EX ({ex_data['aluResult']})"
                else:
                    tooltip_content += "Incomplete ALU data."
            elif stage == "WB":
                wb_data = delayed_wb_values_by_cycle[cycle_idx]
                if wb_data and all(k in wb_data for k in ["rd", "wb_data"]):
                    tooltip_content += f"Write Register (rd): ${wb_data['rd']}\n"
                    tooltip_content += f"Write Data: {wb_data['wb_data']}"
                    display_text = f"WB (${wb_data['rd']})"
                else:
                    tooltip_content += "Incomplete WB data."
            
            pipeline_data_for_js[synthetic_pc][cycle_idx] = {
                "stage": stage,
                "tooltip": tooltip_content,
                "display_text": display_text,
                "hazard_info": hazard_info # NEW: Add hazard info
            }

# Convert defaultdict to regular dict for JSON serialization
pipeline_data_for_js_serializable = {
    str(pc): cycle_data for pc, cycle_data in pipeline_data_for_js.items()
}

# Also need instruction labels for JS
instruction_labels_for_js = []
for synthetic_pc in sorted(pipeline_data_for_js.keys()):
    actual_pc = None
    for apc, spc in vcd_actual_to_synthetic_pc_map.items():
        if spc == synthetic_pc:
            actual_pc = apc
            break
    instr_hex_display = actual_pc_to_instr_hex_display.get(actual_pc, "N/A_HEX")
    dis_info = actual_pc_to_disassembled_instr.get(actual_pc, {})
    asm_display = dis_info.get("asm", "N/A_ASM")
    instruction_labels_for_js.append(f"PC_0x{synthetic_pc:08x} | {instr_hex_display} ({asm_display})")


# --- HTML Generation for Animation (FIXED) ---
color_map_js = json.dumps({
    "IF": "#4da6ff", "ID": "#5cd65c", "EX": "#ff9933",
    "MEM": "#b366ff", "WB": "#ff4d4d", "STALL": "#bfbfbf"
})
# The `format()` method is used here to safely inject the Python variables
# without interfering with the JavaScript template literals (like `${currentCycle}`).
html_content = """
<html>
<head>
<title>Pipeline Animation</title>
<style>
body {{ font-family: sans-serif; margin: 20px; }}
h2 {{ text-align: center; }}
.controls {{
    text-align: center;
    margin-bottom: 20px;
}}
.controls button {{
    padding: 10px 20px;
    font-size: 16px;
    margin: 0 5px;
    cursor: pointer;
    border: 1px solid #ccc;
    border-radius: 5px;
    background-color: #f0f0f0;
}}
.controls button:hover {{
    background-color: #e0e0e0;
}}
#cycleCounter {{
    font-size: 18px;
    font-weight: bold;
    margin: 0 15px;
}}
.pipeline-grid {{
    display: grid;
    grid-template-columns: 400px repeat(5, 120px); /* Fixed width for all columns */
    border: 1px solid #ccc;
    width: fit-content;
    margin: 0 auto;
}}
.grid-header, .grid-cell {{
    padding: 8px;
    border: 1px solid #eee;
    text-align: center;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}}
.grid-header {{
    background-color: #ddd;
    font-weight: bold;
}}
.instruction-label {{
    text-align: left;
    background-color: #f9f9f9;
    font-weight: bold;
}}
.stage-cell {{
    height: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}}
.stage-content {{
    width: 90%;
    height: 80%;
    border-radius: 5px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    color: #333;
    cursor: help;
    box-sizing: border-box;
    padding: 0 5px;
    transition: all 0.2s ease-in-out; /* Smooth transition for highlight */
}}
.tooltip-text {{
    visibility: hidden;
    background-color: #555;
    color: #fff;
    text-align: left;
    border-radius: 6px;
    padding: 8px;
    position: absolute;
    z-index: 10;
    bottom: 125%;
    left: 50%;
    transform: translateX(-50%);
    opacity: 0;
    transition: opacity 0.3s;
    width: 250px;
    white-space: pre-wrap;
    pointer-events: none; /* Allows clicks through tooltip to elements below */
}}
.stage-content:hover .tooltip-text {{
    visibility: visible;
    opacity: 1;
}}
.forwarding-highlight {{
    border: 3px solid #FFD700; /* Gold border for forwarding, thicker */
    box-shadow: 0 0 10px rgba(255, 215, 0, 0.7); /* More prominent shadow */
    background-color: #FFFACD !important; /* Lemon Chiffon background */
}}
.legend {{
    margin-top: 20px;
    text-align: center;
    font-size: 14px;
    width: fit-content; /* Make legend fit its content */
    margin: 20px auto; /* Center the legend */
}}
.legend-item {{
    display: inline-flex;
    align-items: center;
    margin: 0 10px;
}}
.legend-color-box {{
    width: 20px;
    height: 20px;
    border-radius: 4px;
    margin-right: 8px; /* Add space between box and text */
    border: 2px solid #FFD700; /* Matching border for consistency */
    box-shadow: 0 0 5px rgba(255, 215, 0, 0.5);
    background-color: #FFFACD; /* Matching background */
}}
</style>
</head>
<body>
<h2>Pipeline Animation</h2>

<div class="controls">
    <button id="prevBtn">Previous Cycle</button>
    <span id="cycleCounter">Cycle ${{currentCycle}} / ${{numCycles_py}}</span>
    <button id="nextBtn">Next Cycle</button>
    <button id="playPauseBtn">Play</button>
</div>

<div class="legend">
    <div class="legend-item">
        <div class="legend-color-box"></div>
        <span>Hazard/Forwarding Detected</span>
    </div>
</div>

<div id="pipelineDisplay" class="pipeline-grid">
    <div class="grid-header">Instruction</div>
    <div class="grid-header">IF</div>
    <div class="grid-header">ID</div>
    <div class="grid-header">EX</div>
    <div class="grid-header">MEM</div>
    <div class="grid-header">WB</div>
</div>

<script>
    const pipelineData = {pipeline_data_for_js_serializable_py};
    const instructionLabels = {instruction_labels_for_js_py};
    const numCycles = {num_cycles_py};
    const colorMap = {color_map_js_py};

    let currentCycle = 0;
    let animationInterval = null;
    const animationSpeed = 500; // milliseconds per cycle

    const pipelineDisplay = document.getElementById('pipelineDisplay');
    const cycleCounter = document.getElementById('cycleCounter');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const playPauseBtn = document.getElementById('playPauseBtn');

    function updatePipelineDisplay() {{
        // Clear previous instruction rows (keep headers)
        while (pipelineDisplay.children.length > 6) {{ // 6 is number of headers
            pipelineDisplay.removeChild(pipelineDisplay.lastChild);
        }}

        cycleCounter.textContent = `Cycle ${{currentCycle}} / ${{numCycles - 1}}`;

        instructionLabels.forEach((label, instrIdx) => {{
            const syntheticPc = Object.keys(pipelineData)[instrIdx]; // Get synthetic PC string

            const labelDiv = document.createElement('div');
            labelDiv.className = 'grid-cell instruction-label';
            labelDiv.textContent = label;
            pipelineDisplay.appendChild(labelDiv);

            const stages = ["IF", "ID", "EX", "MEM", "WB"];
            stages.forEach(stageName => {{
                const stageCell = document.createElement('div');
                stageCell.className = 'grid-cell stage-cell';

                const instrCycleData = pipelineData[syntheticPc] ? pipelineData[syntheticPc][currentCycle] : null;

                if (instrCycleData && instrCycleData.stage === stageName) {{
                    const contentDiv = document.createElement('div');
                    contentDiv.className = 'stage-content';
                    contentDiv.style.backgroundColor = colorMap[stageName];
                    contentDiv.textContent = instrCycleData.display_text;

                    // NEW: Add forwarding highlight
                    if (stageName === "EX" && (instrCycleData.hazard_info.forwardA !== 0 || instrCycleData.hazard_info.forwardB !== 0)) {{
                        contentDiv.classList.add('forwarding-highlight');
                    }}

                    const tooltipSpan = document.createElement('span');
                    tooltipSpan.className = 'tooltip-text';
                    tooltipSpan.textContent = instrCycleData.tooltip;
                    contentDiv.appendChild(tooltipSpan);
                    
                    stageCell.appendChild(contentDiv);
                }}
                pipelineDisplay.appendChild(stageCell);
            }});
        }});

        prevBtn.disabled = currentCycle === 0;
        nextBtn.disabled = currentCycle === numCycles - 1;
    }}

    function nextCycle() {{
        if (currentCycle < numCycles - 1) {{
            currentCycle++;
            updatePipelineDisplay();
        }} else {{
            // Stop animation if it reaches the end
            stopAnimation();
        }}
    }}

    function prevCycle() {{
        if (currentCycle > 0) {{
            currentCycle--;
            updatePipelineDisplay();
        }}
    }}

    function startAnimation() {{
        if (animationInterval) return; // Already running
        playPauseBtn.textContent = 'Pause';
        animationInterval = setInterval(() => {{
            if (currentCycle < numCycles - 1) {{
                nextCycle();
            }} else {{
                stopAnimation();
            }}
        }}, animationSpeed);
    }}

    function stopAnimation() {{
        clearInterval(animationInterval);
        animationInterval = null;
        playPauseBtn.textContent = 'Play';
    }}

    prevBtn.addEventListener('click', prevCycle);
    nextBtn.addEventListener('click', nextCycle);
    playPauseBtn.addEventListener('click', () => {{
        if (animationInterval) {{
            stopAnimation();
        }} else {{
            startAnimation();
        }}
    }});

    // NEW: Keyboard navigation
    document.addEventListener('keydown', (event) => {{
        if (event.key === 'ArrowRight') {{
            nextCycle();
        }} else if (event.key === 'ArrowLeft') {{
            prevCycle();
        }}
    }});

    // Initial display
    updatePipelineDisplay();
</script>
</body>
</html>
""".format(
    num_cycles_py=num_cycles,
    pipeline_data_for_js_serializable_py=json.dumps(pipeline_data_for_js_serializable),
    instruction_labels_for_js_py=json.dumps(instruction_labels_for_js),
    color_map_js_py=color_map_js
)

# --- Write the final HTML file ---
print(f"Writing output to {output_html}")
with open(output_html, "w") as f:
    f.write(html_content)

print(f"✅ Successfully generated '{output_html}'. Open this file in your web browser to view the animation.")
