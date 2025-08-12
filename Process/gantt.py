#!/usr/bin/env python
"""
Pipeline visualization generator: Gantt-style Timeline View.

This script generates an HTML file that visualizes the pipeline activity
as a Gantt chart, showing the lifespan of each instruction across pipeline stages
and cycles.

It reuses VCD parsing logic from previous versions and adapts it for a
horizontal bar representation.

Outputs:
  - pipeline_gantt.html (HTML file with the Gantt chart visualization)
"""

from vcdvcd import VCDVCD
import pandas as pd
from collections import defaultdict
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32
import os
import re
from binascii import unhexlify

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
    "aluResult": "HazardDetectionRV2I.core.EX.io_aluResult",
    "UOP": "HazardDetectionRV32I.core.EX.io_uop"
}
wb_signals = {
    "rd": "HazardDetectionRV32I.core.WB.io_rd",
    "wb_data": "HazardDetectionRV32I.core.WB.io_check_res" # Assuming a signal for data written back
}

output_html = "pipeline_gantt.html" # Output filename for the Gantt chart

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

for key, signal_name in ex_signals.items():
    if signal_name not in vcd.signals:
        print(f"⚠️ Signal {signal_name} not found in VCD.")
        continue
    tv_sorted = sorted(vcd[signal_name].tv, key=lambda x: x[0])
    last_val = None
    idx = 0
    for cycle_idx, rise_time in enumerate(rising_edges):
        while idx < len(tv_sorted) and tv_sorted[idx][0] <= rise_time:
            last_val = tv_sorted[idx][1]
            idx += 1
        try:
            if last_val is not None and 'x' not in last_val.lower():
                ex_values_by_cycle[cycle_idx][key] = int(last_val, 2)
        except Exception:
            ex_values_by_cycle[cycle_idx][key] = None

for key, signal_name in wb_signals.items():
    if signal_name not in vcd.signals:
        print(f"⚠️ Signal {signal_name} not found in VCD.")
        continue
    tv_sorted = sorted(vcd[signal_name].tv, key=lambda x: x[0])
    last_val = None
    idx = 0
    for cycle_idx, rise_time in enumerate(rising_edges):
        while idx < len(tv_sorted) and tv_sorted[idx][0] <= rise_time:
            last_val = tv_sorted[idx][1]
            idx += 1
        try:
            if last_val is not None and 'x' not in last_val.lower():
                wb_values_by_cycle[cycle_idx][key] = int(last_val, 2)
        except Exception:
            wb_values_by_cycle[cycle_idx][key] = None

# Delay EX and WB values for correct association
delayed_ex_values_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1, num_cycles):
    delayed_ex_values_by_cycle[i] = ex_values_by_cycle[i-1]

delayed_wb_values_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1, num_cycles):
    delayed_wb_values_by_cycle[i] = wb_values_by_cycle[i-1]


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
        elif all(c in '0123456789abcdef' for c in instr_instr_raw_val.lower()):
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

# --- Instruction Lifespan and Stage Occupancy ---
# Stores {synthetic_pc: {stage: [start_cycle, end_cycle]}}
instruction_timeline = defaultdict(lambda: defaultdict(lambda: [None, None]))
# Stores {synthetic_pc: {cycle_idx: tooltip_text}}
instruction_tooltips = defaultdict(lambda: [''] * num_cycles)

for cycle_idx in range(num_cycles):
    for stage, actual_pc in cycle_stage_pc[cycle_idx].items():
        if actual_pc is not None and actual_pc in vcd_actual_to_synthetic_pc_map:
            synthetic_pc = vcd_actual_to_synthetic_pc_map[actual_pc]
            
            # Update start/end cycles for the stage
            if instruction_timeline[synthetic_pc][stage][0] is None:
                instruction_timeline[synthetic_pc][stage][0] = cycle_idx
            instruction_timeline[synthetic_pc][stage][1] = cycle_idx # Always update end to current cycle

            # Build tooltip for this specific instruction and stage at this cycle
            tooltip_content = f"Stage: {stage}\n"
            tooltip_content += f"PC: 0x{actual_pc:08x}\n"
            dis_info = actual_pc_to_disassembled_instr.get(actual_pc, {})
            disassembled_text = dis_info.get("asm", "N/A_ASM")
            tooltip_content += f"Instruction (ASM): {disassembled_text}\n"

            if stage == "EX":
                ex_data = delayed_ex_values_by_cycle[cycle_idx]
                if ex_data and all(k in ex_data for k in ["operandA", "operandB", "aluResult"]):
                    operator = disassembled_text.split()[0].upper() if isinstance(disassembled_text, str) else "?"
                    tooltip_content += f"ALU Operation: {ex_data['operandA']} {operator} {ex_data['operandB']}\n"
                    tooltip_content += f"ALU Result: {ex_data['aluResult']}"
                else:
                    tooltip_content += "Incomplete ALU data."
            elif stage == "WB":
                wb_data = delayed_wb_values_by_cycle[cycle_idx]
                if wb_data and all(k in wb_data for k in ["rd", "wb_data"]):
                    tooltip_content += f"Write Register (rd): ${wb_data['rd']}\n"
                    tooltip_content += f"Write Data: {wb_data['wb_data']}"
                else:
                    tooltip_content += "Incomplete WB data."
            
            instruction_tooltips[synthetic_pc][cycle_idx] = tooltip_content

# Sort instructions by their synthetic PC for consistent display
sorted_synthetic_pcs = sorted(instruction_timeline.keys())

# --- HTML Generation for Gantt Chart ---
color_map = {
    "IF": "#4da6ff", "ID": "#5cd65c", "EX": "#ff9933",
    "MEM": "#b366ff", "WB": "#ff4d4d", "STALL": "#bfbfbf"
}

html_header = f"""
<html>
<head>
<title>Pipeline Gantt Chart</title>
<style>
body {{ font-family: sans-serif; margin: 20px; }}
h2 {{ text-align: center; }}
.gantt-container {{
    width: 100%;
    overflow-x: auto;
    border: 1px solid #ccc;
    padding: 10px;
    box-sizing: border-box;
}}
.gantt-chart {{
    display: grid;
    grid-template-columns: auto repeat({num_cycles}, 50px); /* Adjust 50px for cycle width */
    grid-auto-rows: minmax(30px, auto);
    border-collapse: collapse;
}}
.header-cell {{
    background-color: #eee;
    font-weight: bold;
    padding: 5px;
    text-align: center;
    border: 1px solid #ddd;
    position: sticky;
    top: 0;
    z-index: 2;
}}
.row-label {{
    background-color: #f9f9f9;
    font-weight: bold;
    padding: 5px;
    text-align: left;
    border: 1px solid #ddd;
    position: sticky;
    left: 0;
    z-index: 1;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 150px; /* Adjust as needed */
}}
.cycle-cell {{
    border: 1px solid #eee;
    position: relative;
    height: 30px; /* Height of each row */
}}
.gantt-bar {{
    position: absolute;
    height: 80%; /* Make bars slightly smaller than cell height */
    top: 10%;
    border-radius: 3px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 10px;
    color: #333;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    padding: 0 2px;
    box-sizing: border-box;
    cursor: help; /* Indicates tooltip */
}}
.tooltip {{
    position: relative;
    display: inline-block;
}}
.tooltip .tooltiptext {{
    visibility: hidden;
    background-color: #555;
    color: #fff;
    text-align: left;
    border-radius: 6px;
    padding: 8px;
    position: absolute;
    z-index: 3;
    bottom: 125%;
    left: 50%;
    margin-left: -100px;
    opacity: 0;
    transition: opacity 0.3s;
    width: 200px;
    white-space: pre-wrap;
}}
.tooltip:hover .tooltiptext {{
    visibility: visible;
    opacity: 1;
}}
</style>
</head>
<body>
<h2>Pipeline Gantt Chart</h2>
<div class="gantt-container">
    <div class="gantt-chart">
        <div class="header-cell">Instruction</div>
"""

# Cycle headers
for c in range(num_cycles):
    html_header += f'<div class="header-cell">C{c}</div>'

# Instruction rows
html_rows = ""
for synthetic_pc in sorted_synthetic_pcs:
    actual_pc = None
    # Find the actual PC corresponding to this synthetic PC
    for apc, spc in vcd_actual_to_synthetic_pc_map.items():
        if spc == synthetic_pc:
            actual_pc = apc
            break

    instr_hex_display = actual_pc_to_instr_hex_display.get(actual_pc, "N/A_HEX")
    dis_info = actual_pc_to_disassembled_instr.get(actual_pc, {})
    asm_display = dis_info.get("asm", "N/A_ASM")
    
    row_label_text = f"PC_0x{synthetic_pc:08x} | {instr_hex_display} ({asm_display})"
    html_rows += f'<div class="row-label" title="{row_label_text}">{row_label_text}</div>'

    for cycle_idx in range(num_cycles):
        html_rows += f'<div class="cycle-cell">'
        
        # Find which stage this instruction is in at this cycle
        current_stage = None
        for stage, pc_in_stage in cycle_stage_pc[cycle_idx].items():
            if pc_in_stage == actual_pc:
                current_stage = stage
                break
        
        # If instruction is in a stage, draw a bar
        if current_stage:
            bar_color = color_map.get(current_stage, "#ccc")
            # The bar spans one cycle, so width is 100% of the cell
            # Position is relative to the cell, so left is 0
            
            tooltip_text = instruction_tooltips[synthetic_pc][cycle_idx]
            
            # Short display text for the bar
            display_text = current_stage
            if current_stage == "IF":
                display_text = "IF"
            elif current_stage == "ID":
                display_text = "ID"
            elif current_stage == "EX":
                ex_data = delayed_ex_values_by_cycle[cycle_idx]
                if ex_data and all(k in ex_data for k in ["operandA", "operandB", "aluResult"]):
                    display_text = f"EX ({ex_data['aluResult']})" # Show result in bar
            elif current_stage == "WB":
                wb_data = delayed_wb_values_by_cycle[cycle_idx]
                if wb_data and all(k in wb_data for k in ["rd", "wb_data"]):
                    display_text = f"WB (${wb_data['rd']})" # Show rd in bar

            html_rows += f"""
            <div class="gantt-bar tooltip" style="background-color: {bar_color}; width: 100%; left: 0;">
                {display_text}
                <span class="tooltiptext">{tooltip_text}</span>
            </div>
            """
        html_rows += '</div>'
html_rows += """
    </div>
</div>
</body>
</html>
"""

with open(output_html, "w") as f:
    f.write(html_header + html_rows)

print(f"\n✅ Gantt chart saved to {output_html}")
print("\n--- First 15 ALU Operations from VCD (for reference) ---")
for i in range(min(15, len(delayed_ex_values_by_cycle))):
    entry = delayed_ex_values_by_cycle[i]
    pc = None
    # Find PC for EX stage at this cycle (if available)
    for stage_data in cycle_stage_pc[i].values():
        if stage_data is not None and stage_data in vcd_actual_to_synthetic_pc_map:
            pc = stage_data
            break
    
    if entry and all(k in entry for k in ["operandA", "operandB", "aluResult"]) and pc is not None:
        print(f"Cycle {i} (PC: 0x{pc:08x}): {entry['operandA']} ? {entry['operandB']} => {entry['aluResult']}")
    else:
        print(f"Cycle {i}: Incomplete data (or no previous cycle data for cycle 0)")
print("----------------------------------------------------------")

print("\n--- First 15 WB Register Writes from VCD (for reference) ---")
for i in range(min(15, len(delayed_wb_values_by_cycle))):
    entry = delayed_wb_values_by_cycle[i]
    pc = None
    # Find PC for WB stage at this cycle (if available)
    for stage_data in cycle_stage_pc[i].values():
        if stage_data is not None and stage_data in vcd_actual_to_synthetic_pc_map:
            pc = stage_data
            break

    if entry and all(k in entry for k in ["rd", "wb_data"]) and pc is not None:
        print(f"Cycle {i} (PC: 0x{pc:08x}): Write Register ${entry['rd']} <= {entry['wb_data']}")
    else:
        print(f"Cycle {i}: Incomplete data (or no previous cycle data for cycle 0)")
print("----------------------------------------------------------")
