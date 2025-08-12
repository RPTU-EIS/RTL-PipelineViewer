#!/usr/bin/env python
"""
Pipeline visualization generator (synthetic PC mapping).

**What's new in this version (modified vcd11.py):**
1. **Instructions are fetched directly from VCD signals**, not from BinaryFile.txt.
   - Specifically from:
     - "HazardDetectionRV32I.core.IFBarrier.io_inst_out"
     - "HazardDetectionRV32I.core.IDBarrier.instReg"
     - "HazardDetectionRV32I.core.EXBarrier.instReg"
     - "HazardDetectionRV32I.core.MEMBarrier.instReg"
     - "HazardDetectionRV32I.core.WBBarrier.instReg"
2. **Row count limited to unique PCs observed in VCD.**
3. **Synthetic sequential PCs starting at 0x00000000** are assigned to your instructions *in the order their corresponding PC value first appears in any VCD stage signal*.
   **Fix**: The actual PC corresponding to instruction 0x00000013 (your first instruction) is now explicitly mapped to synthetic PC 0x00000000.
4. Pipeline activity from the VCD is mapped **in program-order-of-first-appearance** onto these synthetic PCs. That means: the *first unique PC value observed* in the VCD is treated as *instruction 0*, the second unique PC observed as *instruction 1*, etc., but we LABEL those rows using synthetic PC addresses 0x00000000, 0x00000004, ... so that your HTML shows exactly the format you requested: `PC_0xXXXXXXXX | XXXXXXXX` (where XXXXXXXX is the instruction hex from VCD).
5. Optional Capstone disassembly (if installed) is used **only in tooltips**, not in the row label.
6. STALL detection retained (ID/EX repeats). No FLUSH marking.

Outputs:
  - pipeline_matrix.csv          (PC rows, cycle columns, stage cells)
  - pipeline_matrix.html         (color, tooltips, search; rows show PC | HEX from VCD)
  - (No VCD output file will be generated in this version)

"""

from vcdvcd import VCDVCD
import pandas as pd
from collections import defaultdict
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32
md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
import os

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
instruction_signals = { # NEW: Instruction signals for each pipeline stage (hex value)
    "IF": "HazardDetectionRV32I.core.IFBarrier.io_inst_out",
    "ID": "HazardDetectionRV32I.core.IDBarrier.instReg",
    "EX": "HazardDetectionRV32I.core.EXBarrier.instReg",
    "MEM": "HazardDetectionRV32I.core.MEMBarrier.instReg",
    "WB": "HazardDetectionRV32I.core.WBBarrier.instReg"
}
output_csv = "pipeline_matrix.csv"
output_html = "pipeline_matrix.html"


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


# --- Collect PC → Instruction Hex mapping directly from VCD ---
actual_pc_to_instr_hex_binary = {}

for stage_name, pc_signal_name in stage_signals.items():
    instr_signal_name = instruction_signals.get(stage_name)

    if pc_signal_name not in vcd.signals:
        print(f"⚠️ Warning: PC Signal '{pc_signal_name}' for stage {stage_name} not found in VCD.")
        continue
    if instr_signal_name not in vcd.signals:
        print(f"⚠️ Warning: Instruction Signal '{instr_signal_name}' for stage {stage_name} not found in VCD.")
        continue

    pc_tv = sorted(vcd[pc_signal_name].tv, key=lambda x: x[0])
    instr_tv = sorted(vcd[instr_signal_name].tv, key=lambda x: x[0])

    all_signal_times_for_stage = sorted(list(set([t for t, _ in pc_tv] + [t for t, _ in instr_tv])))

    current_pc_val = None
    current_instr_hex_binary = None
    
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
            current_instr_hex_binary = instr_tv[instr_idx][1]
            instr_idx += 1
        
        if current_pc_val is not None and current_instr_hex_binary is not None and 'x' not in current_instr_hex_binary.lower():
            actual_pc_to_instr_hex_binary[current_pc_val] = current_instr_hex_binary

print(f"Collected {len(actual_pc_to_instr_hex_binary)} PC → Instruction Hex (Binary) mappings from VCD.")


# --- Build timeline (cycle_stage_pc) ---
cycle_stage_pc = [{stage: None for stage in stage_signals} for _ in range(num_cycles)]

for stage, signal_name in stage_signals.items():
    if signal_name not in vcd.signals:
        print(f"⚠️ Warning: Signal {signal_name} not found in VCD.")
        continue
    signal_tv = vcd[signal_name].tv
    
    sorted_signal_tv = sorted(signal_tv, key=lambda x: x[0])

    last_pc_val_seen = None
    for _, val in sorted_signal_tv:
        try:
            initial_pc_val = int(val, 16)
            last_pc_val_seen = initial_pc_val
            break 
        except ValueError:
            continue 

    idx = 0 
    for t, val in sorted_signal_tv:
        try:
            current_pc_val = int(val, 16)
            last_pc_val_seen = current_pc_val 
        except ValueError:
            pass

        while idx < num_cycles and rising_edges[idx] <= t:
            if last_pc_val_seen is not None:
                cycle_stage_pc[idx][stage] = last_pc_val_seen
            idx += 1

    while idx < num_cycles:
        if last_pc_val_seen is not None:
            cycle_stage_pc[idx][stage] = last_pc_val_seen
        idx += 1


# --- Collect all unique actual PC values from VCD and assign synthetic PCs ---
vcd_unique_actual_pcs_ordered = []
vcd_actual_to_synthetic_pc_map = {}
synthetic_pc_counter = 0

# --- FIX START: Prioritize mapping for instruction 0x00000013 to synthetic PC 0x0 ---
TARGET_INSTR_HEX_BINARY_FOR_SYNTH_0 = "00000013" # The instruction hex you expect at PC_0x00000000

initial_actual_pc_for_target_instr = None
for actual_pc, instr_hex_binary in actual_pc_to_instr_hex_binary.items():
    # Convert observed instruction hex binary to int, then to 8-digit hex string for comparison
    try:
        if len(instr_hex_binary) == 32 and all(c in '01' for c in instr_hex_binary):
            # Convert binary string to integer, then to hex, then strip '0x' and pad
            observed_hex_str = f"{int(instr_hex_binary, 2):08x}"
        else: # Handle cases like 'x' or non-binary
            observed_hex_str = instr_hex_binary
        
        if observed_hex_str == TARGET_INSTR_HEX_BINARY_FOR_SYNTH_0:
            initial_actual_pc_for_target_instr = actual_pc
            break
    except ValueError:
        continue # Skip if conversion fails (e.g., 'x' values)

if initial_actual_pc_for_target_instr is not None:
    # If the actual PC for the target instruction is found, assign it to synthetic PC 0x0
    vcd_actual_to_synthetic_pc_map[initial_actual_pc_for_target_instr] = 0x0
    vcd_unique_actual_pcs_ordered.append(initial_actual_pc_for_target_instr)
    synthetic_pc_counter = 4 # Start subsequent synthetic PCs from 0x4
    print(f"✅ Explicitly mapped actual PC 0x{initial_actual_pc_for_target_instr:08x} (for instruction 0x{TARGET_INSTR_HEX_BINARY_FOR_SYNTH_0}) to synthetic PC 0x00000000.")
else:
    print(f"⚠️ Warning: Instruction 0x{TARGET_INSTR_HEX_BINARY_FOR_SYNTH_0} not found in VCD instruction signals. PC_0x00000000 will be assigned to the first observed PC.")


# Iterate through cycles and stages to find the first appearance of each actual PC
for cycle_idx in range(num_cycles):
    for stage_name in stage_signals.keys():
        actual_pc_in_stage = cycle_stage_pc[cycle_idx][stage_name]
        # Only add if it's a new actual PC (not already mapped, especially not the initial_actual_pc)
        if actual_pc_in_stage is not None and actual_pc_in_stage not in vcd_actual_to_synthetic_pc_map:
            vcd_actual_to_synthetic_pc_map[actual_pc_in_stage] = synthetic_pc_counter
            vcd_unique_actual_pcs_ordered.append(actual_pc_in_stage)
            synthetic_pc_counter += 4

# --- FIX END ---

print(f"Assigned synthetic PCs to {len(vcd_unique_actual_pcs_ordered)} unique actual PCs from VCD.")


# --- Build pipeline matrix and tooltips ---
instruction_matrix = defaultdict(lambda: [''] * num_cycles)
tooltips_matrix = defaultdict(lambda: [''] * num_cycles)

# First, populate `ordered_row_labels` which defines the rows of the HTML table
ordered_row_labels = []
for actual_pc in vcd_unique_actual_pcs_ordered:
    synthetic_pc = vcd_actual_to_synthetic_pc_map[actual_pc]
    instr_hex_binary = actual_pc_to_instr_hex_binary.get(actual_pc, "N/A_INSTR")
    
    if instr_hex_binary != "N/A_INSTR" and all(c in '01' for c in instr_hex_binary):
        instr_hex_display = f"{int(instr_hex_binary, 2):08x}"
    else:
        instr_hex_display = instr_hex_binary
    
    row_label = f"PC_0x{synthetic_pc:08x} | {instr_hex_display}"
    ordered_row_labels.append(row_label)

# Initialize matrix and tooltip entries for all planned rows
for row_label in ordered_row_labels:
    instruction_matrix[row_label] = [''] * num_cycles
    tooltips_matrix[row_label] = [''] * num_cycles

# Now, populate with data derived from VCD signals
for cycle_idx, stages_in_cycle in enumerate(cycle_stage_pc):
    for stage, actual_pc in stages_in_cycle.items():
        if actual_pc is not None and actual_pc in vcd_actual_to_synthetic_pc_map:
            synthetic_pc = vcd_actual_to_synthetic_pc_map[actual_pc]
            instr_hex_binary = actual_pc_to_instr_hex_binary.get(actual_pc, "N/A_INSTR")
            
            if instr_hex_binary != "N/A_INSTR" and all(c in '01' for c in instr_hex_binary):
                instr_hex_display = f"{int(instr_hex_binary, 2):08x}"
            else:
                instr_hex_display = instr_hex_binary
            
            display_label = f"PC_0x{synthetic_pc:08x} | {instr_hex_display}"
            
            if display_label not in instruction_matrix:
                instruction_matrix[display_label] = [''] * num_cycles
                tooltips_matrix[display_label] = [''] * num_cycles

            prev_stage_in_cycle = instruction_matrix[display_label][cycle_idx - 1] if cycle_idx > 0 else ''
            
            if stage == prev_stage_in_cycle and stage in ['ID', 'EX', 'MEM'] and instruction_matrix[display_label][cycle_idx] == "":
                instruction_matrix[display_label][cycle_idx] = 'STALL'
            elif instruction_matrix[display_label][cycle_idx] == "":
                instruction_matrix[display_label][cycle_idx] = stage
            
            disassembled_instr = instr_hex_binary
            try:
                if instr_hex_binary != "N/A_INSTR" and all(c in '01' for c in instr_hex_binary):
                    instr_hex_for_bytes = f"{int(instr_hex_binary, 2):08x}"
                    instr_bytes = bytes.fromhex(instr_hex_for_bytes)
                    disassembled = list(md.disasm(instr_bytes, actual_pc))
                    if disassembled:
                        insn = disassembled[0]
                        disassembled_instr = f"{insn.mnemonic} {insn.op_str}"
                else:
                    disassembled_instr = "Not available"
            except ValueError:
                disassembled_instr = f"Invalid Hex/Binary: {instr_hex_binary}"
            except Exception as e:
                disassembled_instr = f"Disassembly Error: {e}"
            
            tooltips_matrix[display_label][cycle_idx] = (
                f"PC (Actual): 0x{actual_pc:08x}\n"
                f"PC (Synthetic): 0x{synthetic_pc:08x}\n"
                f"Instruction (Hex): {instr_hex_display}\n"
                f"Instruction (ASM): {disassembled_instr}\n"
                f"Stage: {instruction_matrix[display_label][cycle_idx]}"
            )

# Create DataFrame from instruction_matrix and sort rows
df = pd.DataFrame.from_dict(instruction_matrix, orient='index', columns=[f"C{c}" for c in range(num_cycles)])

df.index = df.index.map(lambda x: (int(x.split(' | ')[0].split('_0x')[1], 16), x))
df = df.sort_index()
df.index = df.index.map(lambda x: x[1])

tooltips = pd.DataFrame.from_dict(tooltips_matrix, orient='index', columns=[f"C{c}" for c in range(num_cycles)])
tooltips = tooltips.reindex(df.index)

print("\n--- All PC addresses processed into the pipeline matrix ---")
for pc_label in df.index:
    print(pc_label.split(' | ')[0])
print("--------------------------------------------------\n")


# --- Re-Detect Stalls (after initial population to ensure proper marking) ---
color_map_stages = ['IF', 'ID', 'EX', 'MEM', 'WB', 'STALL']
for row_idx, row in df.iterrows():
    for i in range(1, len(row)):
        current_cell_value = row.iloc[i]
        previous_cell_value = row.iloc[i-1]
        
        if current_cell_value == previous_cell_value and current_cell_value in ['ID', 'EX', 'MEM']:
            df.at[row_idx, df.columns[i]] = 'STALL'
            
            current_tooltip = tooltips.at[row_idx, tooltips.columns[i]]
            if "(STALL)" not in current_tooltip:
                tooltips.at[row_idx, tooltips.columns[i]] = current_tooltip.replace(f"Stage: {previous_cell_value}", f"Stage: {previous_cell_value} (STALL)")


# --- Save CSV ---
df.to_csv(output_csv)
print(f"\n✅ Matrix saved to {output_csv}")
print(df.iloc[:10, :25].fillna('').to_string())


# --- HTML with Colors + Tooltips + Search ---
color_map = {
    "IF": "#4da6ff", "ID": "#5cd65c", "EX": "#ff9933",
    "MEM": "#b366ff", "WB": "#ff4d4d", "STALL": "#bfbfbf"
}

html_header = """
<html>
<head>
<style>
body { font-family: sans-serif; }
table {border-collapse: collapse; width: 100%; font-size: 12px; margin-top: 10px;}
th, td {border: 1px solid #999; padding: 4px; text-align: center; white-space: nowrap;}
th {position: sticky; top: 0; background: #ddd; z-index: 2;}
td:first-child, th:first-child {position: sticky; left: 0; background: #eee; z-index: 1;}
input {margin-bottom: 10px; width: 50%; padding: 5px; font-size: 14px;}
.tooltip {position: relative; display: inline-block;}
.tooltip .tooltiptext {
    visibility: hidden; background-color: #555; color: #fff; text-align: left;
    border-radius: 6px; padding: 8px; position: absolute; z-index: 3;
    bottom: 125%; left: 50%; margin-left: -100px;
    opacity: 0; transition: opacity 0.3s;
    width: 200px;
    white-space: pre-wrap;
}
.tooltip:hover .tooltiptext {visibility: visible; opacity: 1;}
</style>
<script>
function searchTable() {
  var input = document.getElementById("searchBox").value.toUpperCase();
  var rows = document.querySelectorAll("table tbody tr");
  rows.forEach(row => {
    row.style.display = row.innerText.toUpperCase().includes(input) ? "" : "none";
  });
}
</script>
</head>
<body>
<h2>Pipeline Visualization</h2>
<input type="text" id="searchBox" onkeyup="searchTable()" placeholder="Search by PC, instruction hex, or assembly...">
<table>
<thead>
<tr><th>PC | Instruction (Hex)</th>
"""

html_header += ''.join(f"<th>{c}</th>" for c in df.columns)
html_header += "</tr></thead><tbody>"

html_rows = ""
for idx in df.index:
    html_rows += f"<tr><td>{idx}</td>"
    for c_idx, val in enumerate(df.loc[idx]):
        color = color_map.get(val, "#fff")
        tooltip_text = tooltips.loc[idx][c_idx]
        html_rows += f'<td style="background:{color}"><div class="tooltip">{val}<span class="tooltiptext">{tooltip_text}</span></div></td>'
    html_rows += "</tr>"

html_footer = "</tbody></table></body></html>"

with open(output_html, "w") as f:
    f.write(html_header + html_rows + html_footer)

print(f"✅ Interactive HTML saved as {output_html}. Open in a browser.")