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
4. Pipeline activity from the VCD is mapped **in program-order-of-first-appearance** onto these synthetic PCs. That means: the *first unique PC value observed* in the VCD is treated as *instruction 0*, the second unique PC observed as *instruction 1*, etc., but we LABEL those rows using synthetic PC addresses 0x00000000, 0x00000004, ... so that your HTML shows exactly the format you requested: `PC_0xXXXXXXXX | XXXXXXXX` (where XXXXXXXX is the instruction hex from VCD).
5. Optional Capstone disassembly (if installed) is used **only in tooltips**, not in the row label.
6. STALL detection retained (ID/EX repeats). No FLUSH marking.

Outputs:
  - pipeline_matrix.csv          (PC rows, cycle columns, stage cells)
  - pipeline_cycle_trace.vcd     (stage waveforms w/ PC per cycle)
  - pipeline_matrix.html         (color, tooltips, search; rows show PC | HEX from VCD)

"""

from vcdvcd import VCDVCD
from vcd.writer import VCDWriter
import pandas as pd
from collections import defaultdict
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32
md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
import os

# --- Configuration ---
VCD_FILE = "dump.vcd" # Your VCD file
# BINARY_FILE is no longer used for instruction lookup, instructions now come from VCD signals
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
output_vcd = "pipeline_cycle_trace.vcd"


# --- Load VCD ---
print(f"Loading VCD file: {VCD_FILE}")
try:
    vcd = VCDVCD(VCD_FILE, store_tvs=True)
except FileNotFoundError:
    print(f"❌ Error: VCD file '{VCD_FILE}' not found. Please ensure it's in the same directory.")
    exit() # Exit if VCD is not found

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


# --- NEW: Collect PC -> Instruction Hex mapping directly from VCD ---
# This dictionary will store actual VCD PCs mapped to their observed instruction hex
actual_pc_to_instr_hex = {}

# Iterate through all stage signals (for PC) and their corresponding instruction signals
# We need to find the instruction hex that corresponds to a given PC
# This is done by looking at the PC and instruction signals simultaneously
all_pc_instr_times = set()
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

    # Combine all unique timestamps from both PC and instruction signals for this stage
    all_signal_times_for_stage = sorted(list(set([t for t, _ in pc_tv] + [t for t, _ in instr_tv])))

    current_pc_val = None
    current_instr_hex = None
    
    # Track last valid values for signals as we advance through time
    pc_idx = 0
    instr_idx = 0

    for t in all_signal_times_for_stage:
        # Update current PC value if a change occurred at or before 't'
        while pc_idx < len(pc_tv) and pc_tv[pc_idx][0] <= t:
            try:
                current_pc_val = int(pc_tv[pc_idx][1], 16)
            except ValueError:
                current_pc_val = None # Value is 'x' or invalid
            pc_idx += 1
        
        # Update current instruction value if a change occurred at or before 't'
        while instr_idx < len(instr_tv) and instr_tv[instr_idx][0] <= t:
            current_instr_hex = instr_tv[instr_idx][1]
            instr_idx += 1
        
        # If both PC and instruction are valid at this timestamp, map them
        if current_pc_val is not None and current_instr_hex is not None and 'x' not in current_instr_hex.lower():
            # Store the latest instruction hex for this PC. This implicitly handles changes.
            actual_pc_to_instr_hex[current_pc_val] = current_instr_hex

print(f"Collected {len(actual_pc_to_instr_hex)} PC -> Instruction Hex mappings from VCD.")


# --- Build timeline (cycle_stage_pc) ---
# This part processes the PC values per cycle, using the actual VCD PC signals
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
            pass # Keep last valid PC if 'x' encountered

        while idx < num_cycles and rising_edges[idx] <= t:
            if last_pc_val_seen is not None:
                cycle_stage_pc[idx][stage] = last_pc_val_seen
            idx += 1

    while idx < num_cycles:
        if last_pc_val_seen is not None:
            cycle_stage_pc[idx][stage] = last_pc_val_seen
        idx += 1


# --- NEW: Collect all unique actual PC values from VCD and assign synthetic PCs ---
# This determines the program order based on the first appearance of actual PCs in the VCD trace.
vcd_unique_actual_pcs_ordered = [] # Ordered list of actual PCs as they first appear in any stage
vcd_actual_to_synthetic_pc_map = {} # Maps actual VCD PC to synthetic PC
synthetic_pc_counter = 0

# Iterate through cycles and stages to find the first appearance of each actual PC
for cycle_idx in range(num_cycles):
    for stage_name in stage_signals.keys(): # Iterate through stages in a consistent order
        actual_pc_in_stage = cycle_stage_pc[cycle_idx][stage_name]
        if actual_pc_in_stage is not None and actual_pc_in_stage not in vcd_actual_to_synthetic_pc_map:
            # This is the first time we've seen this actual PC in the pipeline
            vcd_actual_to_synthetic_pc_map[actual_pc_in_stage] = synthetic_pc_counter
            vcd_unique_actual_pcs_ordered.append(actual_pc_in_stage)
            synthetic_pc_counter += 4 # Increment synthetic PC by 4 (for 32-bit instructions)

print(f"Assigned synthetic PCs to {len(vcd_unique_actual_pcs_ordered)} unique actual PCs from VCD.")


# --- Build pipeline matrix and tooltips ---
instruction_matrix = defaultdict(lambda: [''] * num_cycles)
tooltips_matrix = defaultdict(lambda: [''] * num_cycles)
last_stage = {} # For stall detection logic

# First, populate `ordered_row_labels` which defines the rows of the HTML table
ordered_row_labels = []
for actual_pc in vcd_unique_actual_pcs_ordered:
    synthetic_pc = vcd_actual_to_synthetic_pc_map[actual_pc]
    # Get the instruction hex from the map populated directly from VCD instructions
    instr_hex = actual_pc_to_instr_hex.get(actual_pc, "N/A_INSTR")
    row_label = f"PC_0x{synthetic_pc:08x} | {instr_hex}"
    ordered_row_labels.append(row_label)

# Manual override for PC_0x00000000 (synthetic) for WB stage at C0
# Find the actual PC that maps to synthetic 0x0 (if any)
actual_pc_for_synth_0 = next((apc for apc, spc in vcd_actual_to_synthetic_pc_map.items() if spc == 0x0), None)
instr_hex_for_synth_0 = actual_pc_to_instr_hex.get(actual_pc_for_synth_0, "N/A_INSTR") if actual_pc_for_synth_0 is not None else "N/A_INSTR"
target_pc_label_for_manual_override = f"PC_0x00000000 | {instr_hex_for_synth_0}"

# Ensure the synthetic 0x0 PC row exists in the ordered labels
if target_pc_label_for_manual_override not in ordered_row_labels:
    ordered_row_labels.insert(0, target_pc_label_for_manual_override)


# Initialize matrix and tooltip entries for all planned rows
for row_label in ordered_row_labels:
    instruction_matrix[row_label] = [''] * num_cycles
    tooltips_matrix[row_label] = [''] * num_cycles


# Apply manual override for PC_0x00000000 (synthetic)
if num_cycles > 0:
    instruction_matrix[target_pc_label_for_manual_override][0] = "WB"
    tooltip_text_manual = (f"PC (Synthetic): 0x00000000\n"
                            f"PC (Actual): 0x{actual_pc_for_synth_0:08x} (if applicable)\n"
                            f"Instruction (Hex): {instr_hex_for_synth_0}\n"
                            f"Stage: WB (Manual Override)")
    tooltips_matrix[target_pc_label_for_manual_override][0] = tooltip_text_manual
    print(f"✅ Manually set {target_pc_label_for_manual_override} to WB at C0.")


# Now, populate with data derived from VCD signals (using actual PCs, then mapping to synthetic for row labels)
for cycle_idx, stages_in_cycle in enumerate(cycle_stage_pc):
    for stage, actual_pc in stages_in_cycle.items():
        if actual_pc is not None and actual_pc in vcd_actual_to_synthetic_pc_map:
            synthetic_pc = vcd_actual_to_synthetic_pc_map[actual_pc]
            instr_hex = actual_pc_to_instr_hex.get(actual_pc, "N/A_INSTR") # Get instruction hex from VCD
            
            display_label = f"PC_0x{synthetic_pc:08x} | {instr_hex}"
            
            # Ensure the row exists (it should, due to `ordered_row_labels` initialization)
            if display_label not in instruction_matrix:
                # This case should ideally not happen if ordered_row_labels is comprehensive
                instruction_matrix[display_label] = [''] * num_cycles
                tooltips_matrix[display_label] = [''] * num_cycles

            # Stall detection logic
            # Check the previous cycle's stage for this instruction
            prev_stage_in_cycle = instruction_matrix[display_label][cycle_idx - 1] if cycle_idx > 0 else ''
            
            # If the current stage is the same as the previous cycle's stage (and it's a "stalling" stage)
            # and the current cell is not already filled by a manual override
            if stage == prev_stage_in_cycle and stage in ['ID', 'EX', 'MEM'] and instruction_matrix[display_label][cycle_idx] == "":
                instruction_matrix[display_label][cycle_idx] = 'STALL'
            elif instruction_matrix[display_label][cycle_idx] == "": # Only fill if empty (e.g., not from manual override)
                instruction_matrix[display_label][cycle_idx] = stage
            
            # Generate tooltip text
            disassembled_instr = instr_hex # Fallback
            try:
                if instr_hex != "N/A_INSTR" and 'x' not in instr_hex.lower():
                    instr_bytes = bytes.fromhex(instr_hex)
                    # Use the actual PC as the base address for disassembly
                    disassembled = list(md.disasm(instr_bytes, actual_pc))
                    if disassembled:
                        insn = disassembled[0]
                        disassembled_instr = f"{insn.mnemonic} {insn.op_str}"
                else:
                    disassembled_instr = "Not available"
            except ValueError: # e.g., non-hex characters in instr_hex
                disassembled_instr = f"Invalid Hex: {instr_hex}"
            except Exception as e: # Catch other disassembly errors
                disassembled_instr = f"Disassembly Error: {e}"
            
            tooltips_matrix[display_label][cycle_idx] = (
                f"PC (Actual): 0x{actual_pc:08x}\n"
                f"PC (Synthetic): 0x{synthetic_pc:08x}\n"
                f"Instruction (Hex): {instr_hex}\n"
                f"Instruction (ASM): {disassembled_instr}\n"
                f"Stage: {instruction_matrix[display_label][cycle_idx]}" # Use the possibly "STALL" stage
            )

# Create DataFrame from instruction_matrix and sort rows
df = pd.DataFrame.from_dict(instruction_matrix, orient='index', columns=[f"C{c}" for c in range(num_cycles)])

# Sort the DataFrame index by the synthetic PC address
# Extract integer synthetic PC from "PC_0x..." string for sorting
df.index = df.index.map(lambda x: (int(x.split(' | ')[0].split('_0x')[1], 16), x))
df = df.sort_index()
df.index = df.index.map(lambda x: x[1]) # Restore original string index

tooltips = pd.DataFrame.from_dict(tooltips_matrix, orient='index', columns=[f"C{c}" for c in range(num_cycles)])
tooltips = tooltips.reindex(df.index) # Ensure tooltips DataFrame matches the sorted df index

print("\n--- All PC addresses processed into the pipeline matrix ---")
for pc_label in df.index:
    print(pc_label.split(' | ')[0])
print("--------------------------------------------------\n")


# --- Re-Detect Stalls (after initial population to ensure proper marking) ---
# This block is now integrated into the main population loop above for better accuracy.
# Keeping it here as a fallback or for a second pass if needed, but the primary stall detection
# should happen during the `instruction_matrix` population.
# For now, this block can be removed or simplified if the above logic is sufficient.
# I'll keep it for now but note its redundancy if logic above covers it.
color_map_stages = ['IF', 'ID', 'EX', 'MEM', 'WB', 'STALL']
for row_idx, row in df.iterrows(): # Use iterrows for easier row access
    for i in range(1, len(row)):
        current_cell_value = row.iloc[i]
        previous_cell_value = row.iloc[i-1]
        
        # A stall is detected if a stage persists beyond one cycle in ID, EX, or MEM
        # And if the current cell is not already a STALL (to avoid re-marking)
        if current_cell_value == previous_cell_value and current_cell_value in ['ID', 'EX', 'MEM']:
            df.at[row_idx, df.columns[i]] = 'STALL'
            
            # Update tooltip to reflect STALL
            current_tooltip = tooltips.at[row_idx, tooltips.columns[i]]
            if "(STALL)" not in current_tooltip: # Avoid duplicate "(STALL)"
                tooltips.at[row_idx, tooltips.columns[i]] = current_tooltip.replace(f"Stage: {current_cell_value}", f"Stage: {current_cell_value} (STALL)")


# --- Save CSV ---
df.to_csv(output_csv)
print(f"\n✅ Matrix saved to {output_csv}")
print(df.iloc[:10, :25].fillna('').to_string())


# --- Generate VCD of stage occupancy ---
print(f"\nGenerating VCD file: {output_vcd}")
with open(output_vcd, 'w') as f:
    with VCDWriter(f, timescale='1ns', date='2025-07-25', comment='Pipeline trace from vcd11.py (modified)') as writer:
        signal_refs = {}
        # Register signals for each synthetic PC and each stage
        for synthetic_pc_label in ordered_row_labels:
            # Extract the raw synthetic PC hex from the label
            clean_synth_pc_hex = synthetic_pc_label.split(' | ')[0].replace('PC_0x', '')
            for stage in stage_signals.keys():
                signal_name_in_vcd = f"synth_PC_{clean_synth_pc_hex}_{stage}" # Added PC_ back for clarity in VCD
                # Make sure the signal name doesn't exceed common VCD limits if very long
                if len(signal_name_in_vcd) > 250: # Arbitrary limit for long names
                    signal_name_in_vcd = signal_name_in_vcd[:240] + "_TRUNC"
                signal_refs[(synthetic_pc_label, stage)] = writer.register_var("pipeline_timeline", signal_name_in_vcd, "wire", size=1)
        
        if signal_refs:
            # Write initial values (all to 0 or 'x')
            for (synth_pc_label, stage), sig_ref in signal_refs.items():
                writer.change(0, sig_ref, '0') 
            writer.change(0, None, None) # Ensure time 0 is written

        # Write value changes based on the DataFrame
        for c_idx, col_name in enumerate(df.columns):
            # Calculate the VCD timestamp for this cycle
            current_time_ns = rising_edges[c_idx] 
            writer.change(current_time_ns, None, None) # Time change event

            for synthetic_pc_label in df.index:
                for stage in stage_signals.keys():
                    signal_ref = signal_refs.get((synthetic_pc_label, stage))
                    if signal_ref:
                        cell_value = df.loc[synthetic_pc_label, col_name]
                        is_active = '1' if cell_value == stage or cell_value == 'STALL' else '0' # STALLs also mean activity
                        writer.change(current_time_ns, signal_ref, is_active)

writer.close()
print(f"✅ VCD file '{output_vcd}' generated successfully.")


# --- HTML with Colors + Tooltips + Search ---
color_map = {
    "IF": "#4da6ff", "ID": "#5cd65c", "EX": "#ff9933",
    "MEM": "#b366ff", "WB": "#ff4d4d", "STALL": "#bfbfbf" # Gray for stalls
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
    border-radius: 6px; padding: 8px; position: absolute; z-index: 3; /* Increased z-index */
    bottom: 125%; left: 50%; margin-left: -100px; /* Adjust as needed */
    opacity: 0; transition: opacity 0.3s;
    width: 200px; /* Fixed width for better appearance */
    white-space: pre-wrap; /* Preserve newlines */
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

# Header
html_header += ''.join(f"<th>{c}</th>" for c in df.columns)
html_header += "</tr></thead><tbody>"

# Rows
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