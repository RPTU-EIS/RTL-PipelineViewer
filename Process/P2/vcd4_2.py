#!/usr/bin/env python
"""
Pipeline visualization generator (re-indexed/synthetic PC mapping).

**What's new in this version (modified vcd14.py):**
1. **Instructions are fetched directly from VCD signals**, not from BinaryFile.txt.
   - Specifically from:
     - "HazardDetectionRV32I.core.IFBarrier.io_inst_out"
     - "HazardDetectionRV32I.core.IDBarrier.instReg"
     - "HazardDetectionRV32I.core.EXBarrier.instReg"
     - "HazardDetectionRV32I.core.MEMBarrier.instReg"
     - "HazardDetectionRV32I.core.WBBarrier.instReg"
2. **Row count limited to unique PCs observed in VCD.**
3. **Re-indexed sequential PCs starting at 0x00000000** are assigned to your instructions *in the order their corresponding actual PC value first appears in any VCD stage signal*. This is done to achieve human-readable, sequentially incrementing PC labels in the output.
   - The actual PC for instruction '00000013' is explicitly mapped to synthetic PC 0x00000000.
4. Pipeline activity from the VCD is mapped **in program-order-of-first-appearance** onto these re-indexed PCs. That means: the *first unique actual PC value observed* in the VCD is treated as *instruction 0*, the second unique PC observed as *instruction 1*, etc., and we LABEL those rows using the re-indexed PC addresses (0x00000000, 0x00000004, ...) so that your HTML shows exactly the format you requested: `PC_0xXXXXXXXX | XXXXXXXX` (where XXXXXXXX is the instruction hex from VCD).
5. **Capstone disassembly (if installed) is now used only in tooltips and the summary print**, the **main row label remains PC | HEX instruction** as requested.
6. STALL detection retained (ID/EX repeats). No FLUSH marking.
7. **Tooltips only appear on 'ID' stage cells.**

Outputs:
  - pipeline_matrix.csv          (Re-indexed PC rows, cycle columns, stage cells)
  - pipeline_matrix.html         (color, tooltips, search; rows show Re-indexed PC | HEX)
  - (No VCD output file will be generated in this version)

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
    "aluResult": "HazardDetectionRV32I.core.EX.io_aluResult",
    "UOP": "HazardDetectionRV32I.core.EX.io_uop"
}

output_csv = "pipeline_matrix.csv" # Updated output filename
output_html = "pipeline_matrix.html" # Updated output filename


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

# --- Extract operandA, operandB, aluResult over time ---
ex_values_by_cycle = [{} for _ in range(num_cycles)]

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

    # Replace all 0x... with signed decimal
    return re.sub(r'0x[0-9a-fA-F]+', replace_hex, disasm)


# --- Collect PC → Instruction Hex (Binary/Raw) and Disassemble ---
actual_pc_to_instr_raw = {} # Stores original raw string from VCD (binary or hex)
actual_pc_to_instr_hex_display = {} # Stores 8-digit hex string for display/conversion
actual_pc_to_disassembled_instr = {} # Stores disassembled string

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
    current_instr_raw_val = None
    
    pc_idx = 0
    instr_idx = 0
    ex_operator_by_actual_pc = {}

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
            instr_display_str = current_instr_raw_val # Default to raw if not convertible

            # Determine instr_hex_for_bytes (for Capstone) and instr_display_str (for output labels/tooltips)
            try:
                if len(current_instr_raw_val) == 32 and all(c in '01' for c in current_instr_raw_val):
                    # It's a 32-bit binary string
                    instr_hex_for_bytes = f"{int(current_instr_raw_val, 2):08x}"
                    instr_display_str = instr_hex_for_bytes
                elif all(c in '0123456789abcdef' for c in current_instr_raw_val.lower()):
                    # It's already a hex string (e.g., '00000013' or '13')
                    instr_hex_for_bytes = f"{int(current_instr_raw_val, 16):08x}" # Ensure 8 digits
                    instr_display_str = instr_hex_for_bytes
                else:
                    # Invalid format
                    instr_hex_for_bytes = ""
                    instr_display_str = "INVALID_INSTR_FORMAT"
            except ValueError:
                instr_hex_for_bytes = ""
                instr_display_str = "CONVERSION_ERROR"

            actual_pc_to_instr_hex_display[current_pc_val] = instr_display_str

            # Disassemble here and store it for later use
            if current_pc_val not in actual_pc_to_disassembled_instr:  # Disassemble only once per PC
                disassembled_text = "N/A_ASM"
                operand_info_lines = []  # This will store operand breakdown (rd, rs1, rs2, imm)

                if instr_hex_for_bytes:
                    try:
                        instr_bytes = bytes.fromhex(instr_hex_for_bytes)
                        instr_bytes_le = instr_bytes[::-1]

                        disassembled = list(md.disasm(instr_bytes_le, current_pc_val))
                        if disassembled:
                            insn = disassembled[0]
                            disassembled_text = f"{insn.mnemonic} {insn.op_str}"
                            disassembled_text = convert_hex_immediates_to_decimal(disassembled_text)

                            # 🔍 Extract operand breakdown
                            if insn.mnemonic in {"addi", "andi", "ori", "xori", "slti", "sltiu", "slli", "srli", "srai"}:
                                if len(insn.operands) == 3:
                                    rd  = insn.reg_name(insn.operands[0].reg)
                                    rs1 = insn.reg_name(insn.operands[1].reg)
                                    imm = insn.operands[2].imm
                                    operand_info_lines = [
                                        f"rd = {rd}",
                                        f"rs1 = {rs1}",
                                        f"imm = {imm}"
                                    ]
                            elif insn.mnemonic in {"add", "sub", "sll", "slt", "sltu", "xor", "srl", "sra", "or", "and"}:
                                if len(insn.operands) == 3:
                                    rd  = insn.reg_name(insn.operands[0].reg)
                                    rs1 = insn.reg_name(insn.operands[1].reg)
                                    rs2 = insn.reg_name(insn.operands[2].reg)
                                    operand_info_lines = [
                                        f"rd = {rd}",
                                        f"rs1 = {rs1}",
                                        f"rs2 = {rs2}"
                                    ]
                        else:
                            disassembled_text = "N/A_ASM"
                    except Exception as e:
                        disassembled_text = f"N/A_ASM (Error: {e})"

                # 👇 Store both disassembled instruction and operand breakdown
                actual_pc_to_disassembled_instr[current_pc_val] = {
                    "asm": disassembled_text,
                    "operands": operand_info_lines
                }

print(f"Collected {len(actual_pc_to_instr_raw)} PC → Instruction raw mappings, "
      f"{len(actual_pc_to_instr_hex_display)} hex mappings, and "
      f"{len(actual_pc_to_disassembled_instr)} disassemblies from VCD.")


# --- Build timeline (cycle_stage_pc) with improved sampling ---
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

# Prioritize mapping for instruction 0x00000013 to synthetic PC 0x00000000
TARGET_INSTR_HEX_BINARY_FOR_SYNTH_0 = "00000013"

initial_actual_pc_for_target_instr = None
for actual_pc, instr_raw_val in actual_pc_to_instr_raw.items():
    try:
        if len(instr_raw_val) == 32 and all(c in '01' for c in instr_raw_val):
            observed_hex_str = f"{int(instr_raw_val, 2):08x}"
        elif all(c in '0123456789abcdef' for c in instr_raw_val.lower()):
            observed_hex_str = f"{int(instr_raw_val, 16):08x}"
        else:
            continue # Skip invalid instruction raw values
        
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


# Iterate through cycles and stages to find the first appearance of each actual PC
for cycle_idx in range(num_cycles):
    for stage_name in stage_signals.keys():
        actual_pc_in_stage = cycle_stage_pc[cycle_idx][stage_name]
        if actual_pc_in_stage is not None and actual_pc_in_stage not in vcd_actual_to_synthetic_pc_map:
            vcd_actual_to_synthetic_pc_map[actual_pc_in_stage] = synthetic_pc_counter
            vcd_unique_actual_pcs_ordered.append(actual_pc_in_stage)
            synthetic_pc_counter += 4

print(f"Assigned re-assigned PCs to {len(vcd_unique_actual_pcs_ordered)} unique actual PCs from VCD.")


# --- Build pipeline matrix and tooltips ---
instruction_matrix = defaultdict(lambda: [''] * num_cycles)
tooltips_matrix = defaultdict(lambda: [''] * num_cycles)

# Populate ordered_row_labels based on the determined order of actual PCs and their synthetic mapping
ordered_row_labels = []
for actual_pc in vcd_unique_actual_pcs_ordered:
    synthetic_pc = vcd_actual_to_synthetic_pc_map.get(actual_pc)
    # Use the pre-calculated hex display for the row label (as requested)
    instr_hex_display_for_label = actual_pc_to_instr_hex_display.get(actual_pc, "N/A_HEX")
    
    row_label = f"PC_0x{synthetic_pc:08x} | {instr_hex_display_for_label}"
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

            instr_hex_display = actual_pc_to_instr_hex_display.get(actual_pc, "N/A_HEX")
            disassembled_instr_for_tooltip = actual_pc_to_disassembled_instr.get(actual_pc, "N/A_ASM")
            display_label = f"PC_0x{synthetic_pc:08x} | {instr_hex_display}"

            # Update stage cell in matrix if not yet filled
            if instruction_matrix[display_label][cycle_idx] == "":
                instruction_matrix[display_label][cycle_idx] = stage

            # Convert to binary string (optional)
            try:
                instr_bin = f"{int(instr_hex_display, 16):032b}"
            except Exception:
                instr_bin = "N/A_BIN"

            # Build tooltip content
            dis_info = actual_pc_to_disassembled_instr.get(actual_pc, {})
            disassembled_instr_for_tooltip = dis_info.get("asm", "N/A_ASM")
            operand_lines = dis_info.get("operands", [])

            if stage == "IF":
                # Show only basic info in IF stage
                tooltip = (
                    f"Stage: {stage}\n"
                    f"PC (bin): 0x{actual_pc:08x}\n"
                    f"PC (hex): 0x{synthetic_pc:08x}\n"
                    f"Inst (bin): {instr_bin}\n"
                    f"Inst (hex): {instr_hex_display}\n"
                    f"Instruction (ASM): {disassembled_instr_for_tooltip}"
                )

            elif stage == "ID":
                # Show detailed decoding only in ID stage
                tooltip = (
                    f"Stage: {stage}\n"
                    f"ASM: {disassembled_instr_for_tooltip}"
                )
                if operand_lines:
                    tooltip += "\n" + "\n".join(operand_lines)

            elif stage == "EX":
                tooltip = (
                    f"Stage: {stage}\n"
                )

                ex_data = ex_values_by_cycle[cycle_idx] if cycle_idx < len(ex_values_by_cycle) else {}
                op_a = ex_data.get("operandA")
                op_b = ex_data.get("operandB")
                result = ex_data.get("aluResult")

                # Extract operator mnemonic (e.g., "add", "xor") from ASM text
                operator = disassembled_instr_for_tooltip.split()[0].upper() if isinstance(disassembled_instr_for_tooltip, str) else "?"

                if op_a is not None and op_b is not None and result is not None:
                    tooltip += f"\n{op_a} {operator} {op_b}\nResult: {result}"

            else:
                tooltip = (
                    f"Stage: {stage}\n"
                )

            tooltips_matrix[display_label][cycle_idx] = tooltip
# Create DataFrame from instruction_matrix and sort rows by the re-indexed PC
df = pd.DataFrame.from_dict(instruction_matrix, orient='index', columns=[f"C{c}" for c in range(num_cycles)])

# Sorting by the synthetic PC part of the index
df.index = df.index.map(lambda x: (int(x.split(' | ')[0].split('_0x')[1], 16), x))
df = df.sort_index()
df.index = df.index.map(lambda x: x[1])

tooltips = pd.DataFrame.from_dict(tooltips_matrix, orient='index', columns=[f"C{c}" for c in range(num_cycles)])
tooltips = tooltips.reindex(df.index)

# print("\n--- All PC addresses processed into the pipeline matrix ---")
# for pc_label in df.index:
#     print(pc_label.split(' | ')[0])
# print("--------------------------------------------------\n")


# --- Re-Detect Stalls (after initial population to ensure proper marking) ---
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


# --- Print a summary of PC to Assembly mapping (clean version) ---
print("\n--- Summary of PC(hex), PC(bin), Instruction(Hex) and Disassembled Instruction ---")
# Sort by synthetic PC for readability
sorted_pcs_for_print = sorted(vcd_actual_to_synthetic_pc_map.items(), key=lambda item: item[1])

for actual_pc, synthetic_pc in sorted_pcs_for_print:
    instr_hex_display = actual_pc_to_instr_hex_display.get(actual_pc, "N/A_HEX")
    dis_info = actual_pc_to_disassembled_instr.get(actual_pc, {})
    
    asm = dis_info.get("asm", "N/A_ASM")
    
    print(f" PC(bin): 0x{actual_pc:08x} | PC(hex): 0x{synthetic_pc:08x} | Instr(Hex): {instr_hex_display} | ASM: {asm}")

print("-----------------------------------------------------------------------------------\n")




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
/* Tooltip text styles - these apply *only* to elements with .tooltiptext */
.tooltip .tooltiptext {
    visibility: hidden; background-color: #555; color: #fff; text-align: left;
    border-radius: 6px; padding: 8px; position: absolute; z-index: 3;
    bottom: 125%; left: 50%; margin-left: -100px; /* Adjust for centering */
    opacity: 0; transition: opacity 0.3s;
    width: 200px;
    white-space: pre-wrap; /* Preserve newlines */
}
/* Show the tooltip text when hovering over the parent .tooltip */
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
<h2>Pipeline Visualization (PC | Instruction / No. of cycle)</h2>
<input type="text" id="searchBox" onkeyup="searchTable()" placeholder="Search by PC, instruction hex, or assembly...">
<table>
<thead>
<tr><th>PC | Instruction (Hex)</th>
""" # HTML header for the table

html_header += ''.join(f"<th>{c}</th>" for c in df.columns)
html_header += "</tr></thead><tbody>"

html_rows = ""
for idx in df.index:
    html_rows += f"<tr><td>{idx}</td>"
    for c_idx, val in enumerate(df.loc[idx]):
        color = color_map.get(val, "#fff")
        tooltip_text = tooltips.loc[idx].iloc[c_idx]
        cell_content = val  # default content

        # Extract short ASM from tooltip if available
        asm_line = ""
        if pd.notna(tooltip_text):
            for line in tooltip_text.split("\n"):
                if line.startswith("Instruction (ASM):"):
                    asm_line = line.replace("Instruction (ASM):", "").strip()
                    break

        # Show stage and ASM in the cell for IF and ID stages
        if val in ["IF", "ID"] and asm_line:
            cell_content = (
                f'<div class="tooltip">{val}<br>'
                f'<span style="font-size:9px; color:#000;">{asm_line}</span>'
                f'<span class="tooltiptext">{tooltip_text}</span></div>'
            )
        elif pd.notna(tooltip_text):
            # Default tooltip behavior
            cell_content = (
                f'<div class="tooltip">{val}'
                f'<span class="tooltiptext">{tooltip_text}</span></div>'
            )

        html_rows += f'<td style="background:{color}">{cell_content}</td>'
    html_rows += "</tr>"



html_footer = "</tbody></table></body></html>"

with open(output_html, "w") as f:
    f.write(html_header + html_rows + html_footer)



print("\n--- First 15 ALU Operations from VCD ---")
for i in range(min(15, len(ex_values_by_cycle))):
    entry = ex_values_by_cycle[i]
    if all(k in entry for k in ["operandA", "operandB", "aluResult"]):
        print(f"Cycle {i}: {entry['operandA']} ? {entry['operandB']} => {entry['aluResult']}")
    else:
        print(f"Cycle {i}: Incomplete data")
print("----------------------------------------------------------")




