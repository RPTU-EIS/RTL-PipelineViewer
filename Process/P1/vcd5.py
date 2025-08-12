from vcdvcd import VCDVCD
from vcd.writer import VCDWriter
import pandas as pd
from collections import defaultdict
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32
import os

# --- Configuration ---
VCD_FILE = "dump.vcd"
BINARY_FILE = "BinaryFile.txt"  # Mapping PC → Instruction
CLOCK_SIGNAL = None
stage_signals = {
    "IF": "HazardDetectionRV32I.core.pc_if",
    "ID": "HazardDetectionRV32I.core.pc_id",
    "EX": "HazardDetectionRV32I.core.pc_ex",
    "MEM": "HazardDetectionRV32I.core.pc_mem",
    "WB": "HazardDetectionRV32I.core.pc_wb"
}
output_csv = "pipeline_matrix.csv"
output_html = "pipeline_matrix.html"
output_vcd = "pipeline_cycle_trace.vcd"

# --- Load VCD ---
print(f"Loading VCD file: {VCD_FILE}")
vcd = VCDVCD(VCD_FILE, store_tvs=True)

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

# --- Load PC → Instruction mapping ---
pc_to_instr = {}

if os.path.exists(BINARY_FILE):
    with open(BINARY_FILE, 'r') as f:
        for i, line in enumerate(f):
            instr = line.strip()
            if instr:
                pc = i * 4
                pc_to_instr[pc] = instr
print(f"Loaded {len(pc_to_instr)} instructions from {BINARY_FILE}")


# --- Build timeline ---
cycle_stage_pc = [{stage: None for stage in stage_signals} for _ in range(num_cycles)]
for stage, signal_name in stage_signals.items():
    if signal_name not in vcd.signals:
        print(f"⚠️ Warning: Signal {signal_name} not found in VCD.")
        continue
    signal_tv = vcd[signal_name].tv
    last_pc = None
    idx = 0
    for t, val in sorted(signal_tv, key=lambda x: x[0]):
        try:
            pc_val = int(val, 16)
        except ValueError:
            pc_val = None
        if pc_val is not None:
            last_pc = pc_val
        while idx < num_cycles and rising_edges[idx] <= t:
            if last_pc is not None:
                cycle_stage_pc[idx][stage] = last_pc
            idx += 1

# --- Build matrix ---
instruction_matrix = defaultdict(lambda: [''] * num_cycles)
tooltips_matrix = defaultdict(lambda: [''] * num_cycles)

for cycle_idx, stages in enumerate(cycle_stage_pc):
    for stage, pc in stages.items():
        if pc is not None:
            label = f"PC_0x{pc:08x}"
            instr_text = pc_to_instr.get(pc, "")
            display_label = label + (f" | {instr_text}" if instr_text else "")
            instruction_matrix[display_label][cycle_idx] = stage
            tooltips_matrix[display_label][cycle_idx] = f"{label} {instr_text}"

# DataFrame
df = pd.DataFrame.from_dict(instruction_matrix, orient='index', columns=[f"C{c}" for c in range(num_cycles)])
tooltips = pd.DataFrame.from_dict(tooltips_matrix, orient='index', columns=[f"C{c}" for c in range(num_cycles)])
df = df.sort_index()
tooltips = tooltips.reindex(df.index)

# --- Detect Stalls ---
for row in df.index:
    row_data = df.loc[row].tolist()
    for i in range(1, len(row_data)):
        if row_data[i] == row_data[i-1] and row_data[i] in ['ID', 'EX']:
            df.iloc[df.index.get_loc(row), i] = 'STALL'
            tooltips.iloc[tooltips.index.get_loc(row), i] += " (STALL)"

# --- Save CSV ---
df.to_csv(output_csv)
print(f"\n✅ Matrix saved to {output_csv}")
print(df.iloc[:10, :25].fillna('').to_string())

# --- Generate VCD ---
print(f"\nGenerating VCD file: {output_vcd}")
with open(output_vcd, 'w') as f:
    with VCDWriter(f, timescale='1ns', date='2025-07-18', comment='Pipeline trace') as writer:
        vcd_signals = {stage: writer.register_var('pipeline_monitor', f'pc_{stage.lower()}', 'wire', size=32)
                       for stage in stage_signals}
        last_written = {stage: None for stage in stage_signals}
        for cycle_idx, stages in enumerate(cycle_stage_pc):
            time_ns = cycle_idx * 10
            for stage in stage_signals.keys():
                current_pc = stages[stage]
                if current_pc is not None:
                    if last_written[stage] != current_pc:
                        writer.change(vcd_signals[stage], time_ns, current_pc)
                        last_written[stage] = current_pc
                else:
                    if last_written[stage] != 'x':
                        writer.change(vcd_signals[stage], time_ns, 'x')
                        last_written[stage] = 'x'
print(f"✅ VCD file '{output_vcd}' generated successfully.")

# --- HTML with Colors + Tooltips + Search ---
color_map = {
    "IF": "#4da6ff", "ID": "#5cd65c", "EX": "#ff9933",
    "MEM": "#b366ff", "WB": "#ff4d4d", "STALL": "#bfbfbf"
}

html_header = """
<html>
<head>
<style>
table {border-collapse: collapse; width: 100%; font-size: 12px;}
th, td {border: 1px solid #999; padding: 4px; text-align: center;}
th {position: sticky; top: 0; background: #ddd;}
input {margin-bottom: 10px; width: 50%; padding: 5px;}
.tooltip {position: relative; display: inline-block;}
.tooltip .tooltiptext {
    visibility: hidden; background-color: #555; color: #fff; text-align: center;
    border-radius: 6px; padding: 5px; position: absolute; z-index: 1;
    bottom: 125%; left: 50%; margin-left: -60px; opacity: 0; transition: opacity 0.3s;
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
<input type="text" id="searchBox" onkeyup="searchTable()" placeholder="Search by PC or instruction...">
<table>
<thead>
<tr><th>PC | Instruction</th>
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

