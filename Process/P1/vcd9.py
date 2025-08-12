#!/usr/bin/env python
"""
Pipeline visualization generator (order-mapped binary).

This version addresses the alignment problem where the **PC values observed in the VCD**
(e.g., 0x00000100, 0x00001000, ...) do **not** line up numerically with the
sequential instructions in `BinaryFile.txt` (which are listed without PC addresses).

We therefore provide an *order-based* mapping option:
  • We watch the pipeline and record each **unique PC** the first time it appears in *any* stage.
  • We sort those PCs by the cycle of first appearance (program order as executed).
  • We assign instruction words from `BinaryFile.txt` in that order.

Result: HTML first column shows `PC_0xXXXXXXXX | XXXXXXXX` (PC + raw hex instruction) —
exactly as requested.

Outputs:
  - pipeline_matrix.csv          (PC rows, cycle columns, stage cells)
  - pipeline_cycle_trace.vcd     (stage waveforms w/ PC per cycle)
  - pipeline_matrix.html         (color, tooltips, search; rows show PC | HEX)

Optional disassembly (Capstone) is done only for tooltips and console debug; it is *not*
shown in the HTML row label (per user request).
"""

import os
from collections import defaultdict, OrderedDict

import pandas as pd
from vcdvcd import VCDVCD
from vcd.writer import VCDWriter

# Capstone is optional; we only use it for tooltips/console debug if available.
try:
    from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_LITTLE_ENDIAN
    HAVE_CAPSTONE = True
except Exception:  # ImportError et al.
    HAVE_CAPSTONE = False

# -----------------------------------------------------------------------------
# User Configuration
# -----------------------------------------------------------------------------
VCD_FILE      = "dump.vcd"
BINARY_FILE   = "BinaryFile.txt"  # raw 32-bit hex words, one per line (no 0x)
CLOCK_SIGNAL  = None              # auto-detect if None
ORDER_MAP_BIN = True              # <-- map binary lines in order of *first PC appearance*
                                  #     If False, we try numeric mapping w/ BASE_PC.
BASE_PC       = 0x00000000        # used only if ORDER_MAP_BIN=False
PC_STRIDE     = 4                 # bytes per instruction when using numeric mapping

# Pipeline stage signals in the VCD (edit to match your design)
stage_signals = {
    "IF": "HazardDetectionRV32I.core.IFBarrier.io_pc_out",
    "ID": "HazardDetectionRV32I.core.IDBarrier.pcReg",
    "EX": "HazardDetectionRV32I.core.EXBarrier.pcReg",
    "MEM": "HazardDetectionRV32I.core.MEMBarrier.pcReg",
    "WB": "HazardDetectionRV32I.core.WBBarrier.pcReg"
}

# Output filenames
output_csv  = "pipeline_matrix.csv"
output_html = "pipeline_matrix.html"
output_vcd  = "pipeline_cycle_trace.vcd"

# Colors
color_map = {
    "IF":    "#4da6ff",
    "ID":    "#5cd65c",
    "EX":    "#ff9933",
    "MEM":   "#b366ff",
    "WB":    "#ff4d4d",
    "STALL": "#bfbfbf",
}

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------

def normalize_hex_word(word: str) -> str:
    """Return 8-hex-digit uppercase string (no 0x)."""
    w = word.strip().lower().replace("0x", "")
    # keep only hex chars
    w = ''.join(ch for ch in w if ch in '0123456789abcdef')
    if not w:
        return '00000000'
    return w.zfill(8)[-8:]


def disassemble_rv32_hex_word(pc: int, word8: str) -> str:
    """Return disassembly string for a single 32-bit word at pc.
    If Capstone not available, return empty string.
    """
    if not HAVE_CAPSTONE:
        return ""
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    try:
        b = bytes.fromhex(word8)
    except ValueError:
        return ""
    txt = ""
    for insn in md.disasm(b, pc):
        txt = f"{insn.mnemonic} {insn.op_str}".strip()
    return txt


def build_html(df: pd.DataFrame, tooltips: pd.DataFrame, html_path: str):
    """Write colored, searchable HTML table."""
    html_header = """
<html>
<head>
<meta charset=\"utf-8\">
<title>Pipeline Visualization</title>
<style>
table {border-collapse: collapse; width: 100%; font-size: 12px;}
th, td {border: 1px solid #999; padding: 4px; text-align: center;}
th {position: sticky; top: 0; background: #ddd;}
input {margin-bottom: 10px; width: 50%; padding: 5px;}
.tooltip {position: relative; display: inline-block; width:100%;}
.tooltip .tooltiptext {
    visibility: hidden; background-color: #555; color: #fff; text-align: left;
    border-radius: 6px; padding: 5px; position: absolute; z-index: 1;
    bottom: 125%; left: 50%; transform: translateX(-50%);
    opacity: 0; transition: opacity 0.3s; white-space: nowrap;
}
.tooltip:hover .tooltiptext {visibility: visible; opacity: 1;}
.legend-box {display:inline-block;width:12px;height:12px;margin-right:4px;border:1px solid #000;}
.legend-item {margin-right:12px;font-size:12px;}
</style>
<script>
function searchTable() {
  var input = document.getElementById(\"searchBox\").value.toUpperCase();
  var rows = document.querySelectorAll(\"table tbody tr\");
  rows.forEach(row => {
    row.style.display = row.innerText.toUpperCase().includes(input) ? \"\" : \"none\";
  });
}
</script>
</head>
<body>
<h2>Pipeline Visualization</h2>
<div>
  <span class=\"legend-item\"><span class=\"legend-box\" style=\"background:#4da6ff\"></span>IF</span>
  <span class=\"legend-item\"><span class=\"legend-box\" style=\"background:#5cd65c\"></span>ID</span>
  <span class=\"legend-item\"><span class=\"legend-box\" style=\"background:#ff9933\"></span>EX</span>
  <span class=\"legend-item\"><span class=\"legend-box\" style=\"background:#b366ff\"></span>MEM</span>
  <span class=\"legend-item\"><span class=\"legend-box\" style=\"background:#ff4d4d\"></span>WB</span>
  <span class=\"legend-item\"><span class=\"legend-box\" style=\"background:#bfbfbf\"></span>STALL</span>
</div>
<input type=\"text\" id=\"searchBox\" onkeyup=\"searchTable()\" placeholder=\"Search by PC, hex, or instruction...\">
<table>
<thead>
<tr><th>PC | Hex</th>
"""
    # header columns
    html_header += "".join(f"<th>{c}</th>" for c in df.columns)
    html_header += "</tr></thead><tbody>"

    html_rows = []
    for idx in df.index:
        html_rows.append(f"<tr><td>{idx}</td>")
        row_vals = df.loc[idx]
        row_tips = tooltips.loc[idx]
        for i, val in enumerate(row_vals):
            color = color_map.get(val, "#fff")
            tip = row_tips[i]
            html_rows.append(
                f'<td style="background:{color}"><div class="tooltip">{val}<span class="tooltiptext">{tip}</span></div></td>'
            )
        html_rows.append("</tr>")
    html_footer = "</tbody></table></body></html>"

    with open(html_path, "w") as fh:
        fh.write(html_header + "".join(html_rows) + html_footer)


# -----------------------------------------------------------------------------
# Load VCD & clock
# -----------------------------------------------------------------------------
print(f"Loading VCD file: {VCD_FILE}")
vcd = VCDVCD(VCD_FILE, store_tvs=True)

# Auto-detect clock
if CLOCK_SIGNAL is None:
    clocks = [s for s in vcd.signals if "clk" in s.lower() or "clock" in s.lower()]
    if not clocks:
        raise RuntimeError("No clock signal found. Set CLOCK_SIGNAL.")
    CLOCK_SIGNAL = clocks[0]
print(f"Using clock signal: {CLOCK_SIGNAL}")

# Rising edges => cycles
clock_tv = vcd[CLOCK_SIGNAL].tv
rising_edges = []
prev = '0'
for t, v in sorted(clock_tv, key=lambda x: x[0]):
    if prev == '0' and v == '1':
        rising_edges.append(t)
    prev = v
num_cycles = len(rising_edges)
print(f"Detected {num_cycles} clock cycles.")

# -----------------------------------------------------------------------------
# Build cycle->stage->PC occupancy & record first-appearance order of PCs
# -----------------------------------------------------------------------------
cycle_stage_pc = [{st: None for st in stage_signals} for _ in range(num_cycles)]
first_seen_cycle = {}  # pc -> cycle index

for stage, sig in stage_signals.items():
    if sig not in vcd.signals:
        print(f"⚠️ Warning: missing signal {sig}")
        continue
    tv = sorted(vcd[sig].tv, key=lambda x: x[0])

    # initialize last_pc from first valid value if exists
    last_pc = None
    for _, v in tv:
        try:
            last_pc = int(v, 16)
            break
        except ValueError:
            continue

    idx = 0
    for t, v in tv:
        try:
            last_pc = int(v, 16)
        except ValueError:
            pass
        while idx < num_cycles and rising_edges[idx] <= t:
            if last_pc is not None:
                cycle_stage_pc[idx][stage] = last_pc
                if last_pc not in first_seen_cycle:
                    first_seen_cycle[last_pc] = idx
            idx += 1
    while idx < num_cycles:
        if last_pc is not None:
            cycle_stage_pc[idx][stage] = last_pc
            if last_pc not in first_seen_cycle:
                first_seen_cycle[last_pc] = idx
        idx += 1

# If no PCs seen, bail
if not first_seen_cycle:
    raise RuntimeError("No valid PC values found in pipeline signals!")

# Build ordered list of PCs by first appearance
pcs_in_order = sorted(first_seen_cycle.items(), key=lambda kv: kv[1])  # (pc, cycle)
pcs_in_order = [pc for pc, _ in pcs_in_order]

# Debug print
print("\n--- PC appearance order (pc, first_cycle) ---")
for pc, cyc in sorted(first_seen_cycle.items(), key=lambda kv: kv[1]):
    print(f"PC_0x{pc:08x} @ cycle {cyc}")

# -----------------------------------------------------------------------------
# Load BinaryFile & map to PCs
# -----------------------------------------------------------------------------
hex_words = []
if os.path.exists(BINARY_FILE):
    with open(BINARY_FILE, "r") as bf:
        for line in bf:
            w = line.strip()
            if w:
                hex_words.append(normalize_hex_word(w))
else:
    print(f"⚠️ {BINARY_FILE} not found; HTML will show PC only.")

# order-mapped association
pc_to_hex = {}
pc_to_dis = {}
if ORDER_MAP_BIN and hex_words:
    for i, pc in enumerate(pcs_in_order):
        if i < len(hex_words):
            word8 = hex_words[i]
            pc_to_hex[pc] = word8
            pc_to_dis[pc] = disassemble_rv32_hex_word(pc, word8)
        else:
            break
else:
    # numeric mapping fallback
    pc = BASE_PC
    for word8 in hex_words:
        pc_to_hex[pc] = word8
        pc_to_dis[pc] = disassemble_rv32_hex_word(pc, word8)
        pc += PC_STRIDE

print(f"Loaded {len(hex_words)} instruction words from {BINARY_FILE}")
print("--- Mapped PCs to instruction words ---")
for pc in pcs_in_order:
    raw_hex = pc_to_hex.get(pc, "????????")
    disasm = pc_to_dis.get(pc, "")
    print(f"PC_0x{pc:08x}: {raw_hex} {('| ' + disasm) if disasm else ''}")

# -----------------------------------------------------------------------------
# Build Instruction × Cycle Matrix (rows keyed by PC|HEX)
# -----------------------------------------------------------------------------
instruction_matrix = defaultdict(lambda: [''] * num_cycles)
tooltips_matrix     = defaultdict(lambda: [''] * num_cycles)

for c_idx, stages in enumerate(cycle_stage_pc):
    for stage, pc in stages.items():
        if pc is None:
            continue
        raw_hex = pc_to_hex.get(pc, "????????")
        # Row label: PC | HEX  (per user request; no disasm in row label)
        label = f"PC_0x{pc:08x} | {raw_hex}"
        # Fill cell if empty
        if instruction_matrix[label][c_idx] == '':
            instruction_matrix[label][c_idx] = stage
        # Tooltip includes disasm (if any)
        disasm = pc_to_dis.get(pc, "")
        tip = f"PC=0x{pc:08x}  HEX={raw_hex}"
        if disasm:
            tip += f"  {disasm}"
        tooltips_matrix[label][c_idx] = tip

# Create DataFrames
columns = [f"C{c}" for c in range(num_cycles)]
df = pd.DataFrame.from_dict(instruction_matrix, orient='index', columns=columns)
tooltips = pd.DataFrame.from_dict(tooltips_matrix, orient='index', columns=columns)

# Sort rows by *first appearance order* rather than alphabetical label
# Build ordered index list from pcs_in_order -> label
ordered_labels = []
for pc in pcs_in_order:
    raw_hex = pc_to_hex.get(pc, "????????")
    ordered_labels.append(f"PC_0x{pc:08x} | {raw_hex}")
# Filter to only those actually present in df
ordered_labels = [lbl for lbl in ordered_labels if lbl in df.index]

# Reindex DataFrames
df = df.reindex(ordered_labels)
tooltips = tooltips.reindex(df.index)

# -----------------------------------------------------------------------------
# Detect simple stalls (stay in ID or EX >1 cycle)
# -----------------------------------------------------------------------------
for ridx, row in enumerate(df.index):
    row_vals = df.loc[row].tolist()
    for i in range(1, len(row_vals)):
        if row_vals[i] == row_vals[i-1] and row_vals[i] in ['ID', 'EX']:
            df.iat[ridx, i] = 'STALL'
            old_tip = tooltips.iat[ridx, i]
            tooltips.iat[ridx, i] = (old_tip + " (STALL)") if old_tip else "STALL"

# -----------------------------------------------------------------------------
# Save CSV + print snippet
# -----------------------------------------------------------------------------
df.to_csv(output_csv)
print(f"\n✅ Matrix saved to {output_csv}")
print(df.iloc[:10, :25].fillna('').to_string())

# -----------------------------------------------------------------------------
# Generate VCD of stage occupancy
# -----------------------------------------------------------------------------
print(f"\nGenerating VCD file: {output_vcd}")
with open(output_vcd, 'w') as fh:
    with VCDWriter(fh, timescale='1ns', date='2025-07-18', comment='Pipeline trace') as writer:
        sigs = {st: writer.register_var('pipeline_monitor', f'pc_{st.lower()}', 'wire', size=32)
                for st in stage_signals}
        last_written = {st: None for st in stage_signals}
        for c_idx, stages in enumerate(cycle_stage_pc):
            t_ns = c_idx * 10  # 10ns per cycle (adjust as needed)
            for st in stage_signals:
                pc_val = stages[st]
                if pc_val is not None:
                    if last_written[st] != pc_val:
                        writer.change(sigs[st], t_ns, pc_val)
                        last_written[st] = pc_val
                else:
                    if last_written[st] != 'x':
                        writer.change(sigs[st], t_ns, 'x')
                        last_written[st] = 'x'
print(f"✅ VCD file '{output_vcd}' generated successfully.")

# -----------------------------------------------------------------------------
# HTML
# -----------------------------------------------------------------------------
build_html(df, tooltips, output_html)
print(f"✅ Interactive HTML saved as {output_html}. Open in a browser.")
