#!/usr/bin/env python
"""
Pipeline visualization generator (synthetic PC mapping).

**What's new in this version (vcd11.py):**
1. **Row count limited to number of instructions in BinaryFile.txt.** Extra PCs that appear in the VCD beyond the instruction count are ignored (not shown in HTML/CSV).
2. **Synthetic sequential PCs starting at 0x00000000** are assigned to your instructions *in the order they appear in BinaryFile.txt* (first row always `PC_0x00000000`).
3. Pipeline activity from the VCD is mapped **in program-order-of-first-appearance** onto these synthetic PCs. That means: the *first unique PC value observed* in the VCD is treated as *instruction 0*, the second unique PC observed as *instruction 1*, etc., but we LABEL those rows using synthetic PC addresses 0x00000000, 0x00000004, ... so that your HTML shows exactly the format you requested: `PC_0xXXXXXXXX | XXXXXXXX`.
4. Optional Capstone disassembly (if installed) is used **only in tooltips**, not in the row label (per request).
5. STALL detection retained (ID/EX repeats). No FLUSH marking.

Outputs:
  - pipeline_matrix.csv          (PC rows, cycle columns, stage cells)
  - pipeline_cycle_trace.vcd     (stage waveforms w/ PC per cycle)
  - pipeline_matrix.html         (color, tooltips, search; rows show PC | HEX)

Edit the stage signal names below if they differ in your VCD.
"""

import os
from collections import defaultdict

import pandas as pd
from vcdvcd import VCDVCD
from vcd.writer import VCDWriter

# Capstone optional -----------------------------------------------------------
try:
    from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_LITTLE_ENDIAN
    HAVE_CAPSTONE = True
except Exception:  # ImportError etc.
    HAVE_CAPSTONE = False

# -----------------------------------------------------------------------------
# User Configuration
# -----------------------------------------------------------------------------
VCD_FILE      = "dump.vcd"
BINARY_FILE   = "BinaryFile.txt"  # raw 32-bit hex words, one per line (no 0x)
CLOCK_SIGNAL  = None               # auto-detect if None
PC_STRIDE     = 4                  # bytes per instruction for synthetic PCs

# Pipeline stage signals in the VCD (edit to match your design)
stage_signals = {
    "IF": "HazardDetectionRV32I.core.IFBarrier.io_pc_out",
    "ID": "HazardDetectionRV32I.core.IDBarrier.pcReg",
    "EX": "HazardDetectionRV32I.core.EXBarrier.pcReg",
    "MEM": "HazardDetectionRV32I.core.MEMBarrier.pcReg",
    "WB": "HazardDetectionRV32I.core.WBBarrier.pcReg"
}

# Output filenames ------------------------------------------------------------
output_csv  = "pipeline_matrix.csv"
output_html = "pipeline_matrix.html"
output_vcd  = "pipeline_cycle_trace.vcd"

# Colors ----------------------------------------------------------------------
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
    w = ''.join(ch for ch in w if ch in '0123456789abcdef')
    if not w:
        return '00000000'
    return w.zfill(8)[-8:]


def disassemble_rv32_hex_word(pc: int, word8: str) -> str:
    """Return disassembly string for a single 32-bit word at pc (optional)."""
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
<input type=\"text\" id=\"searchBox\" onkeyup=\"searchTable()\" placeholder=\"Search by PC or hex...\">
<table>
<thead>
<tr><th>PC | Hex</th>
"""
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
# Build cycle->stage->PC occupancy & record first-appearance order of *hardware* PCs
# -----------------------------------------------------------------------------
cycle_stage_pc = [{st: None for st in stage_signals} for _ in range(num_cycles)]
first_seen_cycle = {}  # hw_pc -> cycle index

for stage, sig in stage_signals.items():
    if sig not in vcd.signals:
        print(f"⚠️ Warning: missing signal {sig}")
        continue
    tv = sorted(vcd[sig].tv, key=lambda x: x[0])

    # init last_pc from first valid value if exists
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

# Build hardware PC appearance order ------------------------------------------------
if not first_seen_cycle:
    raise RuntimeError("No valid PC values found in pipeline signals!")

# Sort by first appearance
pcs_hw_ordered = [pc for pc, _ in sorted(first_seen_cycle.items(), key=lambda kv: kv[1])]

# Force-insert synthetic PC_0x00000000 as *instruction 0* regardless of VCD contents
# (user request: first row always PC_0x00000000)
FORCED_FIRST_SYNTH_PC = 0x00000000

# -----------------------------------------------------------------------------
# Load BinaryFile & map *instruction index* -> synthetic PC & hex word
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

num_instr = len(hex_words)
print(f"Loaded {num_instr} instruction words from {BINARY_FILE}")

# Limit to instruction count --------------------------------------------------
# Build mapping *hardware PC* -> *synthetic PC* (0x0 + i*PC_STRIDE) for up to num_instr-1 entries.
# Instruction 0 is always synthetic PC=0, gets hex_words[0].  It is NOT mapped to a hardware PC; it will
# show empty stage occupancy unless hardware PC value matches some stage (rare) — this is intentional.

hw_to_synth_pc = {}
instr_index = 1  # start from 1 because 0 reserved for forced PC_0
for hw_pc in pcs_hw_ordered:
    if instr_index >= num_instr:  # stop when out of instructions
        break
    synth_pc = instr_index * PC_STRIDE
    hw_to_synth_pc[hw_pc] = synth_pc
    instr_index += 1

# Build label + decode dictionaries for synthetic PCs ------------------------
pc_synth_to_hex = {0: hex_words[0]} if num_instr > 0 else {}
pc_synth_to_dis = {}
if HAVE_CAPSTONE and num_instr > 0:
    pc_synth_to_dis[0] = disassemble_rv32_hex_word(0, hex_words[0])

# rest
for i in range(1, num_instr):
    pc_synth = i * PC_STRIDE
    word8 = hex_words[i]
    pc_synth_to_hex[pc_synth] = word8
    if HAVE_CAPSTONE:
        pc_synth_to_dis[pc_synth] = disassemble_rv32_hex_word(pc_synth, word8)

# Debug mapping ---------------------------------------------------------------
print("--- Synthetic PC mapping (instruction index -> synth PC) ---")
for i in range(num_instr):
    pc_synth = i * PC_STRIDE
    word8 = pc_synth_to_hex.get(pc_synth, '????????')
    disasm = pc_synth_to_dis.get(pc_synth, '')
    print(f"{i:02d}: PC_0x{pc_synth:08x} | {word8}{(' | ' + disasm) if disasm else ''}")

# -----------------------------------------------------------------------------
# Build Instruction × Cycle Matrix
#   We walk the pipeline occupancy, translate hardware PC -> synthetic PC (if mapped),
#   ignore any hardware PCs beyond the instruction count.
# -----------------------------------------------------------------------------
instruction_matrix = defaultdict(lambda: [''] * num_cycles)
tooltips_matrix     = defaultdict(lambda: [''] * num_cycles)

# ensure row 0 exists even if never mapped from hardware PC
if num_instr > 0:
    label0 = f"PC_0x{0:08x} | {pc_synth_to_hex.get(0, '????????')}"
    instruction_matrix[label0]  # creates row
    tooltips_matrix[label0]     # creates row

for c_idx, stages in enumerate(cycle_stage_pc):
    for stage, hw_pc in stages.items():
        if hw_pc is None:
            continue
        if hw_pc not in hw_to_synth_pc:
            continue  # drop extra PCs beyond instruction count
        synth_pc = hw_to_synth_pc[hw_pc]
        raw_hex  = pc_synth_to_hex.get(synth_pc, '????????')
        label    = f"PC_0x{synth_pc:08x} | {raw_hex}"
        if instruction_matrix[label][c_idx] == '':
            instruction_matrix[label][c_idx] = stage
        disasm = pc_synth_to_dis.get(synth_pc, '')
        tip = f"PC=0x{synth_pc:08x}  HEX={raw_hex}"
        if disasm:
            tip += f"  {disasm}"
        tooltips_matrix[label][c_idx] = tip

# Create DataFrames -----------------------------------------------------------
columns = [f"C{c}" for c in range(num_cycles)]
df = pd.DataFrame.from_dict(instruction_matrix, orient='index', columns=columns)
tooltips = pd.DataFrame.from_dict(tooltips_matrix, orient='index', columns=columns)

# Reindex rows strictly to instruction order (0..num_instr-1)
ordered_labels = []
for i in range(num_instr):
    pc_synth = i * PC_STRIDE
    raw_hex  = pc_synth_to_hex.get(pc_synth, '????????')
    ordered_labels.append(f"PC_0x{pc_synth:08x} | {raw_hex}")

df = df.reindex(ordered_labels)
tooltips = tooltips.reindex(ordered_labels)

# -----------------------------------------------------------------------------
# Detect simple stalls (stay in ID or EX >1 cycle)
# -----------------------------------------------------------------------------
for ridx, row in enumerate(df.index):
    row_vals = df.loc[row].tolist()
    for i in range(1, len(row_vals)):
        if row_vals[i] == row_vals[i-1] and row_vals[i] in ['ID', 'EX']:
            df.iat[ridx, i] = 'STALL'
            old_tip = tooltips.iat[ridx, i]
            tooltips.iat[ridx, i] = (old_tip + " (STALL)") if isinstance(old_tip, str) and old_tip else "STALL"

# -----------------------------------------------------------------------------
# Save CSV + print snippet
# -----------------------------------------------------------------------------
df.to_csv(output_csv)
print(f"\n✅ Matrix saved to {output_csv}")
print(df.iloc[:10, :25].fillna('').to_string())

# -----------------------------------------------------------------------------
# Generate VCD of stage occupancy (note: writes hardware PCs, not synthetic)
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