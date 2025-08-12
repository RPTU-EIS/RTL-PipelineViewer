from vcdvcd import VCDVCD
from vcd.writer import VCDWriter
import pandas as pd
from collections import defaultdict
import os

# --- Configuration ---
VCD_FILE = "dump.vcd"
CLOCK_SIGNAL = None  # Auto-detect clock if None
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

# --- Detect rising edges (cycles) ---
clock_tv = vcd[CLOCK_SIGNAL].tv
rising_edges = []
prev_val = '0'
for t, val in sorted(clock_tv, key=lambda x: x[0]):
    if prev_val == '0' and val == '1':
        rising_edges.append(t)
    prev_val = val
num_cycles = len(rising_edges)
print(f"Detected {num_cycles} clock cycles.")

# --- Build timeline: cycle → stage → PC ---
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

# --- Build Instruction × Cycle Matrix ---
instruction_matrix = defaultdict(lambda: [''] * num_cycles)
for cycle_idx, stages in enumerate(cycle_stage_pc):
    for stage, pc in stages.items():
        if pc is not None:
            row_key = f"PC_0x{pc:08x}"
            instruction_matrix[row_key][cycle_idx] = stage

# Create DataFrame
df = pd.DataFrame.from_dict(instruction_matrix, orient='index', columns=[f"C{c}" for c in range(num_cycles)])
df = df.sort_index()

# --- Save CSV ---
df.to_csv(output_csv)
print(f"\n✅ Matrix saved to {output_csv}")

# --- Print snippet like example ---
print(df.iloc[:10, :25].fillna('').to_string())

# --- Generate VCD for surfer visualization ---
print(f"\nGenerating VCD file: {output_vcd}")
with open(output_vcd, 'w') as f:
    with VCDWriter(f, timescale='1ns', date='2025-07-18', comment='Cycle-aligned pipeline trace') as writer:
        vcd_signals = {
            stage: writer.register_var('pipeline_monitor', f'pc_{stage.lower()}', 'wire', size=32)
            for stage in stage_signals.keys()
        }
        last_written = {stage: None for stage in stage_signals}
        for cycle_idx, stages in enumerate(cycle_stage_pc):
            time_ns = cycle_idx * 10  # assume 10ns per cycle
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

# --- Generate HTML with colors ---
try:
    import jinja2  # check if installed
except ImportError:
    os.system("pip install jinja2")

color_map = {
    "IF": "#4da6ff", "ID": "#5cd65c", "EX": "#ff9933", "MEM": "#b366ff", "WB": "#ff4d4d"
}

def color_stage(val):
    return f"background-color:{color_map.get(val, '#ffffff')};text-align:center;"

styled_df = df.style.applymap(color_stage)
styled_df.set_table_attributes('border="1" class="pipeline-table"').to_html(output_html)

print(f"✅ HTML visualization saved as {output_html}. Open in browser.")
