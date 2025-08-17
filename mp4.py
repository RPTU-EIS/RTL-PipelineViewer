#!/usr/bin/env python


from vcdvcd import VCDVCD
import pandas as pd
from collections import defaultdict
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32
import os
import re
import json # Import json for embedding data
import webbrowser

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

# --- Signals for Hazard Detection and Forwarding Unit ---
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

# --- Signals for Register File ---
register_signals = {f"x{i}": f"HazardDetectionRV32I.core.regFile.regFile_{i}" for i in range(32)}

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
                if last_val.startswith('b'):
                    values.append(int(last_val[1:], 2))
                elif last_val.startswith('h'):
                    values.append(int(last_val[1:], 16))
                else:
                    values.append(int(last_val, base))
            except (ValueError, TypeError):
                values.append(default_val)
        else:
            values.append(default_val)
    return values

# --- Extract Signal Data ---
ex_values_by_cycle = [{} for _ in range(num_cycles)]
wb_values_by_cycle = [{} for _ in range(num_cycles)]
hazard_data_raw_by_cycle = [{} for _ in range(num_cycles)]
register_values_by_cycle = [{} for _ in range(num_cycles)]

for key, signal_name in ex_signals.items():
    vals = extract_signal_at_cycles(signal_name, default_val=None, base=2) 
    for cycle_idx, val in enumerate(vals):
        ex_values_by_cycle[cycle_idx][key] = val

for key, signal_name in wb_signals.items():
    vals = extract_signal_at_cycles(signal_name, default_val=None, base=2)
    for cycle_idx, val in enumerate(vals):
        wb_values_by_cycle[cycle_idx][key] = val

for key, signal_name in hazard_signals.items():
    vals = extract_signal_at_cycles(signal_name, default_val=0, base=2)
    for cycle_idx, val in enumerate(vals):
        hazard_data_raw_by_cycle[cycle_idx][key] = val

print("Extracting register values for each cycle...")
for reg_name, signal_name in register_signals.items():
    vals = extract_signal_at_cycles(signal_name, default_val=0, base=16)
    for cycle_idx, val in enumerate(vals):
        if isinstance(val, int):
            register_values_by_cycle[cycle_idx][reg_name] = f"0x{val:08x}"
        else:
            register_values_by_cycle[cycle_idx][reg_name] = '0x00000000'
print("✅ Register data extracted.")

# --- Apply Delays for Correct Cycle Synchronization ---
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
print("✅ Applied one-cycle delay to register file data.")

def convert_hex_immediates_to_decimal(disasm: str) -> str:
    def replace_hex(match):
        hex_str = match.group(0)
        value = int(hex_str, 16)
        if value >= 0x800: value -= 0x1000
        return str(value)
    return re.sub(r'0x[0-9a-fA-F]+', replace_hex, disasm)

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
            try: current_pc_val = int(pc_tv[pc_idx][1], 16)
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
cycle_stage_pc = [{stage: None for stage in stage_signals} for _ in range(num_cycles)]
for stage, signal_name in stage_signals.items():
    if signal_name not in vcd.signals: continue
    signal_tv = sorted(vcd[signal_name].tv, key=lambda x: x[0])
    last_valid_pc, tv_idx = None, 0
    for cycle_idx, rise_time in enumerate(rising_edges):
        while tv_idx < len(signal_tv) and signal_tv[tv_idx][0] <= rise_time:
            val = signal_tv[tv_idx][1]
            if 'x' not in val.lower():
                try: last_valid_pc = int(val, 16)
                except (ValueError, TypeError): pass
            tv_idx += 1
        cycle_stage_pc[cycle_idx][stage] = last_valid_pc

# --- Assign Synthetic PCs ---
vcd_actual_to_synthetic_pc_map = {}
synthetic_pc_counter = 0
all_pcs_from_vcd = sorted(list(actual_pc_to_instr_raw.keys()))
for actual_pc in all_pcs_from_vcd:
    if actual_pc not in vcd_actual_to_synthetic_pc_map:
        vcd_actual_to_synthetic_pc_map[actual_pc] = synthetic_pc_counter
        synthetic_pc_counter += 4

# --- Prepare Data for HTML/JS ---
pipeline_data_for_js = defaultdict(lambda: [None] * num_cycles)
for cycle_idx in range(num_cycles):
    current_hazard_data = delayed_hazard_data_by_cycle[cycle_idx]
    forwardA = current_hazard_data.get("forwardA", 0)
    forwardB = current_hazard_data.get("forwardB", 0)
    hazard_sources = set()
    if forwardA == 1 or forwardB == 1: hazard_sources.add(cycle_stage_pc[cycle_idx].get("MEM"))
    if forwardA == 2 or forwardB == 2: hazard_sources.add(cycle_stage_pc[cycle_idx].get("WB"))
    
    for stage, actual_pc in cycle_stage_pc[cycle_idx].items():
        if actual_pc in vcd_actual_to_synthetic_pc_map:
            synth_pc = vcd_actual_to_synthetic_pc_map[actual_pc]
            asm_text = actual_pc_to_disassembled_instr.get(actual_pc, {}).get("asm", "N/A_ASM")
            tooltip = f"Stage: {stage}\nPC: 0x{actual_pc:08x}\nInstruction: {asm_text}"
            display = stage
            # --- MODIFICATION: Added source_pc_mem/wb for arrows ---
            hazard_info = {"forwardA": 0, "forwardB": 0, "source_pc_mem": None, "source_pc_wb": None}
            is_source = actual_pc in hazard_sources
            if is_source: tooltip += "\n--- Hazard Source ---"

            if stage == "EX":
                hazard_info["forwardA"] = forwardA
                hazard_info["forwardB"] = forwardB
                if forwardA == 1 or forwardB == 1:
                    hazard_info["source_pc_mem"] = vcd_actual_to_synthetic_pc_map.get(
                        cycle_stage_pc[cycle_idx].get("MEM")
                    )
                if forwardA == 2 or forwardB == 2:
                    hazard_info["source_pc_wb"] = vcd_actual_to_synthetic_pc_map.get(
                        cycle_stage_pc[cycle_idx].get("WB")
                    )

                # --- Pretty operator like in mp4.py ---
                ex_data = delayed_ex_values_by_cycle[cycle_idx]
                op_a = ex_data.get("operandA")
                op_b = ex_data.get("operandB")
                res  = ex_data.get("aluResult")

                # Map mnemonics -> math symbols
                operator_map_plain = {
                    "ADDI": "+", "ADD": "+", "SUB": "-",
                    "AND": "&", "ANDI": "&",
                    "OR":  "|", "ORI":  "|",
                    "XOR": "^", "XORI": "^",
                    "SLL": "<<", "SLLI": "<<",
                    "SRL": ">>", "SRLI": ">>",
                    "SRA": ">>>", "SRAI": ">>>",
                    "SLT": "<", "SLTI": "<",
                    "SLTU": "<u", "SLTIU": "<u",
                }

                # Safe mnemonic extraction (works even if asm_text is "N/A_ASM")
                mnemonic = (asm_text.split()[0] if isinstance(asm_text, str) and asm_text else "").upper()
                operator_plain = operator_map_plain.get(mnemonic, mnemonic)

                # Escape for HTML cell so <, >, & render visually
                operator_html = (
                    operator_plain
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                )

                if (op_a is not None) and (op_b is not None) and (res is not None):
                    display = f"EX<br>{op_a} {operator_html} {op_b} = {res}"
                    # Tooltip shows the plain (unescaped) version
                    tooltip += f"\n--- ALU Op ---\n{op_a} {operator_plain} {op_b} = {res}"


            pipeline_data_for_js[synth_pc][cycle_idx] = {
                "stage": stage, "tooltip": tooltip, "display_text": display,
                "hazard_info": hazard_info, "is_hazard_source": is_source
            }

pipeline_data_for_js_serializable = {str(pc): data for pc, data in pipeline_data_for_js.items()}

instruction_labels_for_js = []
sorted_synth_pcs = sorted(vcd_actual_to_synthetic_pc_map.values())
for synth_pc in sorted_synth_pcs:
    actual_pc = next((apc for apc, spc in vcd_actual_to_synthetic_pc_map.items() if spc == synth_pc), None)
    if actual_pc is not None:
        hex_display = actual_pc_to_instr_hex_display.get(actual_pc, "N/A_HEX")
        asm_display = actual_pc_to_disassembled_instr.get(actual_pc, {}).get("asm", "N/A_ASM")
        asm_display = 'nop' if asm_display == 'addi zero, zero, 0' else asm_display
        instruction_labels_for_js.append(f"PC_0x{synth_pc:08x} | {hex_display} ({asm_display})")

# --- HTML Generation ---
color_map_js = json.dumps({"IF":"#ff9933","ID":"#5cd65c","EX":"#4b9aefd7","MEM":"#b366ff","WB":"#ff4d4d"})

html_content = """
<html><head><title>Pipeline & Register Animation</title>
<style>
body {{ font-family: sans-serif; margin: 20px; }} h2, h3 {{ text-align: center; }}
.controls {{ text-align: center; margin-bottom: 20px; display: flex; justify-content: center; align-items: center; gap: 10px; flex-wrap: wrap; }}
.controls button {{ padding: 10px 20px; font-size: 16px; cursor: pointer; }} #cycleCounter {{ font-size: 18px; font-weight: bold; }}
.speed-control-container {{ display: flex; align-items: center; gap: 5px; }}
#speedValue {{ font-family: monospace; font-size: 14px; min-width: 50px; text-align: left; }}
.content-wrapper {{ display: flex; justify-content: center; align-items: flex-start; gap: 50px; flex-wrap: wrap; }}
.pipeline-grid, .register-grid {{ display: grid; border: 1px solid #ccc; width: fit-content; }}
.pipeline-grid {{ grid-template-columns: 390px repeat(5, 140px); }}
.register-grid {{ grid-template-columns: 120px 200px; }}
.grid-header, .grid-cell {{ padding: 8px; border: 1px solid #eee; text-align: center; white-space: nowrap; }}
.grid-header {{ background-color: #ddd; font-weight: bold; }}
.instruction-label {{ text-align: left; font-weight: bold; font-family: monospace; font-size: 14px; }}
.stage-cell {{ height: 50px; position: relative; }}
.stage-content {{ width: 95%; height: 95%; border-radius: 5px; display: flex; flex-direction: column; align-items: center; justify-content: center; font-size: 11px; color: #333; cursor: help; transition: all 0.2s ease-in-out; margin: auto; line-height: 1.2; padding: 2px; }}
.tooltip-text {{ visibility: hidden; background-color: #555; color: #fff; text-align: left; border-radius: 6px; padding: 8px; position: absolute; z-index: 10; bottom: 125%; left: 50%; transform: translateX(-50%); opacity: 0; transition: opacity 0.3s; width: max-content; white-space: pre-wrap; }}
.stage-content:hover .tooltip-text {{ visibility: visible; opacity: 1; }}
.legend {{ margin: 20px auto; display: flex; justify-content: center; gap: 20px; padding: 10px; border: 1px solid #ddd; border-radius: 8px; width: fit-content; flex-wrap: wrap; }}
.legend-item {{ display: inline-flex; align-items: center; gap: 8px; }}
.legend-color-box {{ width: 20px; height: 20px; border-radius: 4px; border: 2px solid; }}
.register-name-cell {{ font-family: monospace; text-align: left !important; padding-left: 10px !important; }}
.register-value-cell {{ font-family: monospace; }}
.register-value-cell.changed {{ background-color: #FFD700; transition: background-color 0.1s ease-in; }}
.hazard-source-highlight {{ border: 3px solid #FF4500 !important; box-shadow: 0 0 10px rgba(255, 69, 0, 0.7); }}
.forwarding-destination-highlight {{ border: 3px solid #007BFF !important; box-shadow: 0 0 10px rgba(0, 123, 255, 0.7); background-color: #cce5ff !important; }}
/* --- MODIFICATION: Styles for dataflow arrows --- */
#arrow-svg {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 5; }}
.arrow {{ stroke: #FF4500; stroke-width: 2.5; fill: none; stroke-dasharray: 5; animation: dash 0.5s linear infinite; marker-end: url(#arrowhead); }}
@keyframes dash {{ to {{ stroke-dashoffset: -10; }} }}
</style>
</head>
<body>
<h2>Pipeline Animation with Register State</h2>
<div class="controls">
    <button id="prevBtn">Previous</button>
    <span id="cycleCounter">Cycle 0 / {num_cycles}</span>
    <button id="nextBtn">Next</button>
    <button id="playPauseBtn">Play</button>
    <button id="toggleArrowsBtn">Hide Arrows</button>
    <button id="restartBtn">Restart</button>
    <div class="speed-control-container">
        <label for="speedControl">Speed:</label>
        <input type="range" id="speedControl" min="100" max="1000" value="500" step="50">
        <span id="speedValue">500ms</span>
    </div>
</div>

<div class="legend">
    <div class="legend-item"><div class="legend-color-box" style="border-color: #FF4500; background-color: #fff2e6;"></div><span>Hazard Source</span></div>
    <div class="legend-item"><div class="legend-color-box" style="border-color: #007BFF; background-color: #cce5ff;"></div><span>Forwarding Destination</span></div>
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
            <div class="grid-header">Register</div><div class="grid-header">Value</div>
        </div>
    </div>
</div>
<div class="controls">
    <button id="prevBtn">Previous</button>
    <span id="cycleCounter">Cycle 0 / {num_cycles}</span>
    <button id="nextBtn">Next</button>
    <button id="playPauseBtn">Play</button>
    <button id="restartBtn">Restart</button>
    <button id="toggleArrowsBtn">Hide Arrows</button>
    <div class="speed-control-container">
        <label for="speedControl">Speed:</label>
        <input type="range" id="speedControl" min="100" max="1000" value="500" step="50">
        <span id="speedValue">500ms</span>
    </div>
</div>

<script>
    const pipelineData = {pipeline_data_js};
    const instructionLabels = {instruction_labels_js};
    const registerData = {register_data_js};
    const numCycles = {num_cycles};
    const colorMap = {color_map_js};
    const vcd_actual_to_synthetic_pc_map = {vcd_actual_to_synthetic_pc_map_js};
    const abiNames = ["zero","ra","sp","gp","tp","t0","t1","t2","s0/fp","s1","a0","a1","a2","a3","a4","a5","a6","a7","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11","t3","t4","t5","t6"];
    let currentCycle = 0, animationInterval = null, animationSpeed = 500, showArrows = true;
    
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

    // --- MODIFICATION: Refactored to build the static grid once ---
    function populateStaticGrid() {{
        // Pipeline Headers
        ['Instruction', 'IF', 'ID', 'EX', 'MEM', 'WB'].forEach(text => {{
            const header = document.createElement('div');
            header.className = 'grid-header'; header.textContent = text;
            pipelineDisplay.appendChild(header);
        }});
        // Instruction Rows
        instructionLabels.forEach((label, idx) => {{
            if (idx === 0) return;
            const synthPc = idx * 4;
            const labelDiv = document.createElement('div');
            labelDiv.className = 'grid-cell instruction-label';
            labelDiv.id = `instr-label-${{synthPc}}`;
            labelDiv.textContent = label;
            pipelineDisplay.appendChild(labelDiv);
            for (let i = 0; i < 5; i++) {{
                const stageCell = document.createElement('div');
                stageCell.className = 'grid-cell stage-cell';
                stageCell.id = `stage-cell-${{synthPc}}-${{i}}`;
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
        }}
    }}

    function updateDisplay() {{
        cycleCounter.textContent = `Cycle ${{currentCycle}} / ${{numCycles - 1}}`;
        updatePipelineDisplay();
        updateRegisterTable();
        prevBtn.disabled = currentCycle === 0;
        nextBtn.disabled = currentCycle === numCycles - 1;
        // Use timeout to ensure DOM is updated before calculating arrow positions
        setTimeout(updateArrows, 0);
    }}

        function updatePipelineDisplay() {{
            // Clear only the dynamic content (stage cells and highlights)
            document.querySelectorAll('.stage-cell').forEach(c => c.innerHTML = '');
            document.querySelectorAll('.instruction-label').forEach(l => l.classList.remove('hazard-source-highlight'));
            
            Object.entries(pipelineData).forEach(([synthPc, cycleData]) => {{
                const instrCycleData = cycleData[currentCycle];
                if (instrCycleData) {{
                    //if (instrCycleData.is_hazard_source) {{
                    //    document.getElementById(`instr-label-${{synthPc}}`).classList.add('hazard-source-highlight');
                    //}}
                    const stageIdx = {{IF:0, ID:1, EX:2, MEM:3, WB:4}}[instrCycleData.stage];
                    const stageCell = document.getElementById(`stage-cell-${{synthPc}}-${{stageIdx}}`);
                    if (!stageCell) return;
                    
                    const contentDiv = document.createElement('div');
                    contentDiv.className = 'stage-content';
                    contentDiv.style.backgroundColor = colorMap[instrCycleData.stage];
                    contentDiv.innerHTML = instrCycleData.display_text;
                    // Assign an ID for the arrow drawing logic
                    contentDiv.id = `content-${{synthPc}}-${{instrCycleData.stage}}`;

                    // Only show the blue "forwarding destination" highlight when arrows are visible
                    if (instrCycleData.stage === "EX") {{
                        const hasForwarding = (instrCycleData.hazard_info.forwardA !== 0) || (instrCycleData.hazard_info.forwardB !== 0);
                        if (showArrows && hasForwarding) {{
                            contentDiv.classList.add('forwarding-destination-highlight');
                        }}
                    }}

                  //  if (instrCycleData.is_hazard_source) {{
                  //      contentDiv.classList.add('hazard-source-highlight');
                  //  }}
                    
                    const tooltipSpan = document.createElement('span');
                    tooltipSpan.className = 'tooltip-text';
                    tooltipSpan.textContent = instrCycleData.tooltip;
                    contentDiv.appendChild(tooltipSpan);
                    stageCell.appendChild(contentDiv);
                }}
            }});
        }}

    
    function updateRegisterTable() {{
        const currentRegs = registerData[currentCycle] || {{}};
        const prevRegs = currentCycle > 0 ? registerData[currentCycle - 1] : {{}};

        for (let i = 0; i < 32; i++) {{
            const valCell = document.getElementById(`reg-val-${{i}}`);
            const currentVal = currentRegs[`x${{i}}`] || '0x00000000';
            const prevVal = prevRegs[`x${{i}}`] || '0x00000000';

            // Show decimal as *binary* if hex digits are only 0/1; otherwise as hex
            let displayValue = currentVal;
            if (typeof currentVal === 'string' && currentVal.startsWith('0x')) {{
                const digits = currentVal.slice(2); // e.g. "00000100"
                let dec = Number.NaN;

                if (/^[01]+$/.test(digits)) {{
                    // treat as binary
                    dec = parseInt(digits, 2);
                }} else if (/^[0-9a-fA-F]+$/.test(digits)) {{
                    // treat as hex
                    dec = parseInt(digits, 16);
                }}

                if (!Number.isNaN(dec)) {{
                    displayValue = `${{currentVal}} (${{dec}})`;
                }}
            }}

            valCell.textContent = displayValue;

            // highlight if value changed
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
        path.setAttribute('class', 'arrow');
        arrowSvg.appendChild(path);
    }}

    // --- NEW: Function to update all arrows for the current cycle ---
    function updateArrows() {{
        if (!showArrows) {{
            arrowSvg.innerHTML = ''; // clear any existing arrows when hidden
            return;
        }}
        arrowSvg.innerHTML = '<defs><marker id="arrowhead" markerWidth="5" markerHeight="3.5" refX="0" refY="1.75" orient="auto"><polygon points="0 0, 5 1.75, 0 3.5" fill="#FF4500" /></marker></defs>';
        
        Object.entries(pipelineData).forEach(([synthPc, cycleData]) => {{
            const instrCycleData = cycleData[currentCycle];
            if (instrCycleData && instrCycleData.stage === 'EX') {{
                const hazardInfo = instrCycleData.hazard_info;
                const toElem = document.getElementById(`content-${{synthPc}}-EX`);

                if (hazardInfo.source_pc_mem !== null) {{
                    const fromElem = document.getElementById(`content-${{hazardInfo.source_pc_mem}}-MEM`);
                    drawArrow(fromElem, toElem);
                }}
                if (hazardInfo.source_pc_wb !== null) {{
                    const fromElem = document.getElementById(`content-${{hazardInfo.source_pc_wb}}-WB`);
                    drawArrow(fromElem, toElem);
                }}
            }}
        }});
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
        document.getElementById('toggleArrowsBtn').textContent = showArrows ? 'Hide Arrows' : 'Show Arrows';
        updateDisplay(); // re-render (clears or draws arrows accordingly)
    }});

    // Initial setup
    populateStaticGrid();
    updateDisplay();
</script>
</body>
</html>
""".format(
    num_cycles=num_cycles,
    pipeline_data_js=json.dumps(pipeline_data_for_js_serializable),
    instruction_labels_js=json.dumps(instruction_labels_for_js),
    register_data_js=json.dumps(delayed_register_values_by_cycle),
    color_map_js=color_map_js,
    vcd_actual_to_synthetic_pc_map_js=json.dumps(vcd_actual_to_synthetic_pc_map)
)

# --- Write the final HTML file ---
print(f"Writing output to {output_html}")
with open(output_html, "w") as f:
    f.write(html_content)

print(f"✅ Successfully generated '{output_html}'. Open this file in your web browser to view the animation.")
webbrowser.open_new_tab(output_html)