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

# --- NEW: Signals for Register File ---
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
                # Handle binary ('b') or hex ('h') prefixes if they exist
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
    vals = extract_signal_at_cycles(signal_name, default_val='x', base=16)
    for cycle_idx, val in enumerate(vals):
        if isinstance(val, int):
            register_values_by_cycle[cycle_idx][reg_name] = f"0x{val:08x}"
        else:
            register_values_by_cycle[cycle_idx][reg_name] = 'N/A'
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

# NEW: Apply one-cycle delay to register file data
delayed_register_values_by_cycle = [{} for _ in range(num_cycles)]
for i in range(1, num_cycles):
    delayed_register_values_by_cycle[i] = register_values_by_cycle[i-1]
print("✅ Applied one-cycle delay to register file data.")


rd_wb_addr_values = extract_signal_at_cycles(hazard_signals["rd_wb_addr"], default_val=0, base=2)
delayed_rd_wb_2_cycles_ago = [0] * num_cycles
for i in range(2, num_cycles):
    delayed_rd_wb_2_cycles_ago[i] = rd_wb_addr_values[i-1]


def convert_hex_immediates_to_decimal(disasm: str) -> str:
    """
    Converts all 0xNNN style immediates in a disassembled instruction to signed decimal.
    """
    def replace_hex(match):
        hex_str = match.group(0)
        value = int(hex_str, 16)
        if value >= 0x800:
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
    pc_idx, instr_idx = 0, 0

    for t in all_signal_times_for_stage:
        while pc_idx < len(pc_tv) and pc_tv[pc_idx][0] <= t:
            try:
                current_pc_val = int(pc_tv[pc_idx][1], 16)
            except (ValueError, TypeError):
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
            except (ValueError, TypeError):
                instr_hex_for_bytes = ""

            actual_pc_to_instr_hex_display[current_pc_val] = instr_display_str

            if current_pc_val not in actual_pc_to_disassembled_instr and instr_hex_for_bytes:
                disassembled_text = "N/A_ASM"
                try:
                    instr_bytes = bytes.fromhex(instr_hex_for_bytes)[::-1]
                    disassembled = list(md.disasm(instr_bytes, current_pc_val))
                    if disassembled:
                        insn = disassembled[0]
                        disassembled_text = f"{insn.mnemonic} {insn.op_str}"
                        disassembled_text = convert_hex_immediates_to_decimal(disassembled_text)
                    actual_pc_to_disassembled_instr[current_pc_val] = {"asm": disassembled_text}
                except Exception as e:
                    actual_pc_to_disassembled_instr[current_pc_val] = {"asm": f"ASM Error: {e}"}

# --- Build timeline (cycle_stage_pc) ---
cycle_stage_pc = [{stage: None for stage in stage_signals} for _ in range(num_cycles)]

for stage, signal_name in stage_signals.items():
    if signal_name not in vcd.signals: continue
    signal_tv = sorted(vcd[signal_name].tv, key=lambda x: x[0])
    last_valid_pc_seen = None
    tv_idx = 0
    for cycle_idx, rise_time in enumerate(rising_edges):
        while tv_idx < len(signal_tv) and signal_tv[tv_idx][0] <= rise_time:
            val = signal_tv[tv_idx][1]
            if 'x' not in val.lower():
                try:
                    last_valid_pc_seen = int(val, 16)
                except (ValueError, TypeError): pass
            tv_idx += 1
        cycle_stage_pc[cycle_idx][stage] = last_valid_pc_seen

# --- Assign synthetic PCs ---
vcd_actual_to_synthetic_pc_map = {}
synthetic_pc_counter = 0
# Get a sorted list of unique PCs to ensure deterministic assignment
all_pcs_from_vcd = sorted(list(actual_pc_to_instr_raw.keys()))
for actual_pc in all_pcs_from_vcd:
    if actual_pc not in vcd_actual_to_synthetic_pc_map:
        vcd_actual_to_synthetic_pc_map[actual_pc] = synthetic_pc_counter
        synthetic_pc_counter += 4


# --- Prepare data for HTML/JS animation ---
pipeline_data_for_js = defaultdict(lambda: [None] * num_cycles)

for cycle_idx in range(num_cycles):
    for stage, actual_pc in cycle_stage_pc[cycle_idx].items():
        if actual_pc is not None and actual_pc in vcd_actual_to_synthetic_pc_map:
            synthetic_pc = vcd_actual_to_synthetic_pc_map[actual_pc]
            
            dis_info = actual_pc_to_disassembled_instr.get(actual_pc, {})
            disassembled_text = dis_info.get("asm", "N/A_ASM")
            
            tooltip_content = f"Stage: {stage}\nPC: 0x{actual_pc:08x}\nInstruction: {disassembled_text}"
            display_text = stage
            hazard_info = {"forwardA": 0, "forwardB": 0}

            if stage == "EX":
                current_hazard_data = delayed_hazard_data_by_cycle[cycle_idx] 
                forwardA_val = current_hazard_data.get("forwardA", 0)
                forwardB_val = current_hazard_data.get("forwardB", 0)
                hazard_info["forwardA"] = forwardA_val
                hazard_info["forwardB"] = forwardB_val
                
                if forwardA_val != 0 or forwardB_val != 0:
                    tooltip_content += "\n--- Forwarding Detected ---"
                    if forwardA_val != 0: tooltip_content += f"\nForwardA: Code {forwardA_val}"
                    if forwardB_val != 0: tooltip_content += f"\nForwardB: Code {forwardB_val}"
            
            pipeline_data_for_js[synthetic_pc][cycle_idx] = {
                "stage": stage,
                "tooltip": tooltip_content,
                "display_text": display_text,
                "hazard_info": hazard_info
            }

pipeline_data_for_js_serializable = {str(pc): data for pc, data in pipeline_data_for_js.items()}

instruction_labels_for_js = []
# Ensure labels are created for all known instructions in a sorted order
sorted_synthetic_pcs = sorted(vcd_actual_to_synthetic_pc_map.values())

for synthetic_pc in sorted_synthetic_pcs:
    actual_pc = next((apc for apc, spc in vcd_actual_to_synthetic_pc_map.items() if spc == synthetic_pc), None)
    if actual_pc is not None:
        instr_hex_display = actual_pc_to_instr_hex_display.get(actual_pc, "N/A_HEX")
        asm_display = actual_pc_to_disassembled_instr.get(actual_pc, {}).get("asm", "N/A_ASM")
        
        # Special case for nop, which is often disassembled as 'addi zero, zero, 0'
        if asm_display == 'addi zero, zero, 0':
            asm_display = 'nop'
            
        instruction_labels_for_js.append(f"PC_0x{synthetic_pc:08x} | {instr_hex_display} ({asm_display})")


# --- HTML Generation for Animation ---
color_map_js = json.dumps({
    "IF": "#4da6ff", "ID": "#5cd65c", "EX": "#ff9933",
    "MEM": "#b366ff", "WB": "#ff4d4d", "STALL": "#bfbfbf"
})

html_content = """
<html>
<head>
<title>Pipeline & Register Animation</title>
<style>
body {{ font-family: sans-serif; margin: 20px; }}
h2, h3 {{ text-align: center; }}
.controls {{ text-align: center; margin-bottom: 20px; }}
.controls button {{ padding: 10px 20px; font-size: 16px; margin: 0 5px; cursor: pointer; }}
#cycleCounter {{ font-size: 18px; font-weight: bold; margin: 0 15px; }}
.content-wrapper {{ display: flex; justify-content: center; align-items: flex-start; gap: 50px; flex-wrap: wrap; }}
.pipeline-grid, .register-grid {{ display: grid; border: 1px solid #ccc; width: fit-content; }}
.pipeline-grid {{ grid-template-columns: 450px repeat(5, 100px); }}
.register-grid {{ grid-template-columns: 150px 140px; }}
.grid-header, .grid-cell {{ padding: 8px; border: 1px solid #eee; text-align: center; white-space: nowrap; }}
.grid-header {{ background-color: #ddd; font-weight: bold; }}
.instruction-label {{ text-align: left; font-weight: bold; font-family: monospace; font-size: 14px; }}
.stage-cell {{ height: 40px; position: relative; }}
.stage-content {{ width: 90%; height: 80%; border-radius: 5px; display: flex; align-items: center; justify-content: center; font-size: 12px; color: #333; cursor: help; transition: all 0.2s ease-in-out; margin: auto; }}
.tooltip-text {{ visibility: hidden; background-color: #555; color: #fff; text-align: left; border-radius: 6px; padding: 8px; position: absolute; z-index: 10; bottom: 125%; left: 50%; transform: translateX(-50%); opacity: 0; transition: opacity 0.3s; width: max-content; white-space: pre-wrap; }}
.stage-content:hover .tooltip-text {{ visibility: visible; opacity: 1; }}
.forwarding-highlight {{ border: 3px solid #FFD700; box-shadow: 0 0 10px rgba(255, 215, 0, 0.7); background-color: #FFFACD !important; }}
.legend {{ margin: 20px auto; text-align: center; width: fit-content; }}
.legend-item {{ display: inline-flex; align-items: center; margin: 0 10px; }}
.legend-color-box {{ width: 20px; height: 20px; border-radius: 4px; margin-right: 8px; border: 2px solid #FFD700; background-color: #FFFACD; }}
.register-name-cell {{ font-family: monospace; text-align: left !important; padding-left: 10px !important; }}
.register-value-cell {{ font-family: monospace; }}
/* NEW: Style for highlighting changed register values */
.register-value-cell.changed {{
    background-color: #FFD700; /* Gold color */
    transition: background-color 0.1s ease-in;
}}
</style>
</head>
<body>
<h2>Pipeline Animation with Register State</h2>
<div class="controls">
    <button id="prevBtn">Previous</button>
    <span id="cycleCounter">Cycle 0 / {num_cycles}</span>
    <button id="nextBtn">Next</button>
    <button id="playPauseBtn">Play</button>
    <button id="restartBtn">Restart</button>
</div>
<div class="legend">
    <div class="legend-item"><div class="legend-color-box"></div><span>Hazard/Forwarding Detected</span></div>
</div>
<div class="content-wrapper">
    <div class="pipeline-container">
        <h3>Pipeline Stages</h3>
        <div id="pipelineDisplay" class="pipeline-grid">
            <div class="grid-header">Instruction</div>
            <div class="grid-header">IF</div><div class="grid-header">ID</div>
            <div class="grid-header">EX</div><div class="grid-header">MEM</div><div class="grid-header">WB</div>
        </div>
    </div>
    <div class="register-container">
        <h3>Register File State</h3>
        <div id="registerTable" class="register-grid">
            <div class="grid-header">Register</div><div class="grid-header">Value</div>
        </div>
    </div>
</div>
<script>
    const pipelineData = {pipeline_data_js};
    const instructionLabels = {instruction_labels_js};
    const registerData = {register_data_js};
    const numCycles = {num_cycles};
    const colorMap = {color_map_js};
    const abiNames = [
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0/fp", "s1", 
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", 
        "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", 
        "t3", "t4", "t5", "t6"
    ];
    let currentCycle = 0;
    let animationInterval = null;
    const animationSpeed = 500;
    const pipelineDisplay = document.getElementById('pipelineDisplay');
    const registerTable = document.getElementById('registerTable');
    const cycleCounter = document.getElementById('cycleCounter');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const playPauseBtn = document.getElementById('playPauseBtn');
    const restartBtn = document.getElementById('restartBtn');

    function updateDisplay() {{
        cycleCounter.textContent = `Cycle ${{currentCycle}} / ${{numCycles - 1}}`;
        updatePipelineDisplay();
        updateRegisterTable();
        prevBtn.disabled = currentCycle === 0;
        nextBtn.disabled = currentCycle === numCycles - 1;
    }}

    function updatePipelineDisplay() {{
        // Clear old rows, keep headers
        while (pipelineDisplay.children.length > 6) {{
            pipelineDisplay.removeChild(pipelineDisplay.lastChild);
        }}
        instructionLabels.forEach((label, instrIdx) => {{
            // Skip the first instruction row (PC 0x0)
            if (instrIdx === 0) return;
            
            const syntheticPcKey = (instrIdx * 4);
            const syntheticPcExists = Object.values(vcd_actual_to_synthetic_pc_map).includes(syntheticPcKey);

            if (!syntheticPcExists) return;

            const labelDiv = document.createElement('div');
            labelDiv.className = 'grid-cell instruction-label';
            labelDiv.textContent = label;
            pipelineDisplay.appendChild(labelDiv);
            
            ["IF", "ID", "EX", "MEM", "WB"].forEach(stageName => {{
                const stageCell = document.createElement('div');
                stageCell.className = 'grid-cell stage-cell';
                
                const cycleDataForPc = pipelineData[syntheticPcKey];
                const instrCycleData = cycleDataForPc ? cycleDataForPc[currentCycle] : null;

                if (instrCycleData && instrCycleData.stage === stageName) {{
                    const contentDiv = document.createElement('div');
                    contentDiv.className = 'stage-content';
                    contentDiv.style.backgroundColor = colorMap[stageName];
                    contentDiv.textContent = instrCycleData.display_text;
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
    }}
    
    function updateRegisterTable() {{
        // Clear old rows, keep headers
        while (registerTable.children.length > 2) {{
            registerTable.removeChild(registerTable.lastChild);
        }}
        const currentRegisterValues = registerData[currentCycle];
        // Get the previous cycle's data for comparison
        const previousRegisterValues = currentCycle > 0 ? registerData[currentCycle - 1] : null;

        for (let i = 0; i < 32; i++) {{
            const regId = `x${{i}}`;
            const regName = `${{regId}} (${{abiNames[i]}})`;

            // Create name cell
            const nameCell = document.createElement('div');
            nameCell.className = 'grid-cell register-name-cell';
            nameCell.textContent = regName;
            registerTable.appendChild(nameCell);
            
            // Create value cell
            const valueCell = document.createElement('div');
            valueCell.className = 'grid-cell register-value-cell';
            
            const currentValue = currentRegisterValues ? (currentRegisterValues[regId] || 'N/A') : 'N/A';
            valueCell.textContent = currentValue;

            // NEW: Highlighting logic
            if (previousRegisterValues) {{
                const previousValue = previousRegisterValues[regId] || 'N/A';
                if (currentValue !== 'N/A' && currentValue !== previousValue) {{
                    valueCell.classList.add('changed');
                }}
            }}
            
            registerTable.appendChild(valueCell);
        }}
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
    document.addEventListener('keydown', (e) => {{
        if (e.key === 'ArrowRight') nextCycle();
        if (e.key === 'ArrowLeft') prevCycle();
    }});

    // Data passed from Python that needs to be available
    const vcd_actual_to_synthetic_pc_map = {vcd_actual_to_synthetic_pc_map_js};

    // Initial display
    updateDisplay();
</script>
</body>
</html>
""".format(
    num_cycles=num_cycles,
    pipeline_data_js=json.dumps(pipeline_data_for_js_serializable),
    instruction_labels_js=json.dumps(instruction_labels_for_js),
    register_data_js=json.dumps(delayed_register_values_by_cycle), # Pass the delayed data
    color_map_js=color_map_js,
    vcd_actual_to_synthetic_pc_map_js=json.dumps(vcd_actual_to_synthetic_pc_map)
)

# --- Write the final HTML file ---
print(f"Writing output to {output_html}")
with open(output_html, "w") as f:
    f.write(html_content)

print(f"✅ Successfully generated '{output_html}'. Open this file in your web browser to view the animation.")
webbrowser.open_new_tab(output_html)