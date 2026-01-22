import argparse
import json
import os
import re
import webbrowser
from collections import defaultdict
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32
from vcdvcd import VCDVCD
import struct
import difflib 



try:
    import yaml  # pip install pyyaml  (only if you want YAML)
except Exception:
    yaml = None

def _is_yaml(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in {".yml", ".yaml"}

def load_signal_map(config_path: str) -> dict:
    """Load a JSON or YAML signal map and expand templates."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        if _is_yaml(config_path):
            if yaml is None:
                raise RuntimeError("YAML config requested but PyYAML is not installed.")
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Signal map must be an object/dict at the top level.")
    return expand_templates_in_signal_map(data)

def expand_templates_in_signal_map(signal_map: dict) -> dict:
    """Expand REG_TEMPLATE → REG_0..REG_31. Accept str or list for candidates."""
    out = dict(signal_map)  # shallow copy
    # Expand register template
    if "REG_TEMPLATE" in out:
        templ = out.pop("REG_TEMPLATE")
        for i in range(32):
            key = f"REG_{i}"
            if isinstance(templ, list):
                out[key] = [s.replace("{i}", str(i)) for s in templ]
            else:
                out[key] = [str(templ).replace("{i}", str(i))]
    return out

# --- Initial Setup ---
md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
md.detail = True
missing_signals_by_label = {}
runtime_warnings = []

# --- New Function to list all signals ---
def list_all_signals(vcd):
    print("\n--- VCD Signals Found ---")
    try:
        signals = list(vcd.signals)   
    except AttributeError:
        
        signals = list(vcd.data.keys())
    
    if not signals:
        print("No signals found in the VCD file.")
        return
    
    for name in sorted(signals):
        print(name)
    print(f"-------------------------\nTotal signals: {len(signals)}\n")


# --- Utility Functions (largely unchanged) ---
def resolve_signal(signal_names, vcd):
    """Find the first available signal name from a list of candidates."""
    if isinstance(signal_names, str):
        signal_names = [signal_names]
    for name in signal_names:
        if name in vcd.signals:
            return name
    return None

def resolve_signals_with_log(signal_dict, vcd, label=""):
    """Resolve a dictionary of signals and log the findings with robust suggestions."""
    resolved = {}
    print(f"\n🔎 Looking for {label} signals:")
    found, missing = 0, 0
    all_vcd_signals = list(vcd.signals)

    for key, candidates in signal_dict.items():
        selected = resolve_signal(candidates, vcd)
        resolved[key] = selected
        if selected:
            print(f"✅ {key} -> {selected}")
            found += 1
        else:
            print(f"⚠️ {key} not found in VCD file.")
            
            # --- START: Robust suggestion logic ---
            # Normalize the key by making it lowercase and removing underscores
            key_normalized = key.lower().replace('_', '')
            suggestions = []

            for sig in all_vcd_signals:
                # Get the final part of the signal name (basename) and normalize it
                sig_basename_normalized = sig.split('.')[-1].lower()

                # Check if the normalized key is a substring of the normalized signal basename.
                # This handles 'rd' in 'rdReg' and 'alu_result' matching 'aluResult'.
                if key_normalized in sig_basename_normalized:
                    suggestions.append(sig)

            if suggestions:
                print(f"   🔍 Possible signals found in VCD that resemble '{key}':")
                for s in suggestions[:5]:
                    print(f"       • {s}")
            else:
                print(f"   ℹ️ No similar signals found for '{key}' in VCD.")
            # --- END: Robust suggestion logic ---
            
            missing += 1
    
    print(f"🧾 {label} summary: {found} found, {missing} missing.")
    if missing > 0:
        if label not in missing_signals_by_label:
            missing_signals_by_label[label] = []
        for key, selected in resolved.items():
            if not selected:
                missing_signals_by_label[label].append(key)
    return resolved

def extract_signal_at_cycles(signal_name, vcd, rising_edges, default_val=None, base=10):
    """Sample a signal's value at each rising clock edge."""
    num_cycles = len(rising_edges)
    if not signal_name or signal_name not in vcd.signals:
        return [default_val] * num_cycles
    
    tv_sorted = sorted(vcd[signal_name].tv, key=lambda x: x[0])
    values = []
    last_val = default_val
    tv_idx = 0
    
    for rise_time in rising_edges:
        while tv_idx < len(tv_sorted) and tv_sorted[tv_idx][0] <= rise_time:
            raw_val = tv_sorted[tv_idx][1]
            if 'x' not in raw_val.lower() and 'z' not in raw_val.lower():
                try:
                    if raw_val.startswith('b'):
                        last_val = int(raw_val[1:], 2)
                    else:
                        last_val = int(raw_val, base)
                except (ValueError, TypeError):
                    pass # Keep previous value if parsing fails
            tv_idx += 1
        values.append(last_val)
    return values


def fmt_hex_dec(val, width=8):
    """Format an integer as 0xXXXXXXXX (D) or '—' if None."""
    if val is None:
        return "—"
    return f"0x{val:0{width}x} ({val})"







# --- Main Script Logic ---
def main(vcd, vcd_file_name, output_html, list_only=False): 
    """Main function to process VCD and generate HTML."""
    global missing_signals_by_label, runtime_warnings
    
    # --- Step 1: Welcome & Initial Info ---
    print("\n" + "="*50)
    print(" VCD to HTML Animation Generator")
    print("="*50)
    print(f"📂 VCD File:         {vcd_file_name}")
    print(f"📊 Total Signals:    {len(vcd.signals)}")

    if list_only:
        list_all_signals(vcd)
        return
    
    # --- Step 2: Signal Mapping ---
    print("\n" + "-"*50)
    print(" Step 1: Mapping Signals...")
    print("-" * 50)
    

    # --- Hardcoded Config Path ---
    CONFIG_FILE = "configs/multicycle.json"  # <-- The required config file

    # --- Load Signal Map ---
    try:
        print(f"Attempting to load signal map from: {CONFIG_FILE}")
        core_signals_raw = load_signal_map(CONFIG_FILE)
        print(f"✅ Successfully loaded '{CONFIG_FILE}'")
    except Exception as e:
        print(f"❌ Error: Failed to load the required config file '{CONFIG_FILE}'.")
        print(f"   Reason: {e}")
        print("   Please ensure the file exists and is a valid JSON/YAML.")
        exit(1) # Stop execution if the config file fails to load
    

    core_signals = resolve_signals_with_log(core_signals_raw, vcd, "Core Signals")
    
    # --- Step 3: Clock & Cycle Detection ---
    print("\n" + "-"*50)
    print(" Step 2: Analyzing Clock Cycles...")
    print("-" * 50)
    clock_candidates = [sig for sig in vcd.signals if "clk" in sig.lower() or "clock" in sig.lower()]
    if not clock_candidates:
        raise RuntimeError("No clock signal found.")
    clock_signal = clock_candidates[0]
    
    clock_tv = vcd[clock_signal].tv
    clock_tv_sorted = sorted(clock_tv)
    rising_edges = []
    prev_val = '0'
    for t, val in clock_tv_sorted:
        if prev_val == '0' and val == '1':
            rising_edges.append(t)
        prev_val = val
    num_cycles = len(rising_edges)
    print(f"✅ Found clock signal: {clock_signal}")
    print(f"✅ Detected {num_cycles} clock cycles.")

    # --- Step 4: Data Extraction & Processing ---
    print("\n" + "-"*50)
    print(" Step 3: Extracting data and generating animation...")
    print("-" * 50)

    # --- Extract Data ---
    fsm_stage_vals = extract_signal_at_cycles(core_signals["STAGE"], vcd, rising_edges, base=2)
    pc_vals = extract_signal_at_cycles(core_signals["PC"], vcd, rising_edges, base=2)
    # ... (all other extract_signal_at_cycles calls remain the same) ...
    instr_vals = extract_signal_at_cycles(core_signals["INSTRUCTION"], vcd, rising_edges, base=2)
    rd_addr_vals = extract_signal_at_cycles(core_signals["RD_ADDR"], vcd, rising_edges, base=2)
    alu_result_vals = extract_signal_at_cycles(core_signals["ALU_RESULT"], vcd, rising_edges, base=2)
    wb_data_vals = extract_signal_at_cycles(core_signals["WB_DATA"], vcd, rising_edges, base=2)
    fetched_inst_vals = extract_signal_at_cycles(core_signals["FETCHED_INST"], vcd, rising_edges, base=2)
    rs1_addr_vals = extract_signal_at_cycles(core_signals["DECODED_RS1"], vcd, rising_edges, base=2)
    rs2_addr_vals = extract_signal_at_cycles(core_signals["DECODED_RS2"], vcd, rising_edges, base=2)
    rs1_data_vals = extract_signal_at_cycles(core_signals["DECODED_RS1_DATA"], vcd, rising_edges, base=2)
    rs2_data_vals = extract_signal_at_cycles(core_signals["DECODED_RS2_DATA"], vcd, rising_edges, base=2)
    operand_a_vals = extract_signal_at_cycles(core_signals["OPERAND_A"], vcd, rising_edges, base=2)
    operand_b_vals = extract_signal_at_cycles(core_signals["OPERAND_B"], vcd, rising_edges, base=2)
    opcode_vals = extract_signal_at_cycles(core_signals["OPCODE"], vcd, rising_edges, base=2)
    decoded_rd_vals = extract_signal_at_cycles(core_signals["DECODED_RD"], vcd, rising_edges, base=2)
    funct3_vals = extract_signal_at_cycles(core_signals["FUNCT3"], vcd, rising_edges, base=2)
    funct7_vals = extract_signal_at_cycles(core_signals["FUNCT7"], vcd, rising_edges, base=2)
    imm_sext_vals = extract_signal_at_cycles(core_signals["IMM_SEXT"], vcd, rising_edges, base=2)
    
    active_op_signals = {}
    for key, signal_path in core_signals.items():
        if key.startswith("IS_"):
            op_name = key.replace("IS_", "")
            active_op_signals[op_name] = extract_signal_at_cycles(signal_path, vcd, rising_edges, base=10)

    # ... (the rest of the data processing code, from instr_word_to_info_map down to the end of the `for` loop, remains unchanged) ...
    # 1. Disassemble all unique instructions found
    instr_word_to_info_map = {}
    for i in range(num_cycles):
        if fsm_stage_vals[i] == 0:
            pc = pc_vals[i]
            instr_word = fetched_inst_vals[i]
            if instr_word is not None and instr_word not in instr_word_to_info_map and instr_word != 0:
                instr_hex = f"{instr_word:08x}"
                try:
                    instr_bytes = bytes.fromhex(instr_hex)[::-1]
                    disassembled = list(md.disasm(instr_bytes, pc))
                    asm = f"{disassembled[0].mnemonic} {disassembled[0].op_str}" if disassembled else "(unknown)"
                    instr_word_to_info_map[instr_word] = {"hex": instr_hex, "asm": asm}
                except Exception as e:
                    instr_word_to_info_map[instr_word] = {"hex": instr_hex, "asm": "Disassembly Error"}
    if 0 not in instr_word_to_info_map:
        instr_word_to_info_map[0] = {"hex": "00000000", "asm": "nop"}
    if 19 not in instr_word_to_info_map:
        instr_word_to_info_map[19] = {"hex": "00000013", "asm": "nop"}

    # 2. Extract register file state directly from VCD signals
    print("Extracting register file state...")
    register_data_js = []
    for i in range(num_cycles):
        cycle_regs = {}
        for j in range(32):
            reg_key = f"REG_{j}"
            reg_signal_name = core_signals.get(reg_key)
            if reg_signal_name:
                val_list = extract_signal_at_cycles(reg_signal_name, vcd, [rising_edges[i]], default_val=0, base=2)
                val = val_list[0] if val_list else 0
            else:
                val = 0
            cycle_regs[f"x{j}"] = fmt_hex_dec(val)
        register_data_js.append(cycle_regs)
    print("✅ Data extraction complete.")

    # 3. Prepare final data structure for JavaScript
    multicycle_data_for_js = []
    reg_highlight_data = []
    stage_map = {0: "Fetch", 1: "Decode", 2: "Execute", 3: "Memory", 4: "Writeback"}
    opcodes_that_use_rs2 = {
        0b0110011,  # R-type
        0b0100011,  # S-type
        0b1100011,  # B-type
    }
    active_instr_word = 0
    for i in range(num_cycles):
        current_highlights = {}
        stage_name = stage_map.get(fsm_stage_vals[i], "Unknown")
        current_instr_in_reg = instr_vals[i]
        if current_instr_in_reg is not None:
            active_instr_word = current_instr_in_reg
        word_to_lookup = active_instr_word
        if stage_name == "Fetch":
            newly_fetched_word = fetched_inst_vals[i]
            if newly_fetched_word is not None:
                word_to_lookup = newly_fetched_word
        instr_info = instr_word_to_info_map.get(word_to_lookup, {"hex": "00000000", "asm": "nop"})
        
        description = "" # ... (rest of the description logic)
        if stage_name == "Fetch":
            pc = pc_vals[i]
            inst_val = fetched_inst_vals[i]
            description = f"Fetching instruction from PC 0x{pc:08x}\n"
            if inst_val is not None:
                description += f"  - Instruction word fetched: 0x{inst_val:08x}"
        elif stage_name == "Decode":
            inst = instr_vals[i]
            rs1 = rs1_addr_vals[i]
            rs2 = rs2_addr_vals[i]
            rs1Data = rs1_data_vals[i]
            rs2Data = rs2_data_vals[i]
            rd = decoded_rd_vals[i]
            op = opcode_vals[i]
            f3 = funct3_vals[i]
            f7 = funct7_vals[i]
            imm = imm_sext_vals[i]
            current_highlights["read_rs1"] = rs1
            if op in opcodes_that_use_rs2:
                current_highlights["read_rs2"] = rs2
            description = f"Decoding instruction: 0x{inst:08x}\n"
            if rs1 is not None: description += f"  - rs1: x{rs1}\n"
            if rs2 is not None: description += f"  - rs2: x{rs2}\n"
            if rd is not None: description += f"  - rd: x{rd}\n"
            if op is not None: description += f"  - Opcode: 0b{op:07b}\n"
            if f3 is not None: description += f"  - funct3: 0b{f3:03b}\n"
            if f7 is not None: description += f"  - funct7: 0b{f7:07b}\n"
            if imm is not None: description += f"  - imm_sext: {fmt_hex_dec(imm)}\n"
            if rs1Data is not None: description += f"  - rs1Data: {fmt_hex_dec(rs1Data)}\n"
            if rs2Data is not None: description += f"  - rs2Data: {fmt_hex_dec(rs2Data)}\n\n"
            active_op = "None"
            if i + 1 < num_cycles:
                for op_name, val_list in active_op_signals.items():
                    if val_list[i + 1] == 1:
                        active_op = op_name
                        break
            description += f"Active function control signal: {active_op}"
        elif stage_name == "Execute":
            op_a = operand_a_vals[i]
            op_b = operand_b_vals[i]
            res = alu_result_vals[i + 1] if i + 1 < num_cycles else None
            active_op_name = "UPO"
            for op_name, val_list in active_op_signals.items():
                if val_list[i] == 1:
                    active_op_name = op_name
                    break
            description = f"Executing in ALU.\n  - UPO: {active_op_name}\n"
            if op_a is not None: description += f"  - Operand A: {fmt_hex_dec(op_a)}\n"
            if op_b is not None: description += f"  - Operand B: {fmt_hex_dec(op_b)}\n"
            if res is not None:
                description += f"  - ALU Result: {fmt_hex_dec(res)}"
        elif stage_name == "Memory":
            description = "Memory stage (no operation for this core)."
        elif stage_name == "Writeback":
            rd = rd_addr_vals[i]
            res = wb_data_vals[i]
            current_highlights["write_rd"] = rd
            if rd is not None and rd != 0 and res is not None:
                description = f"Writing ALU result: {fmt_hex_dec(res)} to destination register(rd) x{rd}."
            else:
                description = "Writeback stage (no write to x0)."

        multicycle_data_for_js.append({
            "asm": instr_info['asm'],
            "stage": stage_name,
            "description": description,
        })
        reg_highlight_data.append(current_highlights)

    # --- Step 5: Final Report and HTML Generation ---
    print("\n✅ Animation data prepared. Generating HTML...")
    html_content = create_html(num_cycles, multicycle_data_for_js, register_data_js, reg_highlight_data, missing_signals_by_label)
    
    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    # --- FINAL SUMMARY REPORT ---
    print("\n" + "="*50)
    print(" Generation Complete")
    print("="*50)
    print(f"📄 Output file:      {output_html}")
    
    if any(missing_signals_by_label.values()):
        total_missing = sum(len(v) for v in missing_signals_by_label.values())
        print(f"⚠️  Status:           Completed with {total_missing} missing signal(s).")
        print("   (The animation may be incomplete. Review logs above.)")
    else:
        print(f"✅ Status:           Success! All signals from '{CONFIG_FILE}' were found.")

    if runtime_warnings:
        print("\n" + "-"*50)
        print("   Additional runtime warnings:")
        for w in runtime_warnings:
            print("   - " + w.replace("\n", "\n     "))
    print("="*50)

    webbrowser.open_new_tab(os.path.abspath(output_html))

# <-- REPLACED BLOCK: Entire create_html function is updated -->
def create_html(num_cycles, multicycle_data, register_data, reg_highlight_data, missing_signals):
    """Generates the full HTML content string with embedded data."""
    
    missing_signals_html = ""
    if any(missing_signals.values()):
        missing_signals_html = '<div class="missing-signals-box">'
        missing_signals_html += '<div class="missing-signals-header">⚠️ Missing Signals Detected</div>'
        missing_signals_html += '<p>The visualization may be incomplete. Please check your VCD file for these signals:</p><ul>'
        for category, keys in missing_signals.items():
            if keys:
                for key in keys:
                    missing_signals_html += f"<li><code>{key}</code> (Category: {category})</li>"
        missing_signals_html += "</ul></div>"

    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Multi-Cycle Processor Animation</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; background-color: #f0f2f5; }}
            .container {{ max-width: 1200px; margin: 20px auto; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h2, h3 {{ text-align: center; color: #333; }}
            .controls {{ text-align: center; margin-bottom: 25px; display: flex; justify-content: center; align-items: center; gap: 10px; flex-wrap: wrap; }}
            .controls button {{ padding: 10px 20px; font-size: 16px; cursor: pointer; border: 1px solid #ccc; background-color: #fff; border-radius: 6px; }}
            .controls button:disabled {{ cursor: not-allowed; opacity: 0.5; }}
            #cycleCounter {{ font-size: 18px; font-weight: bold; font-family: monospace; }}
            .main-display {{ display: flex; justify-content: space-between; gap: 40px; align-items: flex-start; }}
            .status-panel {{ flex: 2; }}
            .register-container {{ flex: 1; }}
            .status-box {{ background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
            .status-box h4 {{ margin-top: 0; font-size: 16px; color: #666; }}
            #current-asm {{ font-family: monospace; font-size: 24px; font-weight: bold; color: #000; }}
            #current-stage {{ font-size: 28px; font-weight: bold; padding: 10px; border-radius: 6px; text-align: center; transition: all 0.3s ease; }}
            #details-box {{ white-space: pre-wrap; font-family: monospace; background: #282c34; color: #abb2bf; padding: 15px; border-radius: 6px; min-height: 80px; }}
            .register-grid {{ display: grid; grid-template-columns: 120px 1fr 70px 70px; border: 1px solid #ccc; }}
            .register-grid .grid-cell {{
                height: 25px; /* Give all cells a fixed height */
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .register-grid .register-name-cell {{
                justify-content: flex-start; /* Keep register names left-aligned */
            }}

            .grid-header, .grid-cell {{ padding: 6px; border: 1px solid #eee; text-align: center; font-size: 14px; }}
            .grid-header {{ background-color: #e9ecef; font-weight: bold; }}
            .register-name-cell {{ font-family: monospace; text-align: left !important; padding-left: 10px !important; }}
            .register-value-cell {{ font-family: monospace; white-space: nowrap; }}
            .register-value-cell.changed {{ background-color: #ffd700; transition: background-color 0.1s ease-in; }}
            .missing-signals-box {{ background-color: #fff3cd; border: 1px solid #ffeeba; color: #856404; padding: 15px; border-radius: 6px; margin-bottom: 20px; }}
            .stage-display-container {{                display: flex;
                justify-content: space-between;
                gap: 10px;
            }}
            .stage-box {{
                flex: 1;
                text-align: center;
                padding: 12px 5px;
                border-radius: 6px;
                border: 2px solid #e9ecef;
                background-color: #f8f9fa;
                color: #6c757d;
                font-weight: bold;
                font-size: 16px;
                transition: all 0.3s ease-in-out; /* For smooth animation */
            }}
            .stage-box.active {{
                transform: scale(1.08); /* Make it slightly bigger */
                color: white; /* White text for active state */
                border-width: 3px;
            }}

        </style>
    </head>
    <body>
        <div class="container">
            <h2>Multi-Cycle Processor Animation</h2>
            {missing_signals_html}
            <div class="controls">
                <button id="prevBtn">Previous</button>
                <span id="cycleCounter">Cycle 0 / {num_cycles}</span>
                <button id="nextBtn">Next</button>
                <button id="playPauseBtn">Play</button>
                <button id="restartBtn">Restart</button>
            </div>
            <div class="main-display">
                <div class="status-panel">
                    <div class="status-box">
                        <h4>CURRENT INSTRUCTION</h4>
                        <div id="current-asm">...</div>
                    </div>
                    <div class="status-box">
                        <h4>PROCESSOR STAGES</h4>
                        <div class="stage-display-container">
                            <div id="stage-box-Fetch" class="stage-box">Fetch</div>
                            <div id="stage-box-Decode" class="stage-box">Decode</div>
                            <div id="stage-box-Execute" class="stage-box">Execute</div>
                            <div id="stage-box-Memory" class="stage-box">Memory</div>
                            <div id="stage-box-Writeback" class="stage-box">Writeback</div>
                        </div>
                    </div>
                    <div class="status-box">
                        <h4>PROCESSOR ACTIVITY</h4>
                        <div id="details-box">...</div>
                    </div>
                </div>
                <div class="register-container">
                    <h3>Register File State</h3>
                    <div id="registerTable" class="register-grid"></div>
                </div>
            </div>
        </div>

        <script>
            const multicycleData = {multicycle_data_js};
            const registerData = {register_data_js};
            const regHighlightData = {reg_highlight_data_js};
            const numCycles = {num_cycles};
            const abiNames = ["zero","ra","sp","gp","tp","t0","t1","t2","s0/fp","s1","a0","a1","a2","a3","a4","a5","a6","a7","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11","t3","t4","t5","t6"];
            const stageColors = {{
                "Fetch": "#ffc107", "Decode": "#28a745", "Execute": "#007bff",
                "Memory": "#6f42c1", "Writeback": "#dc3545", "Unknown": "#6c757d"
            }};

            let currentCycle = 0;
            let animationInterval = null;

            function updateDisplay() {{
                const cycleData = multicycleData[currentCycle];

                document.getElementById('cycleCounter').textContent = `Cycle ${{currentCycle}} / ${{numCycles - 1}}`;
                document.getElementById('current-asm').textContent = cycleData.asm;
                document.getElementById('details-box').textContent = cycleData.description;

                // --- START: New Stage Highlighting Logic ---
                // 1. First, remove the 'active' class from all stage boxes to reset them
                document.querySelectorAll('.stage-box').forEach(el => {{
                    el.classList.remove('active');
                    el.style.backgroundColor = ''; // Clear specific colors
                    el.style.borderColor = '';
                }});

                // 2. Then, find the box for the current stage and activate it
                const currentStageName = cycleData.stage;
                const activeStageEl = document.getElementById(`stage-box-${{currentStageName}}`);
                if (activeStageEl) {{
                    activeStageEl.classList.add('active');
                    // Use the colors we already have for a consistent look
                    activeStageEl.style.backgroundColor = stageColors[currentStageName];
                    activeStageEl.style.borderColor = stageColors[currentStageName];
                }}
                // --- END: New Stage Highlighting Logic ---

                updateRegisterTable();

                document.getElementById('prevBtn').disabled = currentCycle === 0;
                document.getElementById('nextBtn').disabled = currentCycle >= numCycles - 1;
            }}
            
            function updateRegisterTable() {{
                const currentRegs = registerData[currentCycle] || {{}};
                const prevRegs = currentCycle > 0 ? registerData[currentCycle - 1] : {{}};
                const highlights = regHighlightData[currentCycle] || {{}};
                const prev_highlights = currentCycle > 0 ? regHighlightData[currentCycle - 1] : {{}};
                

                for (let i = 0; i < 32; i++) {{
                    const valCell = document.getElementById(`reg-val-${{i}}`);
                    const currentVal = currentRegs[`x${{i}}`] || '0x00000000';
                    const prevVal = prevRegs[`x${{i}}`] || '0x00000000';
                    valCell.textContent = currentVal;
                    valCell.textContent = currentVal;
                    if (currentCycle > 0) {{
                        valCell.classList.toggle('changed', currentVal !== prevVal);
                    }} else {{
                        valCell.classList.remove('changed');
                    }}

                    const readCell = document.getElementById(`reg-read-${{i}}`);
                    const writeCell = document.getElementById(`reg-write-${{i}}`);
                    readCell.innerHTML = '';
                    writeCell.innerHTML = '';

                    // Show read indicators for the instruction NOW in the Execute stage
                    if (prev_highlights.read_rs1 === i || prev_highlights.read_rs2 === i) {{
                        readCell.innerHTML = '<span style="color: #007BFF; font-size: 20px;">●</span>';
                    }}

                    // Show write indicator for the instruction NOW in the Writeback stage
                    if (i !== 0 && highlights.write_rd === i) {{
                        writeCell.innerHTML = '<span style="color: #FF4500; font-size: 20px;">●</span>';
                    }}
                }}
            }}

            function populateStaticGrid() {{
                const registerTable = document.getElementById('registerTable');
                registerTable.innerHTML = '<div class="grid-header">Register</div><div class="grid-header">Value (hex / dec)</div><div class="grid-header">Read (EX)</div><div class="grid-header">Write (WB)</div>';

                for (let i = 0; i < 32; i++) {{
                    const nameCell = document.createElement('div');
                    nameCell.className = 'grid-cell register-name-cell';
                    nameCell.textContent = `x${{i}} (${{abiNames[i]}})`;
                    registerTable.appendChild(nameCell);

                    const valueCell = document.createElement('div');
                    valueCell.className = 'grid-cell register-value-cell';
                    valueCell.id = `reg-val-${{i}}`;
                    registerTable.appendChild(valueCell);

                    const readCell = document.createElement('div');
                    readCell.className = 'grid-cell';
                    readCell.id = `reg-read-${{i}}`;
                    registerTable.appendChild(readCell);

                    const writeCell = document.createElement('div');
                    writeCell.className = 'grid-cell';
                    writeCell.id = `reg-write-${{i}}`;
                    registerTable.appendChild(writeCell);
                }}
            }}
            
            function nextCycle() {{ if (currentCycle < numCycles - 1) {{ currentCycle++; updateDisplay(); }} else {{ stopAnimation(); }} }}
            function prevCycle() {{ if (currentCycle > 0) {{ currentCycle--; updateDisplay(); }} }}
            function startAnimation() {{
                if (animationInterval) return;
                document.getElementById('playPauseBtn').textContent = 'Pause';
                animationInterval = setInterval(nextCycle, 500);
            }}
            function stopAnimation() {{
                clearInterval(animationInterval);
                animationInterval = null;
                document.getElementById('playPauseBtn').textContent = 'Play';
            }}
            
            document.addEventListener('DOMContentLoaded', () => {{
                populateStaticGrid();
                updateDisplay();
                document.getElementById('prevBtn').addEventListener('click', prevCycle);
                document.getElementById('nextBtn').addEventListener('click', nextCycle);
                document.getElementById('restartBtn').addEventListener('click', () => {{ stopAnimation(); currentCycle = 0; updateDisplay(); }});
                document.getElementById('playPauseBtn').addEventListener('click', () => animationInterval ? stopAnimation() : startAnimation());
                
                // --- START: CORRECTED KEYBOARD LISTENER ---
                document.addEventListener('keydown', (e) => {{
                    if (e.key === 'ArrowRight') {{
                        nextCycle();
                    }}
                    if (e.key === 'ArrowLeft') {{
                        prevCycle();
                    }}
                }}); // This now has the correct double closing braces '}}'
                // --- END: CORRECTED KEYBOARD LISTENER ---
            }});
        </script>
    </body>
    </html>
    """.format(
        num_cycles=num_cycles - 1,
        multicycle_data_js=json.dumps(multicycle_data),
        register_data_js=json.dumps(register_data),
        reg_highlight_data_js=json.dumps(reg_highlight_data), # <-- MODIFIED: Pass new data
        missing_signals_html=missing_signals_html
    )
    return html_template

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate an HTML animation for a multi-cycle RISC-V processor from a VCD file or list its signals.")
    parser.add_argument("vcd_file", nargs='?', default=None, help="Optional: Path to the VCD file to process.")
    parser.add_argument("-o", "--output", default="multicycle_animation.html", help="Name of the output HTML file.")
    parser.add_argument("-l", "--list-signals", action="store_true", help="Only list all signal names in the VCD file and exit.")
    
    args = parser.parse_args()

    vcd_file = args.vcd_file

    # If no VCD file is provided via command line, ask the user for it.
    if not vcd_file:
        while True:
            vcd_file = input("Enter the name of the VCD file (e.g., dump.vcd): ").strip()
            # Automatically try to add .vcd if missing
            if not vcd_file.lower().endswith(".vcd") and os.path.exists(vcd_file + ".vcd"):
                vcd_file = vcd_file + ".vcd"

            if os.path.exists(vcd_file):
                print(f"✅ Found VCD file: {vcd_file}")
                break
            else:
                print(f"❌ File '{vcd_file}' not found. Please try again.\n")
    else:
        # If a file was provided, check if it exists (and try adding .vcd)
        if not vcd_file.lower().endswith(".vcd") and os.path.exists(vcd_file + ".vcd"):
            vcd_file = vcd_file + ".vcd"

        if not os.path.exists(vcd_file):
            print(f"❌ Error: File '{vcd_file}' not found.")
            exit() # Exit if the file from command line doesn't exist

    # --- Load VCD ---
    print(f"Loading VCD file: {vcd_file}")
    try:
        vcd = VCDVCD(vcd_file, store_tvs=True)
    except Exception as e:
        print(f"❌ Error: Failed to load VCD file '{vcd_file}'. Reason: {e}")
        exit()

    
    


    # Call the main processing function with the loaded vcd object
    main(vcd, vcd_file, args.output, args.list_signals)