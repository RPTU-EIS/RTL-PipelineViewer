import re
from collections import defaultdict
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32

def convert_hex_immediates_to_decimal(disasm: str) -> str:
    def replace_hex(match):
        hex_str = match.group(0)
        value = int(hex_str, 16)
        if value >= 0x800: value -= 0x1000
        return str(value)
    return re.sub(r'0x[0-9a-fA-F]+', replace_hex, disasm)

def process_logic(trace):
    num_cycles = trace["num_cycles"]
    print(f"🧠 Processing logic for {num_cycles} cycles...")

    # --- 1. Setup Disassembler ---
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
    md.detail = True

    # --- 2. Pre-calculation & Alignment ---
    delayed_mem_values_by_cycle = [{} for _ in range(num_cycles)]
    delayed_wb_values_by_cycle = [{} for _ in range(num_cycles)]
    delayed_hazard_data_by_cycle = [{} for _ in range(num_cycles)]
    delayed_ex_values_by_cycle = [{} for _ in range(num_cycles)]
    
    for i in range(1, num_cycles):
        # Map raw trace lists back to dicts for the logic loop
        delayed_mem_values_by_cycle[i] = {k: trace["mem"][k][i-1] for k in trace["mem"]}
        delayed_wb_values_by_cycle[i] = {k: trace["wb"][k][i-1] for k in trace["wb"]}
        delayed_hazard_data_by_cycle[i] = {k: trace["hazard"][k][i-1] for k in trace["hazard"]}
        delayed_ex_values_by_cycle[i] = {k: trace["ex"][k][i-1] for k in trace["ex"]}

    # Control and Stall dictionaries
    stall_values_by_cycle = [{k: trace["stall"][k][i] for k in trace["stall"]} for i in range(num_cycles)]
    
    control_values_by_cycle = [{} for _ in range(num_cycles)]
    for i in range(1, num_cycles):
        control_values_by_cycle[i] = {k: trace["control"][k][i-1] for k in trace["control"]}

    # --- 3. Disassembly & Instruction Mapping ---
    actual_pc_to_instr_hex = {}
    actual_pc_to_disasm = {}
    
    # Gather all PCs seen in any stage
    all_seen_pcs = set()
    for stage in ["IF", "ID", "EX", "MEM", "WB"]:
        all_seen_pcs.update([x for x in trace["stages"][stage] if x is not None])

    # Map PC -> Instruction based on when they appear in ID stage
    if "ID" in trace["instr"]:
        for i, pc in enumerate(trace["stages"]["ID"]):
            inst = trace["instr"]["ID"][i]
            if pc and inst:
                if pc not in actual_pc_to_instr_hex:
                    actual_pc_to_instr_hex[pc] = f"{inst:08x}"
                    try:
                        inst_bytes = inst.to_bytes(4, 'little')
                        disassembled = list(md.disasm(inst_bytes, pc))
                        if disassembled:
                            op = disassembled[0]
                            asm = f"{op.mnemonic} {op.op_str}"
                            actual_pc_to_disasm[pc] = {"asm": convert_hex_immediates_to_decimal(asm)}
                    except:
                        actual_pc_to_disasm[pc] = {"asm": "Invalid"}

    # --- 4. Pipeline Flow Inference (Ghost & Stall Logic) ---
    stage_order_reversed = ["WB", "MEM", "EX", "ID", "IF"]
    cycle_stage_pc = [{s: None for s in stage_order_reversed} for _ in range(num_cycles)]
    forced_flush_mask = defaultdict(lambda: defaultdict(bool))
    
    for i in range(num_cycles):
        curr_stall = stall_values_by_cycle[i]
        curr_ctrl = control_values_by_cycle[i]
        
        for stage in stage_order_reversed:
            # Inputs
            raw_val = trace["stages"][stage][i]
            prev_val = cycle_stage_pc[i-1][stage] if i > 0 else None
            
            # Flags
            is_stalled = (stage in ["IF", "ID"] and curr_stall.get(stage) == 1)
            is_flushed = (curr_ctrl.get(f"flush_{stage.lower()}") == 1)

            upstream = {"ID":"IF", "EX":"ID", "MEM":"EX", "WB":"MEM"}.get(stage)
            
            # Logic
            if is_flushed and i > 0:
                forced_flush_mask[i][stage] = True
                candidate = cycle_stage_pc[i-1][upstream] if upstream else prev_val
                if stage == "IF": candidate = None 
                
                # Ghost Recovery
                if candidate is None:
                    anchor = cycle_stage_pc[i].get("EX") or trace["stages"]["EX"][i]
                    if anchor:
                        if stage == "ID": candidate = anchor + 4
                        if stage == "IF": candidate = anchor + 8
                        if candidate and candidate not in actual_pc_to_disasm:
                            actual_pc_to_disasm[candidate] = {"asm": "FLUSHED (Ghost)"}
                            actual_pc_to_instr_hex[candidate] = "Ghost"
                
                cycle_stage_pc[i][stage] = candidate
            
            elif is_stalled:
                cycle_stage_pc[i][stage] = prev_val if (raw_val == 0 or raw_val is None) else raw_val
            else:
                cycle_stage_pc[i][stage] = raw_val

    # --- 5. Generate Output Data Structures ---
    pipeline_data = defaultdict(lambda: [None] * num_cycles)
    bubble_data = defaultdict(lambda: [None] * num_cycles)
    mem_activity = []
    
    vcd_actual_to_synthetic_pc_map = {pc: pc for pc in sorted(actual_pc_to_disasm.keys()) if pc != 0}

    for idx in range(num_cycles):
        haz = delayed_hazard_data_by_cycle[idx]
        ctrl = control_values_by_cycle[idx]
        fwdA = haz.get("forwardA", 0)
        fwdB = haz.get("forwardB", 0)
        
        hazard_sources = set()
        if fwdA == 1 or fwdB == 1: hazard_sources.add(cycle_stage_pc[idx]["MEM"])
        if fwdA == 2 or fwdB == 2: hazard_sources.add(cycle_stage_pc[idx]["WB"])

        # Bubble Logic
        if idx > 0:
            for pc, hist in bubble_data.items():
                if hist[idx-1] == "EX": hist[idx] = "MEM"
                elif hist[idx-1] == "MEM": hist[idx] = "WB"
            if stall_values_by_cycle[idx-1].get("ID") == 1:
                upstream = cycle_stage_pc[idx].get("ID") or cycle_stage_pc[idx-1].get("ID")
                if upstream in vcd_actual_to_synthetic_pc_map:
                    bubble_data[upstream][idx] = "EX"

        # Stage Loop
        for stage in stage_order_reversed:
            pc = cycle_stage_pc[idx][stage]
            if pc not in vcd_actual_to_synthetic_pc_map: continue
            
            asm_obj = actual_pc_to_disasm.get(pc, {})
            asm_text = asm_obj.get("asm", "Unknown")
            mnemonic = asm_text.split()[0].lower()
            
            # --- RESOURCE INFERENCE ---
            hazard_info = {"forwardA": fwdA, "forwardB": fwdB, "resource_active": []}
            active_resources = []
            
            is_store = any(op in mnemonic for op in ["sw", "sh", "sb"])
            is_load = any(op in mnemonic for op in ["lw", "lh", "lb"])
            
            if stage == "EX":
                mem_chk = delayed_mem_values_by_cycle[idx]
                is_mem_wr = mem_chk.get("wr_en")
                
                if is_load or is_store or is_mem_wr:
                    active_resources.extend(["ALU", "LSU"]) 
                elif any(op in mnemonic for op in ["beq", "bne", "blt", "bge", "jal", "jr"]):
                    active_resources.append("BRU")
                elif any(op in mnemonic for op in ["mul", "div", "rem"]):
                    active_resources.append("MDU")
                elif mnemonic not in ["nop", "flush", "bubble"]:
                    active_resources.append("ALU")
                
                if "beq" in mnemonic or "bne" in mnemonic or "jal" in mnemonic:
                    next_idx = idx + 1 if idx < num_cycles - 1 else idx
                    tgt = control_values_by_cycle[next_idx].get("branch_target")
                    if tgt: hazard_info["branch_target_synth"] = tgt

            elif stage == "MEM":
                if is_load or is_store:
                    active_resources.append("LSU")

            hazard_info["resource_active"] = active_resources
            
            display = stage
            tooltip = f"PC: {pc:x}\n{asm_text}"
            
            is_vis_stalled = False
            if idx > 0 and cycle_stage_pc[idx-1].get(stage) == pc:
                is_vis_stalled = True
                
            for off in [0,1,2]:
                if idx-off >= 0:
                    c = control_values_by_cycle[idx-off]
                    if c.get("flush_if") or c.get("flush_id"):
                        is_vis_stalled = False
            
            is_flushed = (stage=="IF" and (ctrl.get("flush_if") or forced_flush_mask[idx]["IF"])) or \
                         (stage=="ID" and (ctrl.get("flush_id") or forced_flush_mask[idx]["ID"]))

            if is_flushed: is_vis_stalled = False

            pipeline_data[pc][idx] = {
                "stage": stage,
                "display_text": display,
                "tooltip": tooltip,
                "hazard_info": hazard_info,
                "is_stalled": is_vis_stalled,
                "is_flushed": is_flushed,
                "is_hazard_source": (pc in hazard_sources)
            }

    # --- 6. Memory Activity ---
    for idx in range(num_cycles):
        md = delayed_mem_values_by_cycle[idx]
        wr = md.get("wr_en", 0)
        if wr or md.get("addr", 0) != 0: 
            mem_activity.append({
                "cycle": idx,
                "addr": f"0x{md.get('addr',0):08x}",
                "wdata": md.get("wdata", 0),
                "rdata": md.get("rdata", 0),
                "wr_en": wr
            })

    # --- 7. Instruction Labels ---
    instruction_labels = []
    for pc in sorted(vcd_actual_to_synthetic_pc_map.keys()):
        hex_s = actual_pc_to_instr_hex.get(pc, "????????")
        asm_s = actual_pc_to_disasm.get(pc, {}).get("asm", "???")
        instruction_labels.append({
            "id": pc,
            "label": f"PC_0x{pc:08x} | {hex_s} ({asm_s})"
        })

    # --- 8. Register Data (FIXED LOOP) ---
    # The VCD Reader returns a dict of lists { "x0": [val, val...], "x1": [...] }
    # We need to pivot this to { cycle: { "x0": val, "x1": val } }
    reg_display = {}
    for i in range(num_cycles):
        reg_snapshot = {}
        for reg_name, values_list in trace["reg"].items():
            val = values_list[i] if i < len(values_list) else 0
            reg_snapshot[reg_name] = f"0x{val:08x}"
        reg_display[i] = reg_snapshot

    # --- 9. Register Highlight Data ---
    reg_highlights = []
    for i in range(num_cycles):
        h = delayed_hazard_data_by_cycle[i]
        wb = delayed_wb_values_by_cycle[i]
        reg_highlights.append({
            "id_rs1": h.get("rs1_addr"),
            "id_rs2": h.get("rs2_addr"),
            "wb_rd": wb.get("rd")
        })

    return {
        "num_cycles": num_cycles,
        "pipeline_data": pipeline_data,
        "bubble_data": bubble_data,
        "instruction_labels": instruction_labels,
        "register_data": reg_display,
        "reg_highlights": reg_highlights,
        "mem_activity": mem_activity,
        "pc_map": vcd_actual_to_synthetic_pc_map
    }