from collections import defaultdict
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32
import re
import json

def process_trace(trace_data):
    num_cycles = trace_data["num_cycles"]
    sigs = trace_data["signals"]
    vcd = trace_data["vcd_obj"]
    rising_edges = trace_data["rising_edges"]
    
    # --- Disassembler Setup ---
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
    md.detail = True

    def convert_hex_immediates_to_decimal(disasm: str) -> str:
        def replace_hex(match):
            hex_str = match.group(0)
            value = int(hex_str, 16)
            if value >= 0x800: value -= 0x1000
            return str(value)
        return re.sub(r'0x[0-9a-fA-F]+', replace_hex, disasm)

    # --- Delay Logic (Aligning Pipeline Stages) ---
    # We shift everything by 1 cycle relative to fetch to align with the visual pipeline
    delayed_mem = [sigs["mem"][i-1] if i > 0 else {} for i in range(num_cycles)]
    delayed_ex = [sigs["ex"][i-1] if i > 0 else {} for i in range(num_cycles)]
    delayed_wb = [sigs["wb"][i-1] if i > 0 else {} for i in range(num_cycles)]
    delayed_haz = [sigs["hazard"][i-1] if i > 0 else {} for i in range(num_cycles)]
    delayed_reg = [sigs["reg"][i-1] if i > 0 else {f"x{k}": "0x00000000" for k in range(32)} for i in range(num_cycles)]
    stall_vals = [sigs["stall"][i-1] if i > 0 else {} for i in range(num_cycles)]
    ctrl_vals = [sigs["control"][i-1] if i > 0 else {} for i in range(num_cycles)]

    # --- Disassemble All Instructions ---
    actual_pc_to_instr_raw = {}
    actual_pc_to_hex = {}
    actual_pc_to_asm = {}
    
    for stage, pc_sig in trace_data["resolved_maps"]["stage"].items():
        instr_sig = trace_data["resolved_maps"]["instr"].get(stage)
        if not pc_sig or not instr_sig: continue
        
        pc_tv = sorted(vcd[pc_sig].tv, key=lambda x: x[0])
        instr_tv = sorted(vcd[instr_sig].tv, key=lambda x: x[0])
        
        pc_idx, instr_idx = 0, 0
        cur_pc, cur_instr = None, None
        all_times = sorted(list(set([t for t,_ in pc_tv] + [t for t,_ in instr_tv])))
        
        for t in all_times:
            while pc_idx < len(pc_tv) and pc_tv[pc_idx][0] <= t:
                try: cur_pc = int(pc_tv[pc_idx][1], 2)
                except: cur_pc = None
                pc_idx += 1
            while instr_idx < len(instr_tv) and instr_tv[instr_idx][0] <= t:
                cur_instr = instr_tv[instr_idx][1]
                instr_idx += 1
                
            if cur_pc is not None and cur_instr and 'x' not in cur_instr.lower():
                actual_pc_to_instr_raw[cur_pc] = cur_instr
                i_hex = ""
                try:
                    if len(cur_instr) == 32 and all(c in '01' for c in cur_instr):
                        i_hex = f"{int(cur_instr, 2):08x}"
                    elif all(c in '0123456789abcdef' for c in cur_instr.lower()):
                        i_hex = f"{int(cur_instr, 16):08x}"
                except: pass
                actual_pc_to_hex[cur_pc] = i_hex
                if cur_pc not in actual_pc_to_asm and i_hex:
                    try:
                        b = bytes.fromhex(i_hex)[::-1]
                        d = list(md.disasm(b, cur_pc))
                        if d:
                            asm = f"{d[0].mnemonic} {d[0].op_str}"
                            actual_pc_to_asm[cur_pc] = {"asm": convert_hex_immediates_to_decimal(asm)}
                    except:
                        actual_pc_to_asm[cur_pc] = {"asm": "Error"}

    # --- Pipeline Logic (Stalls & Flushes) ---
    raw_stage_pcs = defaultdict(list)
    for stage in ["IF", "ID", "EX", "MEM", "WB"]:
        raw_stage_pcs[stage] = [row.get(stage) for row in sigs["stage_pcs"]]

    cycle_stage_pc = [{s: None for s in ["IF", "ID", "EX", "MEM", "WB"]} for _ in range(num_cycles)]
    forced_flush_mask = defaultdict(lambda: defaultdict(bool))
    stage_order_reversed = ["WB", "MEM", "EX", "ID", "IF"]

    for i in range(num_cycles):
        curr_st = stall_vals[i]
        curr_ct = ctrl_vals[i]
        for stage in stage_order_reversed:
            is_stalled = False
            if stage == "IF" and curr_st.get("IF") == 1: is_stalled = True
            elif stage == "ID" and curr_st.get("ID") == 1: is_stalled = True
            
            is_flushed = (curr_ct.get(f"flush_{stage.lower()}") == 1)
            raw_val = raw_stage_pcs[stage][i]
            prev_val = cycle_stage_pc[i-1][stage] if i > 0 else None
            upstream = {"ID": "IF", "EX": "ID", "MEM": "EX", "WB": "MEM"}.get(stage)
            
            if i == 0:
                cycle_stage_pc[i][stage] = raw_val
                continue

            if is_flushed and i > 0:
                forced_flush_mask[i][stage] = True
                candidate = cycle_stage_pc[i-1][upstream] if upstream else prev_val
                if stage == "IF": candidate = None 
                if candidate is None:
                    anchor = cycle_stage_pc[i].get("EX") or raw_stage_pcs["EX"][i]
                    if anchor and anchor > 0:
                        if stage == "ID": candidate = anchor + 4
                        if stage == "IF": candidate = anchor + 8
                        if candidate and candidate not in actual_pc_to_asm:
                            actual_pc_to_asm[candidate] = {"asm": "Flushed Instruction", "mnemonic": "FLUSH"}
                            actual_pc_to_hex[candidate] = "Ghost"
                cycle_stage_pc[i][stage] = candidate
            elif is_stalled:
                downstream = {"IF":"ID", "ID":"EX", "EX":"MEM", "MEM":"WB"}.get(stage)
                moved = False
                if downstream and prev_val is not None and prev_val == cycle_stage_pc[i][downstream]:
                    moved = True
                
                if moved and upstream: cycle_stage_pc[i][stage] = cycle_stage_pc[i-1][upstream]
                elif raw_val is not None and raw_val != 0: cycle_stage_pc[i][stage] = raw_val
                else: cycle_stage_pc[i][stage] = prev_val
            else:
                cycle_stage_pc[i][stage] = raw_val
            
            if stage == "IF":
                cur_if = cycle_stage_pc[i]["IF"]
                cur_id = cycle_stage_pc[i]["ID"]
                if cur_if is not None and cur_if == cur_id and i < num_cycles - 1:
                    nxt = raw_stage_pcs["IF"][i+1]
                    if nxt and nxt != cur_if: cycle_stage_pc[i]["IF"] = nxt

    # --- Build JS Data ---
    vcd_map = {pc: pc for pc in sorted(actual_pc_to_asm.keys()) if pc != 0}
    pipeline_js = defaultdict(lambda: [None] * num_cycles)
    bubble_js = defaultdict(lambda: [None] * num_cycles)
    instruction_labels = []
    
    for pc in sorted(vcd_map.keys()):
        h = actual_pc_to_hex.get(pc, "N/A")
        a = actual_pc_to_asm.get(pc, {}).get("asm", "N/A")
        if a == "N/A" or h == "00000000": continue
        instruction_labels.append({"id": pc, "label": f"PC_0x{pc:08x} | {h} ({a})"})

    for c in range(num_cycles):
        haz = delayed_haz[c]
        ctrl = ctrl_vals[c]
        fwdA = haz.get("forwardA", 0)
        fwdB = haz.get("forwardB", 0)
        
        sources = set()
        if fwdA == 1 or fwdB == 1: sources.add(cycle_stage_pc[c].get("MEM"))
        if fwdA == 2 or fwdB == 2: sources.add(cycle_stage_pc[c].get("WB"))

        if c > 0:
            for pc, hist in bubble_js.items():
                if hist[c-1] == "EX": hist[c] = "MEM"
                elif hist[c-1] == "MEM": hist[c] = "WB"
            if stall_vals[c-1].get("ID") == 1:
                upstream = cycle_stage_pc[c].get("ID") or cycle_stage_pc[c-1].get("ID")
                if upstream in vcd_map: bubble_js[upstream][c] = "EX"

        for stage in ["IF", "ID", "EX", "MEM", "WB"]:
            pc = cycle_stage_pc[c].get(stage)
            if pc in vcd_map:
                asm = actual_pc_to_asm.get(pc, {}).get("asm", "N/A")
                mnem = asm.split()[0].lower() if asm else ""
                
                # Logic: Stalls, Flushes
                is_stalled = False
                if c > 0:
                    prev = cycle_stage_pc[c-1].get(stage)
                    if prev == pc: 
                        is_stalled = True
                        if stage == "IF" and c < 3 and stall_vals[c].get("IF")==0: is_stalled = False
                        ds = {"IF":"ID", "ID":"EX", "EX":"MEM", "MEM":"WB"}.get(stage)
                        if ds and cycle_stage_pc[c].get(ds) == pc: is_stalled = False
                
                for off in [0,1,2]:
                    if c-off >= 0:
                        cc = ctrl_vals[c-off]
                        if cc.get("flush_if") == 1 or cc.get("flush_id") == 1: is_stalled = False; break
                
                is_flushed = False
                if stage == "IF" and (ctrl.get("flush_if")==1 or forced_flush_mask[c]["IF"]): is_flushed = True
                if stage == "ID" and (ctrl.get("flush_id")==1 or forced_flush_mask[c]["ID"]): is_flushed = True
                if is_flushed: is_stalled = False

                disp = stage
                tt = f"Stage: {stage}\nPC: 0x{pc:08x}\nInstruction: {asm}"
                h_info = {"forwardA": fwdA, "forwardB": fwdB, "source_pc_mem": None, "source_pc_wb": None, "branch_target_synth": None, "resource_active": []}
                
                res_list = []
                is_load_store = any(op in mnem for op in ["lw", "sw", "lb", "sb", "sh", "lh"])
                is_branch = any(op in mnem for op in ["beq", "bne", "blt", "bge", "jal", "jr"])
                is_mul = any(op in mnem for op in ["mul", "div", "rem"])
                
                if stage == "EX":
                    if fwdA == 1 or fwdB == 1: h_info["source_pc_mem"] = cycle_stage_pc[c].get("MEM")
                    if fwdA == 2 or fwdB == 2: h_info["source_pc_wb"] = cycle_stage_pc[c].get("WB")
                    
                    # --- FIX: RESOURCE LOGIC ---
                    if is_load_store: 
                        res_list.append("ALU") # Only ALU active in EX (Address Calc)
                    elif is_branch: 
                        res_list.append("BRU")
                    elif is_mul: 
                        res_list.append("MDU")
                    elif mnem not in ["nop", "flush", "bubble"]: 
                        res_list.append("ALU")
                    
                    # --- FIX: DISPLAY MATH ---
                    op_a = delayed_ex[c].get("operandA")
                    op_b = delayed_ex[c].get("operandB")
                    res = delayed_ex[c].get("aluResult")
                    
                    if is_branch:
                        flushing = (ctrl.get("flush_if")==1 or ctrl.get("flush_id")==1)
                        if flushing:
                            nxt = ctrl_vals[c+1] if c+1 < num_cycles else ctrl
                            tgt = nxt.get("branch_target") or ctrl.get("branch_target") or 0
                            h_info["branch_target_synth"] = tgt
                            disp = f"<strong>Taken</strong><br>⟶ 0x{tgt&0xFFFFFFFF:08x}"
                        else:
                            disp = "<strong>Not Taken</strong>"
                    elif any(op in mnem for op in ["jal", "jalr", "j"]):
                        nxt = ctrl_vals[c+1] if c+1 < num_cycles else ctrl
                        tgt = nxt.get("branch_target") or ctrl.get("branch_target") or res or 0
                        h_info["branch_target_synth"] = tgt
                        disp = f"<strong>Jump</strong><br>⟶ 0x{tgt&0xFFFFFFFF:08x}"
                    elif op_a is not None and op_b is not None:
                        op_map = {"addi": "+", "add": "+", "sub": "-", "and": "&", "or": "|", "xor": "^", "sll": "<<", "srl": ">>"}
                        op_plain = op_map.get(mnem, mnem.upper())
                        
                        # Signed conversion
                        res_s = res if res < 0x80000000 else res - 0x100000000
                        op_a_s = op_a if op_a < 0x80000000 else op_a - 0x100000000
                        op_b_s = op_b if op_b < 0x80000000 else op_b - 0x100000000
                        
                        disp = f"EX<br>{op_a_s} {op_plain} {op_b_s} → {res_s}"
                        tt += f"\n--- ALU ---\n{op_a_s} {op_plain} {op_b_s} = {res_s}"

                elif stage == "MEM":
                    # --- FIX: RESOURCE LOGIC ---
                    if is_load_store: res_list.append("LSU") # LSU active in MEM
                    
                    addr, wdata, rdata = delayed_mem[c].get("addr"), delayed_mem[c].get("wdata"), delayed_mem[c].get("rdata")
                    is_store_op = any(op in mnem for op in ["sw", "sh", "sb"])
                    
                    if is_branch:
                        disp = "---"
                    elif is_store_op: 
                        disp = f"MEM<br>M[{addr}] = {wdata}"
                        tt += f"\n--- Store ---\nAddr: {addr}\nData: {wdata}"
                    elif is_load_store: 
                        rd_val = delayed_haz[c].get("rd_mem_addr")
                        disp = f"MEM<br>Load M[{addr}]"
                        if rd_val: disp += f"<br>x{rd_val} = {rdata}"
                    else: 
                        disp = "—"

                elif stage == "WB":
                    wb_d = delayed_wb[c].get("wb_data") or delayed_wb[c].get("data")
                    wb_r = delayed_wb[c].get("rd") or delayed_wb[c].get("wb_rd")
                    if wb_d is not None and wb_r:
                        disp = f"WB<br>x{wb_r} = {wb_d}"
                    else:
                        h_info["is_skipped"] = True
                        disp = "---"

                h_info["resource_active"] = res_list
                pipeline_js[str(pc)][c] = {
                    "stage": stage, "tooltip": tt, "display_text": disp,
                    "hazard_info": h_info, "is_hazard_source": (pc in sources),
                    "is_stalled": is_stalled, "is_flushed": is_flushed
                }

    # --- Reg Highlight Data ---
    reg_highlight = []
    use_rs2 = {0x33, 0x23, 0x63}
    for c in range(num_cycles):
        h = delayed_haz[c]
        op = h.get("opcode")
        try:
            if isinstance(op, str): op = int(op, 2)
        except: op = None
        reg_highlight.append({
            "id_rs1": h.get("rs1_addr"),
            "id_rs2": h.get("rs2_addr") if op in use_rs2 else None,
            "wb_rd": delayed_wb[c].get("rd")
        })

    # --- Mem Activity ---
    mem_act = []
    for c in range(num_cycles):
        m = delayed_mem[c] if c < len(delayed_mem) else {}
        we = m.get("wrEn")
        try: wr_flag = bool(int(we)) if we is not None else False
        except: wr_flag = bool(we)
        
        mem_act.append({
            "cycle": c,
            "addr": m.get("addr"),
            "wdata": m.get("wdata") if wr_flag else "—",
            "rdata": "—" if wr_flag else m.get("rdata"),
            "wr_en": wr_flag
        })

    return {
        "num_cycles": num_cycles,
        "pipeline_data": pipeline_js,
        "instruction_labels": instruction_labels,
        "register_data": delayed_reg,
        "vcd_map": vcd_map,
        "reg_highlight": reg_highlight,
        "mem_activity": mem_act,
        "bubble_data": bubble_js,
        "missing_report": trace_data["missing_report"]
    }