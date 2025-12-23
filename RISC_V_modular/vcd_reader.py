from vcdvcd import VCDVCD

def resolve_signal(candidates, vcd_obj):
    if not candidates: return None
    if isinstance(candidates, str): candidates = [candidates]
    for name in candidates:
        if name in vcd_obj.signals: return name
    return None

def extract_trace(vcd_path, signal_map):
    print(f"📂 Loading VCD: {vcd_path}...")
    try:
        vcd = VCDVCD(vcd_path, store_tvs=True)
    except FileNotFoundError:
        raise FileNotFoundError(f"VCD file not found: {vcd_path}")

    # 1. Detect Clock
    clock_candidates = [s for s in vcd.signals if "clk" in s.lower() or "clock" in s.lower()]
    if not clock_candidates: raise ValueError("No clock signal found")
    clock_sig = clock_candidates[0]
    
    # 2. Find Rising Edges
    clock_tv = sorted(vcd[clock_sig].tv, key=lambda x: x[0])
    rising_edges = []
    prev = '0'
    for t, val in clock_tv:
        if prev == '0' and val == '1': rising_edges.append(t)
        prev = val
    
    num_cycles = len(rising_edges)
    print(f"📊 Detected {num_cycles} cycles.")

    # 3. Helper to extract data for one signal
    def get_values(sig_keys, default=0):
        sig_name = resolve_signal(signal_map.get(sig_keys), vcd)
        if not sig_name: return [default] * num_cycles
        
        tv = sorted(vcd[sig_name].tv, key=lambda x: x[0])
        values = []
        tv_idx = 0
        last_val = default
        
        for time in rising_edges:
            while tv_idx < len(tv) and tv[tv_idx][0] <= time:
                raw = tv[tv_idx][1]
                # Robust parsing logic
                if isinstance(raw, str) and ('x' in raw.lower() or 'z' in raw.lower()):
                    pass # keep last val
                else:
                    try:
                        if isinstance(raw, int): last_val = raw
                        elif raw.startswith('b'): last_val = int(raw[1:], 2)
                        elif raw.startswith('h'): last_val = int(raw[1:], 16)
                        else: last_val = int(raw, 2)
                    except: pass
                tv_idx += 1
            values.append(last_val)
        return values

    # 4. Extract Everything
    trace_data = {
        "num_cycles": num_cycles,
        "stages": {},
        "instr": {},
        "control": {},
        "stall": {},
        "reg": {},
        "ex": {},
        "mem": {},
        "wb": {},      # <--- Added missing key
        "hazard": {}   # <--- Added missing key
    }

    # Extract PC and Instruction for each stage
    for stage in ["IF", "ID", "EX", "MEM", "WB"]:
        trace_data["stages"][stage] = get_values(f"STAGE_{stage}", 0)
        trace_data["instr"][stage] = get_values(f"INSTR_{stage}", 0)

    # Extract Controls
    trace_data["control"]["flush_if"] = get_values("FLUSH_IF", 0)
    trace_data["control"]["flush_id"] = get_values("FLUSH_ID", 0)
    trace_data["control"]["branch_taken"] = get_values("BRANCH_TAKEN", 0)
    trace_data["control"]["branch_target"] = get_values("BRANCH_TARGET", 0)

    # Extract Stalls
    trace_data["stall"]["IF"] = get_values("STALL_IF", 0)
    trace_data["stall"]["ID"] = get_values("STALL_ID", 0)

    # Extract Regfile (x0-x31)
    for i in range(32):
        trace_data["reg"][f"x{i}"] = get_values(f"x{i}", 0)

    # Extract EX Stage Data
    trace_data["ex"]["alu_result"] = get_values("EX_ALU_RESULT", 0)
    trace_data["ex"]["op_a"] = get_values("EX_OPERAND_A", 0)
    trace_data["ex"]["op_b"] = get_values("EX_OPERAND_B", 0)
    trace_data["ex"]["uop"] = get_values("EX_UOP", 0)

    # Extract MEM Stage Data
    trace_data["mem"]["addr"] = get_values("MEM_ADDR", 0)
    trace_data["mem"]["wdata"] = get_values("MEM_WDATA", 0)
    trace_data["mem"]["rdata"] = get_values("MEM_RDATA", 0)
    trace_data["mem"]["wr_en"] = get_values("MEM_WR_EN", 0)
    trace_data["mem"]["rd_en"] = get_values("MEM_RD_EN", 0)

    # Extract WB Stage Data (FIXED)
    trace_data["wb"]["rd"] = get_values("WB_RD", 0)
    trace_data["wb"]["data"] = get_values("WB_DATA", 0)

    # Extract Hazard Data (FIXED)
    trace_data["hazard"]["forwardA"] = get_values("HAZARD_FORWARD_A", 0)
    trace_data["hazard"]["forwardB"] = get_values("HAZARD_FORWARD_B", 0)
    trace_data["hazard"]["rs1_addr"] = get_values("HAZARD_RS1_ADDR", 0)
    trace_data["hazard"]["rs2_addr"] = get_values("HAZARD_RS2_ADDR", 0)
    trace_data["hazard"]["opcode"] = get_values("HAZARD_OPCODE", 0)
    trace_data["hazard"]["rd_mem_addr"] = get_values("HAZARD_RD_MEM_ADDR", 0)
    
    return trace_data