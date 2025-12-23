from vcdvcd import VCDVCD
from collections import defaultdict

missing_signals_by_label = {}

def resolve_signal(signal_names, vcd):
    if signal_names is None: return None
    if isinstance(signal_names, str): signal_names = [signal_names]
    for name in signal_names:
        if name in vcd.signals: return name
    return None

def resolve_signals_with_log(signal_dict, vcd, label="", vcd_filename="(unknown)"):
    resolved = {}
    print(f"\n🔎 Looking for {label} signals:")
    found, missing = 0, 0
    
    for key, candidates in signal_dict.items():
        selected = resolve_signal(candidates, vcd)
        resolved[key] = selected
        if selected:
            print(f"✅ {key} → {selected}")
            found += 1
        else:
            print(f"⚠️ {key} not found in VCD file.")
            missing += 1

    if label not in missing_signals_by_label:
        missing_signals_by_label[label] = []
    for key, selected in resolved.items():
        if not selected:
            missing_signals_by_label[label].append(key)
    return resolved

def extract_trace(vcd_path, all_signals_raw):
    print(f"📂 Loading VCD: {vcd_path}...")
    vcd = VCDVCD(vcd_path, store_tvs=True)
    
    # 1. Clock & Cycles
    candidates = [sig for sig in vcd.signals if "clk" in sig.lower() or "clock" in sig.lower()]
    if not candidates: raise RuntimeError("No clock signal found.")
    clock_signal = candidates[0]
    
    clock_tv = vcd[clock_signal].tv
    rising_edges = []
    prev_val = '0'
    for t, val in sorted(clock_tv, key=lambda x: x[0]):
        if prev_val == '0' and val == '1': rising_edges.append(t)
        prev_val = val
    num_cycles = len(rising_edges)
    print(f"Detected {num_cycles} clock cycles.")

    # 2. Organize Signal Maps
    def to_camel(name):
        parts = name.lower().split('_')
        return parts[0] + ''.join(p.capitalize() for p in parts[1:])

    stage_map = {k.replace("STAGE_", ""): v for k, v in all_signals_raw.items() if k.startswith("STAGE_")}
    instr_map = {k.replace("INSTR_", ""): v for k, v in all_signals_raw.items() if k.startswith("INSTR_")}
    stall_map = {k.replace("STALL_", ""): v for k, v in all_signals_raw.items() if k.startswith("STALL_")}
    control_map = {
        "branch_taken": all_signals_raw.get("BRANCH_TAKEN"),
        "branch_target": all_signals_raw.get("BRANCH_TARGET"),
        "flush_if": all_signals_raw.get("FLUSH_IF"),
        "flush_id": all_signals_raw.get("FLUSH_ID")
    }
    ex_map = {to_camel(k.replace("EX_", "")): v for k, v in all_signals_raw.items() if k.startswith("EX_")}
    mem_map = {to_camel(k.replace("MEM_", "")): v for k, v in all_signals_raw.items() if k.startswith("MEM_")}
    wb_map = {k.replace("WB_", "").lower(): v for k, v in all_signals_raw.items() if k.startswith("WB_")}
    
    hazard_map = {}
    for k, v in all_signals_raw.items():
        if k.startswith("HAZARD_"):
            name = k.replace("HAZARD_", "")
            hazard_map[to_camel(name) if "FORWARD" in name else name.lower()] = v
            
    reg_map = {k: v for k, v in all_signals_raw.items() if k.startswith("x")}

    # 3. Resolve
    stage_signals = resolve_signals_with_log(stage_map, vcd, "Stage", vcd_path)
    instr_signals = resolve_signals_with_log(instr_map, vcd, "Instruction", vcd_path)
    ex_signals = resolve_signals_with_log(ex_map, vcd, "EX", vcd_path)
    mem_signals = resolve_signals_with_log(mem_map, vcd, "MEM", vcd_path)
    stall_signals = resolve_signals_with_log(stall_map, vcd, "Stall", vcd_path)
    control_signals = resolve_signals_with_log(control_map, vcd, "Control", vcd_path)
    wb_signals = resolve_signals_with_log(wb_map, vcd, "WB", vcd_path)
    hazard_signals = resolve_signals_with_log(hazard_map, vcd, "Hazard", vcd_path)
    reg_signals = resolve_signals_with_log(reg_map, vcd, "Register", vcd_path)

    # 4. Extraction Helper
    def extract_group(signal_dict, default_val=0, base=2, postprocess=None):
        data = [{} for _ in range(num_cycles)]
        for key, sig_name in signal_dict.items():
            if not sig_name:
                for c in range(num_cycles): data[c][key] = default_val
                continue
            
            # Extract
            tv_sorted = sorted(vcd[sig_name].tv, key=lambda x: x[0])
            tv_idx = 0
            last_val = None
            
            for i, rise_time in enumerate(rising_edges):
                while tv_idx < len(tv_sorted) and tv_sorted[tv_idx][0] <= rise_time:
                    last_val = tv_sorted[tv_idx][1]
                    tv_idx += 1
                
                val = default_val
                if last_val and 'x' not in str(last_val).lower():
                    try:
                        if isinstance(last_val, int): val = last_val
                        elif str(last_val).startswith('b'): val = int(last_val[1:], 2)
                        elif str(last_val).startswith('h'): val = int(last_val[1:], 16)
                        else: val = int(last_val, base)
                    except: pass
                
                if postprocess: val = postprocess(val)
                data[i][key] = val
        return data

    # 5. Extract Data
    def hex_fmt(v): return f"0x{v:08x}" if isinstance(v, int) else '0x00000000'

    raw_data = {
        "num_cycles": num_cycles,
        "signals": {
            "stage_pcs": extract_group(stage_signals, None, 2),
            "stage_instrs": extract_group(instr_signals, 0, 2),
            "ex": extract_group(ex_signals, None, 2),
            "mem": extract_group(mem_signals, None, 2),
            "wb": extract_group(wb_signals, None, 2),
            "hazard": extract_group(hazard_signals, 0, 2),
            "stall": extract_group(stall_signals, 0, 2),
            "control": extract_group(control_signals, 0, 2),
            "reg": extract_group(reg_signals, 0, 16, hex_fmt)
        },
        "resolved_maps": {
            "stage": stage_signals,
            "instr": instr_signals
        },
        "vcd_obj": vcd, # Needed for raw binary extraction of instructions
        "rising_edges": rising_edges,
        "missing_report": missing_signals_by_label
    }
    
    return raw_data