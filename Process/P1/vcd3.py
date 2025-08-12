#csv successfully created
#vdc successfully created
#Problem: the visualitions in surfer is not what we expect

from vcdvcd import VCDVCD
from vcd.writer import VCDWriter
import pandas as pd
from collections import defaultdict

# --- Configuration ---
VCD_FILE_NAME = "dump.vcd"

# --- Load the VCD file ---
try:
    print(f"\nAttempting to load VCD file: {VCD_FILE_NAME}")
    vcd = VCDVCD(VCD_FILE_NAME, store_tvs=True)
    print("✅ VCD file loaded successfully.")
except FileNotFoundError:
    print(f"❌ Error: '{VCD_FILE_NAME}' not found. Please ensure the VCD file is in the same directory.")
    exit()
except Exception as e:
    print(f"❌ An error occurred while loading the VCD file: {e}")
    exit()

# --- Define stages with full signal names ---
stage_map = {
    "IF": "HazardDetectionRV32I.core.pc_if",
    "ID": "HazardDetectionRV32I.core.pc_id",
    "EX": "HazardDetectionRV32I.core.pc_ex",
    "MEM": "HazardDetectionRV32I.core.pc_mem",
    "WB": "HazardDetectionRV32I.core.pc_wb"
}

instruction_timeline_data = defaultdict(dict)

print("\n--- Processing PC signals from VCD ---")
for stage, signal_name in stage_map.items():
    print(f"  - Processing stage '{stage}' for signal: '{signal_name}'")
    try:
        signal_obj = vcd[signal_name]
        signal_tvs = getattr(signal_obj, 'tv', [])
        if not signal_tvs:
            print(f"    ℹ️ No time-value pairs for '{signal_name}'.")
            continue

        for time_ns, value_hex in sorted(signal_tvs, key=lambda x: x[0]):
            try:
                pc_val = int(value_hex, 16)
            except ValueError:
                continue
            pc_key = f"PC_0x{pc_val:08x}"
            instruction_timeline_data[pc_key][time_ns] = stage

        print(f"    ✅ Processed '{signal_name}' ({len(signal_tvs)} changes).")
    except KeyError:
        print(f"    ❌ Signal '{signal_name}' not found.")
    except Exception as e:
        print(f"    ❌ Error processing '{signal_name}': {e}")

print("--- Finished processing signals ---")



# --- Build timeline DataFrame ---
all_times = sorted({t for inst in instruction_timeline_data.values() for t in inst})
all_pcs = sorted(instruction_timeline_data.keys())
if not all_pcs:
    print("\n⚠️ No PC data found. Exiting.")
    exit()

df_timeline = pd.DataFrame(index=all_pcs, columns=all_times)
for pc in all_pcs:
    for t in all_times:
        df_timeline.loc[pc, t] = instruction_timeline_data[pc].get(t, "")

# Save CSV
csv_file = "pipeline_timeline_pc_only.csv"
df_timeline_for_csv = df_timeline.copy()
df_timeline_for_csv.columns = [f"{t}ns" for t in all_times]
df_timeline_for_csv.to_csv(csv_file)
print(f"\n✅ CSV saved as {csv_file}")

# Display a snippet (already shows full processing, but for user info)
print("\n--- Pipeline Timeline Snippet (First 5 rows and 10 columns) ---")
print(df_timeline_for_csv.iloc[:, :10].head())


# --- Generate VCD ---
output_vcd = "pipeline_trace.vcd"
print(f"\n--- Generating VCD file: {output_vcd} ---")

try:
    with open(output_vcd, 'w') as f:
        with VCDWriter(f, timescale='1 ns', date='2025-07-18', comment='Pipeline trace') as writer:
            # Define variables
            vcd_signals = {
                stage: writer.register_var('pipeline_monitor', f'pc_{stage.lower()}', 'wire', size=32)
                for stage in stage_map.keys()
            }

            last_written = {stage: None for stage in stage_map.keys()}

            for t in all_times:
                for stage in stage_map.keys():
                    current_pc = None
                    for pc_key in df_timeline.index:
                        if df_timeline.loc[pc_key, t] == stage:
                            current_pc = int(pc_key.split('_0x')[1], 16)
                            break

                    if current_pc is not None:
                        if last_written[stage] != current_pc:
                            writer.change(vcd_signals[stage], t, current_pc)
                            last_written[stage] = current_pc
                    else:
                        if last_written[stage] != 'x':
                            writer.change(vcd_signals[stage], t, 'x')
                            last_written[stage] = 'x'

    print(f"✅ VCD file '{output_vcd}' generated successfully.")
except Exception as e:
    print(f"❌ Error during VCD generation: {e}")
