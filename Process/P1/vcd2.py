# Works
# Problems to write the vcd file



from vcdvcd import VCDVCD
# from vcdvcd.writer import VCDWriter # This line imports VCDWriter from its specific submodule
import pandas as pd
from collections import defaultdict
import os


# --- Configuration ---
# Name of your VCD file
VCD_FILE_NAME = "dump.vcd" 

# --- Load the VCD file ---
vcd = None
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

# Only proceed if VCD was loaded successfully
if vcd:
    # print("\n--- All Full Signal Names Found in VCD (as reported by vcd.signals) ---")
    # print(vcd.signals)
    # print("---------------------------------------------------------------------")

    # Define the stage map with correct FULL HIERARCHICAL names from your VCD header
    stage_map = {
        "IF": "HazardDetectionRV32I.core.pc_if",
        "ID": "HazardDetectionRV32I.core.pc_id",
        "EX": "HazardDetectionRV32I.core.pc_ex",
        "MEM": "HazardDetectionRV32I.core.pc_mem",
        "WB": "HazardDetectionRV32I.core.pc_wb"
    }

    # Instruction timeline - rows will be PC-based
    instruction_timeline_data = defaultdict(dict)

    print("\n--- Processing PC signals from VCD ---")
    for stage, target_full_signal_name in stage_map.items():
        print(f"  - Processing stage '{stage}' for signal: '{target_full_signal_name}'")
        
        try:
            signal_obj = vcd[target_full_signal_name]
            
            # As debugged, signal_obj is a Signal object, and its 'tv' data is an attribute.
            if not hasattr(signal_obj, 'tv'):
                print(f"    DEBUG: Signal object DOES NOT have 'tv' attribute for '{target_full_signal_name}'. Skipping.")
                continue

            signal_tvs = signal_obj.tv
            
            if not signal_tvs:
                print(f"    ℹ️ No time-value pairs found for signal '{target_full_signal_name}'. This stage will not appear for any PC.")
                continue

            signal_tvs = sorted(signal_tvs, key=lambda x: x[0])

            for time_ns, value_hex in signal_tvs:
                try:
                    pc_val = int(value_hex, 16)
                except ValueError:
                    continue 

                pc_str_key = f"PC_0x{pc_val:08x}" 
                instruction_timeline_data[pc_str_key][time_ns] = stage
            print(f"    ✅ Successfully processed '{target_full_signal_name}'. Found {len(signal_tvs)} time-value pairs.")

        except KeyError:
            print(f"    ❌ Full signal name '{target_full_signal_name}' not found in VCD! (KeyError)")
        except Exception as e:
            print(f"    ❌ An unexpected error occurred while processing '{target_full_signal_name}': {e}")
            continue 
    print("--- Finished processing signals ---")

    print("\n--- Building timeline DataFrame ---")
    all_times_ns_raw = sorted({t for inst_data in instruction_timeline_data.values() for t in inst_data})
    all_pcs_keys = sorted(instruction_timeline_data.keys())

    if not all_pcs_keys:
        print("\n⚠️ No PC data found to build timeline. This might be because the specified signals were not found in the VCD or had no value changes.")
        df_timeline = pd.DataFrame(columns=[f"{t}ns" for t in all_times_ns_raw])
    else:
        df_timeline = pd.DataFrame(index=all_pcs_keys, columns=all_times_ns_raw)

        for pc_key in all_pcs_keys:
            for time_ns in all_times_ns_raw:
                df_timeline.loc[pc_key, time_ns] = instruction_timeline_data[pc_key].get(time_ns, "")
    print("✅ DataFrame built.")

    # Convert times from nanoseconds to more readable format for column headers for CSV
    df_timeline_for_csv = df_timeline.copy()
    df_timeline_for_csv.columns = [f"{t}ns" for t in df_timeline_for_csv.columns]

    # Save to CSV
    output_csv_filename = "pipeline_timeline_pc_only.csv"
    df_timeline_for_csv.to_csv(output_csv_filename)
    print(f"\n✅ Saved {output_csv_filename}")

    # Display a snippet (already shows full processing, but for user info)
    print("\n--- Pipeline Timeline Snippet (First 5 rows and 10 columns) ---")
    print(df_timeline_for_csv.iloc[:, :10].head())
    print(f"\nFull timeline saved to '{output_csv_filename}'.")

    # --- Generate new VCD for visualization ---
    output_vcd_filename = "pipeline_trace.vcd"
    print(f"\n--- Generating VCD file for visualization: {output_vcd_filename} ---")

    try:
        # Open the VCD file for writing
        with open(output_vcd_filename, 'w') as f:
            # Create a VCDWriter instance
            # Setting timescale to 1ns as per your VCD header
            # Current time is Thursday, July 17, 2025 at 6:09:15 PM CEST.
            writer = VCDWriter(f, timescale='1ns', date='2025-07-17T18:09:15 CEST', comment='Pipeline trace generated by script')

            # Define the top-level scope for our new signals
            pipeline_scope = writer.scope_module('pipeline_monitor')

            # Define 32-bit register signals for each pipeline stage
            vcd_signals_for_stages = {
                "IF": pipeline_scope.var('pc_if', 'reg', size=32),
                "ID": pipeline_scope.var('pc_id', 'reg', size=32),
                "EX": pipeline_scope.var('pc_ex', 'reg', size=32),
                "MEM": pipeline_scope.var('pc_mem', 'reg', size=32),
                "WB": pipeline_scope.var('pc_wb', 'reg', size=32)
            }
            
            # Keep track of the last PC value written to each stage signal
            # This helps avoid writing redundant changes, making the VCD smaller
            last_written_pcs = {stage: None for stage in stage_map.keys()}

            # Initialize all stage signals to 'x' (unknown/empty) at time 0
            writer.change(vcd_signals_for_stages["IF"], 0, 'x')
            writer.change(vcd_signals_for_stages["ID"], 0, 'x')
            writer.change(vcd_signals_for_stages["EX"], 0, 'x')
            writer.change(vcd_signals_for_stages["MEM"], 0, 'x')
            writer.change(vcd_signals_for_stages["WB"], 0, 'x')

            # Iterate through all unique timestamps in chronological order
            for time_ns in all_times_ns_raw:
                writer.set_time(time_ns)
                
                # Determine current PC in each stage for this timestamp
                current_stage_occupancy = {stage: None for stage in stage_map.keys()}
                for pc_str_key in df_timeline.index:
                    stage_at_this_time = df_timeline.loc[pc_str_key, time_ns]
                    if stage_at_this_time:
                        # Extract integer PC value from 'PC_0x...' string
                        pc_int_val = int(pc_str_key.split('_0x')[1], 16)
                        current_stage_occupancy[stage_at_this_time] = pc_int_val
                
                # Write changes to VCD signals
                for stage_name, current_pc_val in current_stage_occupancy.items():
                    target_vcd_signal = vcd_signals_for_stages[stage_name]
                    
                    if current_pc_val is not None:
                        # Convert PC to a 32-bit hex string for VCD (e.g., '0x00000100')
                        pc_hex_string = f'0x{current_pc_val:08x}'
                        if last_written_pcs[stage_name] != pc_hex_string:
                            writer.change(target_vcd_signal, time_ns, pc_hex_string)
                            last_written_pcs[stage_name] = pc_hex_string
                    else:
                        # If stage is empty, set signal to 'x' (unknown)
                        if last_written_pcs[stage_name] != 'x':
                            writer.change(target_vcd_signal, time_ns, 'x')
                            last_written_pcs[stage_name] = 'x'
        print(f"✅ VCD file '{output_vcd_filename}' generated successfully.")
        print(f"You can now upload '{output_vcd_filename}' to surfer.org or open it with other VCD viewers (e.g., GTKWave) for visualization.")

    except Exception as e:
        print(f"❌ An error occurred during VCD generation: {e}")

else:
    print("\nScript terminated because VCD file could not be loaded.")