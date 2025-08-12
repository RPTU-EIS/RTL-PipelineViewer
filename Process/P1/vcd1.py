from vcdvcd import VCDVCD
import pandas as pd
from collections import defaultdict
import os

# --- Configuration ---
# Name of your VCD file (confirmed by user)
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
    print("\n--- All Full Signal Names Found in VCD (as reported by vcd.signals) ---")
    print(vcd.signals)
    print("---------------------------------------------------------------------")

    # Define the stage map with correct FULL HIERARCHICAL names from your VCD header (dump1.txt)
    # These names start with 'HazardDetectionRV32I.core.'
    stage_map = {
        "IF": "HazardDetectionRV32I.core.pc_if",
        "ID": "HazardDetectionRV32I.core.pc_id",
        "EX": "HazardDetectionRV32I.core.pc_ex",
        "MEM": "HazardDetectionRV32I.core.pc_mem",
        "WB": "HazardDetectionRV32I.core.pc_wb"
    }

    # Instruction timeline - rows will be PC-based, as requested ("track only the pc")
    instruction_timeline_data = defaultdict(dict)

    print("\n--- Processing PC signals from VCD ---")
    for stage, target_full_signal_name in stage_map.items():
        print(f"  - Processing stage '{stage}' for signal: '{target_full_signal_name}'")
        
        try:
            # Attempt to get the signal object using direct indexing
            signal_obj = vcd[target_full_signal_name]
            
            # DEBUG: Confirming it's a Signal object and checking its 'tv' attribute
            print(f"    DEBUG: Type of vcd['{target_full_signal_name}']: {type(signal_obj)}")
            if hasattr(signal_obj, 'tv'):
                print(f"    DEBUG: Signal object has 'tv' attribute.")
            else:
                print(f"    DEBUG: Signal object DOES NOT have 'tv' attribute.")
                continue # Skip if no 'tv' attribute is found

            # Correct way to access time-value pairs for a Signal object
            signal_tvs = signal_obj.tv
            
            if not signal_tvs:
                print(f"    ℹ️ No time-value pairs found for signal '{target_full_signal_name}'. This stage will not appear for any PC.")
                continue

            # Sort time-value pairs by time to ensure chronological processing
            signal_tvs = sorted(signal_tvs, key=lambda x: x[0])

            for time_ns, value_hex in signal_tvs:
                try:
                    pc_val = int(value_hex, 16)
                except ValueError:
                    # Handle cases where value might be 'x' (unknown) or malformed hex
                    continue 

                # For now, instructions are identified by their PC hexadecimal value
                pc_str_key = f"PC_0x{pc_val:08x}" 

                # Store the stage at the given time for this PC
                instruction_timeline_data[pc_str_key][time_ns] = stage
            print(f"    ✅ Successfully processed '{target_full_signal_name}'. Found {len(signal_tvs)} time-value pairs.")

        except KeyError:
            print(f"    ❌ Full signal name '{target_full_signal_name}' not found in VCD! (KeyError)")
        except Exception as e:
            # Catching any other unexpected errors during processing a signal
            print(f"    ❌ An unexpected error occurred while processing '{target_full_signal_name}': {e}")
            continue # Continue to the next signal even if one fails
    print("--- Finished processing signals ---")

    print("\n--- Building timeline DataFrame ---")
    all_times_ns = sorted({t for inst_data in instruction_timeline_data.values() for t in inst_data})
    all_pcs_keys = sorted(instruction_timeline_data.keys())

    if not all_pcs_keys:
        print("\n⚠️ No PC data found to build timeline. This might be because the specified signals were not found in the VCD or had no value changes.")
        df_timeline = pd.DataFrame(columns=[f"{t}ns" for t in all_times_ns]) # Create an empty DataFrame
    else:
        df_timeline = pd.DataFrame(index=all_pcs_keys, columns=all_times_ns)

        # Populate the DataFrame
        for pc_key in all_pcs_keys:
            for time_ns in all_times_ns:
                # Get the stage for the current PC at the current time, or an empty string if not present
                df_timeline.loc[pc_key, time_ns] = instruction_timeline_data[pc_key].get(time_ns, "")
    print("✅ DataFrame built.")

    # Convert times from nanoseconds to more readable format for column headers
    df_timeline.columns = [f"{t}ns" for t in df_timeline.columns]

    # Save to CSV
    output_csv_filename = "pipeline_timeline_pc_only.csv"
    df_timeline.to_csv(output_csv_filename)
    print(f"\n✅ Saved {output_csv_filename}")

    # Display a snippet
    print("\n--- Pipeline Timeline Snippet (First 5 rows and 10 columns) ---")
    print(df_timeline.iloc[:, :10].head())
    print(f"\nFull timeline saved to '{output_csv_filename}'.")
else:
    print("\nScript terminated because VCD file could not be loaded.")