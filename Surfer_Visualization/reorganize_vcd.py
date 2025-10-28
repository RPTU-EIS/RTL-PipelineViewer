# reorganize_vcd.py (Final Version with Special ID Case)

import argparse
import yaml
import sys
import string # Added for ID generation
from typing import Dict, Any, Set

# --- START: Added for String Signal Generation ---
# Mapping from numeric UOP values to mnemonics
UOP_MAPPING = {
    0x01: "ADD",    0x02: "SUB",    0x03: "XOR",
    0x04: "OR",     0x05: "AND",    0x06: "SLL",
    0x07: "SRL",    0x08: "SRA",    0x09: "SLT",
    0x0A: "SLTU",   0x10: "ADDI",   0xFF: "INVALID"
    # Add other mappings if needed from your Chisel Enum
}

DEFAULT_STRING = "?" # Default string if value is not in mapping

def string_to_vcd_binary(text: str, num_chars: int) -> str:
    """Converts a string to its VCD binary ASCII representation."""
    padded_text = text.ljust(num_chars) # Pad with spaces if needed
    binary_string = ""
    for char in padded_text[:num_chars]: # Truncate if too long
        # Get ASCII value and format as 8-bit binary string
        binary_string += format(ord(char), '08b')
    return 'b' + binary_string

# --- UPDATED generate_unique_id FUNCTION ---
def generate_unique_id(existing_ids: Set[str], base_id: str) -> str:
    """Generates a unique VCD ID, avoiding problematic characters."""
    # Sanitize base_id
    safe_base = ""
    for char in base_id:
        # Allow letters, numbers, and underscore. Replace others with underscore.
        if char.isalnum() or char == '_':
            safe_base += char
        else:
            safe_base += '_'
    safe_base = safe_base.strip('_')
    if not safe_base:
        safe_base = 'derived'

    # Try simple prefix
    prefix = 'S_'
    new_id = prefix + safe_base
    new_id = "".join(c for c in new_id if '!' <= c <= '~') # Final VCD check

    if new_id and len(new_id) > 0 and new_id not in existing_ids:
        return new_id

    # If simple prefix is taken, add a counter
    count = 0
    while True:
        new_id = f"S{count}_{safe_base}"
        new_id = "".join(c for c in new_id if '!' <= c <= '~')
        if new_id and len(new_id) > 0 and new_id not in existing_ids:
             return new_id
        count += 1
        if count > 1000:
             raise ValueError(f"Could not generate a unique VCD ID based on '{base_id}' -> '{safe_base}'")
# --- END: Added for String Signal Generation ---


def parse_vcd_header(input_vcd_path: str) -> tuple[Dict[str, Dict[str, Any]], str]:
    """Parses the header to map full signal paths to their details and get the timescale."""
    signals = {}
    timescale_val = "1ns"
    scope_stack = []
    try:
        # Use encoding='utf-8' for broader compatibility
        with open(input_vcd_path, 'r', encoding='utf-8') as f:
            for line in f:
                # Strip leading/trailing whitespace and handle potential BOM
                stripped = line.strip().lstrip('\ufeff')
                if not stripped: continue
                if stripped.startswith('$timescale'):
                    parts = stripped.replace('$end', '').split()
                    if len(parts) > 1:
                        timescale_val = " ".join(parts[1:]).strip()
                    continue
                if stripped.startswith('$scope'):
                    parts = stripped.split()
                    if len(parts) >= 3:
                        scope_stack.append(parts[2])
                    continue
                if stripped.startswith('$upscope'):
                    if scope_stack: scope_stack.pop()
                    continue
                if stripped.startswith('$var'):
                    parts = stripped.split()
                    if len(parts) >= 5:
                        # VCD standard: $var type width id name $end
                        name_part = parts[4]
                        idx = 5
                        while idx < len(parts) and parts[idx] != '$end':
                             if parts[idx].startswith('[') and parts[idx].endswith(']'):
                                 # We ignore range for path matching for simplicity
                                 pass
                             break # Assume first part after ID is the name
                        full_path = ".".join(scope_stack + [name_part])
                        signals[full_path] = {'type': parts[1], 'width': parts[2], 'id': parts[3]}
                    continue
                if stripped.startswith('$enddefinitions'):
                    break
    except FileNotFoundError:
        print(f"❌ Error: Input VCD file not found at '{input_vcd_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"❌ An error occurred during VCD header parsing: {e}")
        sys.exit(1)
    return signals, timescale_val


def parse_vcd_initial_values(input_vcd_path: str, vcd_signals: Dict[str, Any]) -> Dict[str, str]:
    """Parses $dumpvars, returning {id: full_line_string} including derived signals."""
    initial_values = {}
    source_id_to_derived_config = {}

    derived_configs = vcd_signals.get('_derived_strings_config', [])
    for config in derived_configs:
        source_id = config.get('source_id')
        if source_id:
            if source_id not in source_id_to_derived_config:
                source_id_to_derived_config[source_id] = []
            source_id_to_derived_config[source_id].append(config)

    try:
        with open(input_vcd_path, 'r', encoding='utf-8') as f:
            in_header = True
            in_dumpvars = False
            for line in f:
                stripped = line.strip().lstrip('\ufeff')
                if not stripped: continue
                if in_header and stripped.startswith('$enddefinitions'):
                    in_header = False; continue
                if in_header: continue
                if stripped.startswith('$dumpvars'):
                    in_dumpvars = True; continue
                if stripped.startswith('$end') and in_dumpvars: break

                if in_dumpvars:
                    identifier = ""
                    value_str = ""
                    # Robust dumpvars parsing (might have space)
                    parts = stripped.split(' ', 1)
                    if len(parts) >= 1: value_str = parts[0]
                    if len(parts) == 2: identifier = parts[1].strip()
                    elif len(stripped) >= 1 and not value_str.startswith(('b','r','R')): # Scalar without space? Unlikely in dumpvars but check
                        value_str = stripped[0]
                        identifier = stripped[1:].strip()
                    else: continue

                    if not identifier: continue

                    initial_values[identifier] = line.strip() + '\n' # Store original line

                    # Generate initial value for derived string
                    if identifier in source_id_to_derived_config:
                        try:
                            numeric_val = -1
                            if value_str.startswith('b'):
                                numeric_val = int(value_str[1:], 2)
                            elif value_str in '01':
                                numeric_val = int(value_str)

                            mnemonic = UOP_MAPPING.get(numeric_val, DEFAULT_STRING)

                            for derived_config in source_id_to_derived_config[identifier]:
                                num_chars = derived_config['string_width_chars']
                                derived_id = derived_config['derived_id']
                                derived_vcd_val = string_to_vcd_binary(mnemonic, num_chars)
                                initial_values[derived_id] = f"{derived_vcd_val} {derived_id}\n"
                        except ValueError:
                             print(f"⚠️ Warning: Could not parse initial value '{value_str}' for signal ID {identifier} as number.")
                        except Exception as e:
                             print(f"⚠️ Warning: Error processing initial value for derived signal from ID {identifier}: {e}")

    except Exception as e:
        print(f"❌ Error parsing initial values: {e}")
        sys.exit(1)
    return initial_values


def process_groups_recursive(out_f, groups, vcd_signals, included_ids, derived_strings_map):
    """
    Recursively processes groups and subgroups to write the VCD header,
    including derived string signals.
    """
    if not groups: return

    for group in groups:
        group_name = group.get('name', 'Unnamed_Group')
        group_name = "".join(c for c in group_name if c in string.printable and not c.isspace() and c not in '[]{}()')
        if not group_name: group_name = 'Unnamed_Group'
        out_f.write(f"$scope module {group_name} $end\n")

        if 'signals' in group and group['signals']:
            for sig_spec in group['signals']:
                path, name = sig_spec.get('path'), sig_spec.get('name')
                if path and name and path in vcd_signals:
                    info = vcd_signals[path]
                    sanitized_name = name
                    sanitized_name = "".join(c for c in sanitized_name if c in string.printable and not c.isspace() and c not in '[]{}()')
                    if not sanitized_name: sanitized_name = f'signal_{info["id"]}'

                    out_f.write(f"  $var {info['type']} {info['width']} {info['id']} {sanitized_name} $end\n")
                    included_ids.add(info['id'])

                    # Add derived string signal here if source is in this group
                    if path in derived_strings_map:
                        for derived_config in derived_strings_map[path]:
                             num_chars = derived_config['string_width_chars']
                             derived_name = derived_config['new_signal_name']
                             derived_name = "".join(c for c in derived_name if c in string.printable and not c.isspace() and c not in '[]{}()')
                             if not derived_name: derived_name = f'string_{derived_config["derived_id"]}'

                             derived_id = derived_config['derived_id']
                             width_bits = num_chars * 8
                             out_f.write(f"  $var wire {width_bits} {derived_id} {derived_name} $end\n")
                             included_ids.add(derived_id)

        if 'subgroups' in group and group['subgroups']:
            process_groups_recursive(out_f, group['subgroups'], vcd_signals, included_ids, derived_strings_map)

        out_f.write("$upscope $end\n")





def generate_new_vcd(
    output_path: str,
    input_path: str,
    config: Dict[str, Any],
    vcd_signals: Dict[str, Any],
    timescale_val: str,
    initial_values: Dict[str, str]
) -> None:
    """ Generates VCD including derived string signals, correctly parsing the data section. """
    included_ids: Set[str] = set()
    derived_strings_map = vcd_signals.get('_derived_strings_map', {})
    source_id_to_derived = {}

    print("DEBUG: Included signal IDs:")
    for sig in included_ids:
        print(sig)

    if derived_strings_map:
        for source_path, configs in derived_strings_map.items():
            if source_path in vcd_signals:
                source_id = vcd_signals[source_path]['id']
                source_id_to_derived[source_id] = configs

    try:
        with open(output_path, 'w', encoding='utf-8') as out_f:
            # 1. Write header
            out_f.write(f"$timescale {timescale_val} $end\n")
            if 'groups' in config and config['groups']:
                process_groups_recursive(out_f, config['groups'], vcd_signals, included_ids, derived_strings_map)
            out_f.write("$enddefinitions $end\n")

            # 2. Write filtered $dumpvars
            out_f.write("$dumpvars\n")
            for identifier in included_ids:
                if identifier in initial_values:
                    out_f.write(initial_values[identifier].strip() + '\n')
            out_f.write("$end\n")

            # 3. Filter/Generate main data section
            current_signal_values_numeric = {}
            for id, line in initial_values.items():
                try:
                    stripped_init = line.strip()
                    val_str_init = ""
                    parts_init = stripped_init.split(' ', 1)
                    if len(parts_init) >= 1: val_str_init = parts_init[0]

                    if val_str_init.startswith('b'):
                        current_signal_values_numeric[id] = int(val_str_init[1:], 2)
                    elif val_str_init in '01':
                        current_signal_values_numeric[id] = int(val_str_init)
                    else: current_signal_values_numeric[id] = -1
                except: current_signal_values_numeric[id] = -1

            last_timestamp = ""

            with open(input_path, 'r', encoding='utf-8') as in_f:
                past_dumpvars_end = False
                in_dumpvars_block = False
                for line in in_f: # Use in_f here
                    stripped = line.strip().lstrip('\ufeff')
                    if not past_dumpvars_end:
                        if stripped.startswith('$dumpvars'):
                            in_dumpvars_block = True
                            continue
                        # detect the end of dumpvars (looser condition)
                        if in_dumpvars_block and stripped.startswith('$end'):
                            past_dumpvars_end = True
                            continue
                        # skip everything until we finish dumpvars
                        if in_dumpvars_block:
                            continue

                    if stripped.startswith('#'):
                        last_timestamp = line
                        out_f.write(line)
                        continue

                    if not stripped:
                        continue
                    if stripped.startswith('$') and not stripped.startswith('#'):
                        # Keep timestamp and value lines, skip other commands
                        continue

                    identifier = ""
                    value_str = ""
                    try:
                        # --- ROBUST PARSING for data section (ValueIdentifier) ---
                        if stripped[0] in ['b', 'r', 'R']:
                            # Vector assignment: b1010 id
                            parts = stripped.split(' ', 1)
                            if len(parts) == 2:
                                value_str, identifier = parts
                            else:
                                continue
                        else:
                            # Scalar assignment: 0id or 1id (e.g., 1," for clock)
                            value_str = stripped[0]
                            identifier = stripped[1:].strip()

                        # Validate
                        if not identifier:
                            continue
                        # --- END ROBUST PARSING ---
                    except Exception as e:
                        print(f"⚠️ Warning: Error parsing data line, skipped: {stripped} ({e})")
                        continue


                    # --- Process derived signals ---
                    if identifier in source_id_to_derived:
                        numeric_val = -1
                        try:
                            if value_str.startswith('b'): numeric_val = int(value_str[1:], 2)
                            elif value_str in '01': numeric_val = int(value_str)
                        except ValueError: pass

                        if current_signal_values_numeric.get(identifier) != numeric_val:
                            current_signal_values_numeric[identifier] = numeric_val
                            mnemonic = UOP_MAPPING.get(numeric_val, DEFAULT_STRING)

                            if identifier in included_ids:
                                 out_f.write(line.strip() + '\n') # Write original

                            for derived_config in source_id_to_derived[identifier]:
                                try:
                                    num_chars = derived_config['string_width_chars']
                                    derived_id = derived_config['derived_id']
                                    derived_vcd_val = string_to_vcd_binary(mnemonic, num_chars)
                                    out_f.write(f"{derived_vcd_val} {derived_id}\n") # Write derived
                                except Exception as e_inner:
                                     print(f"⚠️ Warning: Error writing derived signal for ID {derived_id}: {e_inner}")
                        elif identifier in included_ids: pass # Value didn't change

                    # --- Otherwise, write original if included ---
                    elif identifier in included_ids:
                        out_f.write(line.strip() + '\n')

        print(f"✅ Successfully generated reorganized VCD file at '{output_path}'")
    except Exception as e:
        print(f"❌ An error occurred during VCD generation: {e}")
        # import traceback # Uncomment for detailed debug info
        # traceback.print_exc() # Uncomment for detailed debug info
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Reorganize VCD and add derived string signals.")
    parser.add_argument('-c', '--config', required=True, help="Path to the input YAML configuration file.")
    parser.add_argument('-i', '--input', required=True, help="Path to the source VCD file.")
    parser.add_argument('-o', '--output', required=True, help="Path for the generated output VCD file.")
    args = parser.parse_args()

    config_data = {}
    try:
        with open(args.config, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
    except Exception as e:
        print(f"❌ Error reading or parsing YAML file '{args.config}': {e}"); sys.exit(1)

    print("⚙️ Parsing VCD header...")
    vcd_signals, timescale_val = parse_vcd_header(args.input)
    existing_ids = {info['id'] for info in vcd_signals.values()} # Collect existing IDs

    # --- Process derived strings config ---
    derived_strings_map = {}
    derived_strings_config = config_data.get('derived_strings', [])
    vcd_signals['_derived_strings_config'] = derived_strings_config # Pass config for initial values
    vcd_signals['_derived_strings_map'] = derived_strings_map # Pass map for header generation
    print(f"⚙️ Processing {len(derived_strings_config)} derived string configuration(s)...")
    for derived_config in derived_strings_config:
        source_path = derived_config.get('source_path')
        if not source_path or source_path not in vcd_signals:
            print(f"⚠️ Warning: Source path '{source_path}' for derived string not found in VCD. Skipping.")
            continue
        if 'new_signal_name' not in derived_config or 'string_width_chars' not in derived_config:
             print(f"⚠️ Warning: Derived string config for '{source_path}' missing 'new_signal_name' or 'string_width_chars'. Skipping.")
             continue

        source_id = vcd_signals[source_path]['id']
        # --- Use the updated generate_unique_id ---
        derived_id = generate_unique_id(existing_ids, source_id)
        # --- End update ---
        existing_ids.add(derived_id)
        derived_config['derived_id'] = derived_id
        derived_config['source_id'] = source_id

        if source_path not in derived_strings_map:
            derived_strings_map[source_path] = []
        derived_strings_map[source_path].append(derived_config)
        print(f"  -> Will generate '{derived_config['new_signal_name']}' (ID: {derived_id}) from '{source_path}' (ID: {source_id})")

    print("⚙️ Parsing initial values from $dumpvars section...")
    initial_values = parse_vcd_initial_values(args.input, vcd_signals) # Pass vcd_signals

    print("⚙️ Generating new, fully filtered VCD file with derived signals...")
    generate_new_vcd(
        args.output,
        args.input,
        config_data,
        vcd_signals, # Contains derived map info
        timescale_val,
        initial_values # Contains derived initial values
    )

if __name__ == '__main__':
    try:
        import yaml
    except ImportError:
        print("❌ Error: PyYAML is not installed. Please run: pip install pyyaml"); sys.exit(1)
    main()