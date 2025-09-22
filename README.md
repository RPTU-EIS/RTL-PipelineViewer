======================================
Pipeline Visualization Generator README
======================================

1. Overview
This Python script generates an interactive HTML animation of a RISC-V processor's pipeline activity. It reads a Value Change Dump (VCD) file from a hardware simulation, processes the signal data, and creates a self-contained webpage to visualize the pipeline stages, register states and data hazards for each clock cycle.

The final output is an HTML file that opens automatically in your web browser, allowing you to step through the simulation cycle by cycle.

---------------
2. Requirements & Installation

To run this script, you will need Python 3 and a few external libraries.

### Dependencies:
- **Python 3.x**

- **Required Python Libraries:**
  - `vcdvcd`: To parse the VCD simulation file.
  - `capstone`: A powerful disassembly framework used here for RISC-V instructions.
  - `pandas`: This library is imported in the script, though not actively used in the final version's logic. It's good practice to have it installed if you plan to modify or extend the data processing parts.

### Installation Steps:
You can install all the required libraries using `pip`, Python's package installer. Open your terminal or command prompt and run the following command:

pip install vcdvcd capstone pandas

The other imported modules (`os`, `re`, `json`, `webbrowser`, `collections`) are part of the Python standard library and do not require separate installation.


3. How to Use
---------------
1.  **Place VCD File**: Make sure you have a vcd file named `dump.vcd` in the same directory as the Python script.

2.  **Run the Script**: Open a terminal or command prompt, navigate to the directory containing the script and execute it with the following command:
    
    python riscv_pipeline_visualizer.py // Pipeline Animation with Register State // Task 4 and 5

    python generate_pipeline_matrix.py  (Pipeline Visualization - Matrix) // Task 4 and 5

    multicycle_riscv_visualizer.py  // Task 3
    
    
    The script will print its progress to the console as it loads the VCD, detects cycles and extracts data.
---------------
4.  **View the Output**: Once the script finishes, it will automatically generate a file named `pipeline_animation.html` and open it in your default web browser. You can then use the on-screen buttons (Previous, Next, Play, Restart) to navigate the pipeline animation.
---------------
5. Configuration
------------------
The script is pre-configured for a specific hardware design's signal names. If your VCD file uses different signal paths, you will need to edit the Python script.

All configurable paths are located at the top of the script in these Python dictionaries:
- `stage_signals`
- `instruction_signals`
- `hazard_signals`
- `register_signals`

You can also change the name of the input VCD file by modifying the `VCD_FILE` variable.
