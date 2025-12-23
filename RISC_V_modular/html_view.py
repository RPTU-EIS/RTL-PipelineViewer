import json

def generate_html(sim_results, missing_signals_html=""):
    
    # 1. Serialize Data for JS
    # Convert pipeline data to dict with string keys for JSON compatibility
    pipeline_serializable = {str(k): v for k, v in sim_results["pipeline_data"].items()}
    
    js_data = {
        "pipeline_data_js": json.dumps(pipeline_serializable),
        "instruction_labels_js": json.dumps(sim_results["instruction_labels"]),
        "register_data_js": json.dumps(sim_results["register_data"]),
        "num_cycles": sim_results["num_cycles"],
        "color_map_js": json.dumps({"IF":"#ff9933","ID":"#5cd65c","EX":"#4b9aefd7","MEM":"#cf66ffb9","WB":"#ff2525c6"}),
        "vcd_actual_to_synthetic_pc_map_js": json.dumps(sim_results["pc_map"]),
        "reg_highlight_data_js": json.dumps(sim_results["reg_highlights"]),
        "mem_activity_js": json.dumps(sim_results["mem_activity"]),
        "bubble_data_js": json.dumps(sim_results["bubble_data"]),
        "missing_signals_html": missing_signals_html
    }

    # 2. The HTML Template (Contains your latest fixes: Double Brackets, Resource Panel, etc.)
    html_template = """
<!DOCTYPE html>
<html><head><title>Pipeline & Register Animation</title>
<style>
body {{ font-family: sans-serif; margin: 20px; background-color: #f9f9f9; }}
h2, h3 {{ text-align: center; color: #333; }}

/* --- Controls & Layout --- */
.controls {{ text-align: center; margin: 20px 0; display: flex; justify-content: center; gap: 10px; flex-wrap: wrap; }}
.controls button {{ padding: 8px 16px; font-size: 14px; cursor: pointer; border: 1px solid #ccc; background: #fff; border-radius: 4px; transition: background 0.2s; }}
.controls button:hover {{ background: #eef; }}
#cycleCounter {{ font-size: 18px; font-weight: bold; margin: 0 15px; align-self: center; }}

.content-wrapper {{ display: flex; justify-content: center; gap: 30px; flex-wrap: wrap; margin-top: 20px; }}

/* --- Resource Timeline (Fixed & Centered) --- */
#resource-panel {{
    margin: 20px auto;
    width: fit-content;
    min-width: 600px; max-width: 98%;
    background-color: #fff; border: 1px solid #ccc;
    box-shadow: 0 2px 5px rgba(0,0,0,0.05); border-radius: 5px;
    display: flex; flex-direction: column; overflow: hidden;
}}
.timeline-scroll-wrapper {{ overflow-x: auto; width: 100%; padding-bottom: 5px; }}
.resource-grid {{ display: grid; gap: 0; background-color: #fff; width: max-content; border-top: 1px solid #ccc; border-collapse: collapse; }}

.resource-row-label {{ 
    position: sticky; left: 0; z-index: 20; 
    background-color: #1e3a8a; color: #fff; padding: 0 8px; 
    font-weight: 600; font-size: 12px; text-align: right; 
    display: flex; align-items: center; justify-content: flex-end;
    border-bottom: 1px solid #4a6fa5; border-right: 1px solid #ccc; height: 26px; box-sizing: border-box;
}}
.grid-header.sticky-corner {{
    position: sticky; left: 0; z-index: 21; background-color: #1e3a8a; color: #fff;
    border: none; font-size: 12px; display: flex; align-items: center; justify-content: center;
    border-right: 1px solid #ccc; height: 26px; box-sizing: border-box;
}}
.resource-cell {{ width: 100%; height: 26px; background-color: #fff; box-sizing: border-box; border-right: 1px solid #eee; border-bottom: 1px solid #eee; }}

.grid-header.timeline-tick {{
    font-size: 11px; font-weight: bold; cursor: pointer; 
    background-color: #1e3a8a; color: white; user-select: none;
    height: 26px; width: 100%; padding: 0; display: flex; align-items: center; justify-content: center;
    border-right: 1px solid #4a6fa5; box-sizing: border-box;
}}
.grid-header.timeline-tick:hover {{ background-color: #3b82f6 !important; }}

/* Resource Colors */
.res-active-ALU {{ background-color: #4b9aef !important; }}
.res-active-LSU {{ background-color: #cf66ff !important; }}
.res-active-BRU {{ background-color: #28a745 !important; }}
.res-active-MDU {{ background-color: #ff9933 !important; }}
.res-active-HAZ {{ background-color: #FF4500 !important; }}
.res-active-FLUSH {{ background-color: #dc3545 !important; }}
.res-active-STALL {{ background-color: #e0e0e0 !important; background-image: repeating-linear-gradient(45deg, transparent, transparent 5px, rgba(0,0,0,0.1) 5px, rgba(0,0,0,0.1) 10px); }}
.current-cycle-column {{ background-color: #fff9c4; border-left: 2px solid #ffc107 !important; border-right: 2px solid #ffc107 !important; z-index: 10; }}

/* --- Pipeline & Register Grids --- */
.pipeline-grid {{ display: grid; border: 1px solid #ccc; width: fit-content; grid-template-columns: 350px repeat(5, 100px); }}
.register-grid {{ display: grid; border: 1px solid #ccc; width: fit-content; grid-template-columns: 100px 180px 80px 80px; }}

.grid-header, .grid-cell {{ padding: 6px; border: 1px solid #eee; text-align: center; white-space: nowrap; font-size: 13px; }}
.grid-header {{ background-color: #ddd; font-weight: bold; }}
.instruction-label {{ text-align: left; font-family: monospace; font-weight: bold; padding-left: 10px; }}

.stage-content {{ 
    width: 90%; height: 90%; border-radius: 4px; margin: auto; 
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    font-size: 11px; color: #333; cursor: help; font-family: monospace;
}}
.stalled-stage {{ border: 2px solid red; background-image: repeating-linear-gradient(45deg, #fff0f0, #fff0f0 10px, #ffe0e0 10px, #ffe0e0 20px); }}
.flushed-stage {{ background-color: #ffcccc !important; text-decoration: line-through; opacity: 0.7; }}
.bubble-stage {{ background-color: #eee !important; border: 2px dashed #bbb; color: #777; font-style: italic; }}

/* Arrow Overlay */
#arrow-svg {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 50; }}

/* Memory Activity Table */
#memActivityTable {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
#memActivityTable th {{ background-color: #1e3a8a; color: white; padding: 8px; }}
#memActivityTable td {{ border: 1px solid #ddd; padding: 6px; text-align: center; }}

</style>
</head>
<body>

<h2>RISC-V Pipeline Visualizer</h2>
{missing_signals_html}

<div class="controls">
    <button id="prevBtn">Previous</button>
    <span id="cycleCounter">Cycle 0</span>
    <button id="nextBtn">Next</button>
    <button id="playPauseBtn">Play</button>
    <button id="toggleResourcesBtn">Hide Resources</button>
    <button id="toggleMemBtn">Show Memory</button>
    <input type="range" id="speedControl" min="100" max="1000" value="500">
</div>

<div id="resource-panel">
    <div style="padding: 10px; background: #f1f1f1; display:flex; justify-content:space-between; border-bottom:1px solid #ddd;">
        <h3 style="margin:0; font-size:14px;">Execution Timeline</h3>
        <div style="font-size:11px; display:flex; gap:10px;">
            <span style="display:flex; align-items:center;"><span style="width:10px;height:10px;background:#4b9aef;margin-right:4px;"></span>ALU</span>
            <span style="display:flex; align-items:center;"><span style="width:10px;height:10px;background:#cf66ff;margin-right:4px;"></span>LSU</span>
            <span style="display:flex; align-items:center;"><span style="width:10px;height:10px;background:#28a745;margin-right:4px;"></span>BRU</span>
            <span style="display:flex; align-items:center;"><span style="width:10px;height:10px;background:#FF4500;margin-right:4px;"></span>Hazard</span>
            <span style="display:flex; align-items:center;"><span style="width:10px;height:10px;background:#e0e0e0;margin-right:4px;"></span>Stall</span>
        </div>
    </div>
    <div class="timeline-scroll-wrapper"><div id="resourceDisplay" class="resource-grid"></div></div>
</div>

<div id="mem-activity-panel" style="display:none; max-width:800px; margin:20px auto;">
    <h3>Memory Activity</h3>
    <table id="memActivityTable">
        <thead><tr><th>Cycle</th><th>Address</th><th>Write Data</th><th>Read Data</th><th>WrEn</th></tr></thead>
        <tbody id="memActivityTbody"></tbody>
    </table>
</div>

<div class="content-wrapper">
    <div class="pipeline-container">
        <h3>Pipeline Stages</h3>
        <div style="position: relative;">
            <div id="pipelineDisplay" class="pipeline-grid"></div>
            <svg id="arrow-svg"></svg>
        </div>
    </div>
    <div class="register-container">
        <h3>Register File</h3>
        <div id="registerTable" class="register-grid">
            <div class="grid-header">Reg</div><div class="grid-header">Val</div><div class="grid-header">Rd</div><div class="grid-header">Wr</div>
        </div>
    </div>
</div>

<script>
    // --- Data Injection ---
    const pipelineData = {pipeline_data_js};
    const instrLabels = {instruction_labels_js};
    const regData = {register_data_js};
    const numCycles = {num_cycles};
    const colorMap = {color_map_js};
    const regHighlights = {reg_highlight_data_js};
    const memActivity = {mem_activity_js};
    const bubbleData = {bubble_data_js};

    // --- State ---
    let currentCycle = 0;
    let isPlaying = false;
    let timer = null;
    let speed = 500;

    // --- UI References ---
    const display = document.getElementById('pipelineDisplay');
    const regTable = document.getElementById('registerTable');
    const arrowSvg = document.getElementById('arrow-svg');
    
    // --- Setup ---
    function init() {{
        // Headers
        ['Instruction', 'IF', 'ID', 'EX', 'MEM', 'WB'].forEach(t => {{
            const d = document.createElement('div'); d.className='grid-header'; d.textContent=t; display.appendChild(d);
        }});
        
        // Pipeline Grid
        instrLabels.forEach(item => {{
            const label = document.createElement('div'); label.className='grid-cell instruction-label';
            label.textContent = item.label; label.id = `label-${{item.id}}`; display.appendChild(label);
            for(let i=0; i<5; i++) {{
                const cell = document.createElement('div'); cell.className='grid-cell'; cell.id = `cell-${{item.id}}-${{i}}`;
                display.appendChild(cell);
            }}
        }});

        // Register Grid
        for(let i=0; i<32; i++) {{
            ['x'+i, '0x0', '', ''].forEach((txt, idx) => {{
                const d = document.createElement('div'); d.className='grid-cell'; 
                if(idx===1) d.id = `reg-val-${{i}}`;
                if(idx===2) d.id = `reg-read-${{i}}`;
                if(idx===3) d.id = `reg-write-${{i}}`;
                d.textContent = idx===0 ? `x${{i}}` : txt;
                regTable.appendChild(d);
            }});
        }}
        
        updateView();
        updateResourceDisplay();
    }}

    function updateView() {{
        document.getElementById('cycleCounter').textContent = `Cycle ${{currentCycle}} / ${{numCycles-1}}`;
        
        // Clear old
        document.querySelectorAll('.stage-content').forEach(e => e.remove());
        
        // Pipeline
        for(const [pc, cycleMap] of Object.entries(pipelineData)) {{
            const data = cycleMap[currentCycle];
            if(data) {{
                const stageIdx = {{'IF':0,'ID':1,'EX':2,'MEM':3,'WB':4}}[data.stage];
                const cell = document.getElementById(`cell-${{pc}}-${{stageIdx}}`);
                if(cell) {{
                    const div = document.createElement('div');
                    div.className = 'stage-content';
                    div.style.backgroundColor = colorMap[data.stage];
                    div.innerHTML = data.display_text;
                    div.id = `content-${{pc}}-${{data.stage}}`; // For arrows
                    if(data.is_stalled) div.classList.add('stalled-stage');
                    if(data.is_flushed) div.classList.add('flushed-stage');
                    cell.appendChild(div);
                }}
            }}
            // Bubbles
            if(bubbleData[pc] && bubbleData[pc][currentCycle]) {{
                const stage = bubbleData[pc][currentCycle];
                const sIdx = {{'IF':0,'ID':1,'EX':2,'MEM':3,'WB':4}}[stage];
                const cell = document.getElementById(`cell-${{pc}}-${{sIdx}}`);
                if(cell) {{
                    const div = document.createElement('div'); div.className='stage-content bubble-stage';
                    div.innerHTML='Bubble'; cell.appendChild(div);
                }}
            }}
        }}

        // Registers
        const curReg = regData[currentCycle] || {{}};
        const hl = regHighlights[currentCycle] || {{}};
        for(let i=0; i<32; i++) {{
            document.getElementById(`reg-val-${{i}}`).textContent = curReg['x'+i] || '0';
            document.getElementById(`reg-read-${{i}}`).textContent = (hl.id_rs1===i || hl.id_rs2===i) ? '●' : '';
            document.getElementById(`reg-write-${{i}}`).textContent = (hl.wb_rd===i && i!==0) ? '●' : '';
        }}

        // Memory Table
        renderMemTable();
        
        // Timeline Highlight
        updateResourceDisplay(); // Re-render grid to update highlight column
        
        // Arrows (Next Tick)
        setTimeout(drawArrows, 0);
    }}

    function drawArrows() {{
        arrowSvg.innerHTML = ''; // Clear
        // Basic Hazard Arrow Logic
        for(const [pc, cycleMap] of Object.entries(pipelineData)) {{
            const data = cycleMap[currentCycle];
            if(data && data.stage === 'EX' && data.hazard_info) {{
                const dest = document.getElementById(`content-${{pc}}-EX`);
                if(!dest) continue;
                
                const h = data.hazard_info;
                // Draw Forwarding Arrows
                if(h.source_pc_mem) drawLine(document.getElementById(`content-${{h.source_pc_mem}}-MEM`), dest, 'red');
                if(h.source_pc_wb) drawLine(document.getElementById(`content-${{h.source_pc_wb}}-WB`), dest, 'red');
                
                // Draw Branch Arrow
                if(h.branch_target_synth) {{
                    const tgt = document.getElementById(`label-${{h.branch_target_synth}}`);
                    if(tgt) drawLine(dest, tgt, 'green');
                }}
            }}
        }}
    }}

    function drawLine(startElem, endElem, color) {{
        if(!startElem || !endElem) return;
        const svgRect = arrowSvg.getBoundingClientRect();
        const r1 = startElem.getBoundingClientRect();
        const r2 = endElem.getBoundingClientRect();
        
        const x1 = r1.left + r1.width/2 - svgRect.left;
        const y1 = r1.top + r1.height/2 - svgRect.top;
        const x2 = r2.left + r2.width/2 - svgRect.left;
        const y2 = r2.top + r2.height/2 - svgRect.top;

        const line = document.createElementNS('http://www.w3.org/2000/svg','path');
        // Simple curve
        const d = `M ${{x1}} ${{y1}} C ${{x1}} ${{y1-30}} ${{x2}} ${{y2-30}} ${{x2}} ${{y2}}`;
        line.setAttribute('d', d);
        line.setAttribute('stroke', color);
        line.setAttribute('fill', 'none');
        line.setAttribute('stroke-width', '2');
        arrowSvg.appendChild(line);
    }}

    function updateResourceDisplay() {{
        const grid = document.getElementById('resourceDisplay');
        const panel = document.getElementById('resource-panel');
        if(panel.style.display === 'none') return;
        
        grid.innerHTML = '';
        const units = ["ALU", "LSU", "BRU", "MDU", "HAZ", "FLUSH", "STALL"];
        grid.style.gridTemplateColumns = `80px repeat(${{numCycles}}, 30px)`;

        // Header
        const corner = document.createElement('div'); corner.className='grid-header sticky-corner'; corner.textContent='Unit'; grid.appendChild(corner);
        for(let c=0; c<numCycles; c++) {{
            const h = document.createElement('div'); h.className='grid-header timeline-tick'; h.textContent=c;
            h.onclick = () => {{ currentCycle=c; updateView(); }};
            if(c === currentCycle) {{ h.style.color='#ffeb3b'; h.style.borderBottom='3px solid #ffeb3b'; }}
            grid.appendChild(h);
        }}

        // Rows
        units.forEach(unit => {{
            const label = document.createElement('div'); label.className='resource-row-label'; label.textContent=unit; grid.appendChild(label);
            for(let c=0; c<numCycles; c++) {{
                const cell = document.createElement('div'); cell.className='resource-cell';
                if(c === currentCycle) cell.classList.add('current-cycle-column');
                
                let active = false;
                // Logic to find activity
                for(const [pc, map] of Object.entries(pipelineData)) {{
                    const d = map[c];
                    if(!d) continue;
                    if(unit==='HAZ' && (d.hazard_info.forwardA || d.hazard_info.forwardB)) active=true;
                    else if(unit==='FLUSH' && d.is_flushed) active=true;
                    else if(unit==='STALL' && d.is_stalled) active=true;
                    else if(d.hazard_info.resource_active && d.hazard_info.resource_active.includes(unit)) active=true;
                }}
                
                if(active) cell.classList.add(`res-active-${{unit}}`);
                grid.appendChild(cell);
            }}
        }});
        
        // Auto Scroll
        setTimeout(() => {{
            const wrap = document.querySelector('.timeline-scroll-wrapper');
            const target = grid.children[currentCycle+1];
            if(wrap && target) {{
                if(target.offsetLeft > wrap.clientWidth/2) wrap.scrollLeft = target.offsetLeft - wrap.clientWidth/2;
            }}
        }}, 10);
    }}

    function renderMemTable() {{
        const tbody = document.getElementById('memActivityTbody');
        tbody.innerHTML = '';
        const m = memActivity[currentCycle];
        if(!m) return; // or show 'no activity'
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${{m.cycle}}</td><td>${{m.addr}}</td><td>${{m.wdata}}</td><td>${{m.rdata}}</td><td>${{m.wr_en}}</td>`;
        tbody.appendChild(tr);
    }}

    // --- Listeners ---
    document.getElementById('nextBtn').onclick = () => {{ if(currentCycle < numCycles-1) currentCycle++; updateView(); }};
    document.getElementById('prevBtn').onclick = () => {{ if(currentCycle > 0) currentCycle--; updateView(); }};
    document.getElementById('toggleResourcesBtn').onclick = function() {{
        const p = document.getElementById('resource-panel');
        const hidden = p.style.display === 'none';
        p.style.display = hidden ? 'flex' : 'none';
        this.textContent = hidden ? 'Hide Resources' : 'Show Resources';
        if(hidden) updateResourceDisplay();
    }};
    document.getElementById('toggleMemBtn').onclick = function() {{
        const p = document.getElementById('mem-activity-panel');
        p.style.display = p.style.display === 'none' ? 'block' : 'none';
    }};
    
    init();
</script>
</body>
</html>
    """
    
    # 3. Inject
    return html_template.format(**js_data)