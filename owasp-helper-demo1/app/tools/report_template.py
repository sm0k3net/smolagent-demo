"""HTML template for generated reports.

Kept in a separate module so importing `report_tools` stays fast.
"""

REPORT_TEMPLATE_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{title}}</title>
    <style>
        :root {
            --primary: #1e3a5f;
            --primary-light: #2d5a8a;
            --accent: #00b4d8;
            --accent-light: #48cae4;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --danger-dark: #b91c1c;
            --info: #6366f1;
            --neutral-50: #f8fafc;
            --neutral-100: #f1f5f9;
            --neutral-200: #e2e8f0;
            --neutral-300: #cbd5e1;
            --neutral-400: #94a3b8;
            --neutral-500: #64748b;
            --neutral-600: #475569;
            --neutral-700: #334155;
            --neutral-800: #1e293b;
            --neutral-900: #0f172a;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif; 
            line-height: 1.6; 
            color: var(--neutral-800);
            background: var(--neutral-100);
            font-size: 15px;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        
        /* Header */
        .report-header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 50%, var(--accent) 100%);
            color: white;
            padding: 3rem 2.5rem;
            margin-bottom: 2rem;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(30, 58, 95, 0.3);
            position: relative;
            overflow: hidden;
        }
        .report-header::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -20%;
            width: 60%;
            height: 200%;
            background: radial-gradient(ellipse, rgba(255,255,255,0.1) 0%, transparent 70%);
            pointer-events: none;
        }
        .report-header h1 { 
            font-size: 2.25rem; 
            margin-bottom: 0.5rem; 
            font-weight: 700;
            letter-spacing: -0.5px;
        }
        .report-header .subtitle { 
            opacity: 0.9; 
            font-size: 1.1rem;
            font-weight: 500;
        }
        .report-header .meta { 
            margin-top: 1.5rem; 
            font-size: 0.9rem; 
            opacity: 0.85;
            display: flex;
            gap: 2rem;
            flex-wrap: wrap;
        }
        .report-header .meta-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .report-header .meta-icon {
            width: 18px;
            height: 18px;
            opacity: 0.8;
        }
        
        /* Sections */
        .section {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
            border: 1px solid var(--neutral-200);
        }
        .section h2 {
            color: var(--primary);
            font-size: 1.35rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding-bottom: 0.75rem;
            border-bottom: 2px solid var(--neutral-200);
        }
        .section h2 .section-icon {
            width: 28px;
            height: 28px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--accent) 100%);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1rem;
        }
        .section h3 { 
            color: var(--neutral-700); 
            margin: 1.5rem 0 1rem; 
            font-size: 1.1rem;
            font-weight: 600;
        }

        /* Tools Table */
        .tools-table {
            width: 100%;
            border-collapse: collapse;
            border: 1px solid var(--neutral-200);
            border-radius: 10px;
            overflow: hidden;
            background: white;
        }
        .tools-table thead th {
            text-align: left;
            font-size: 0.85rem;
            letter-spacing: 0.3px;
            text-transform: uppercase;
            color: var(--neutral-600);
            background: var(--neutral-50);
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--neutral-200);
        }
        .tools-table td {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--neutral-200);
            vertical-align: top;
        }
        .tools-table tr:last-child td { border-bottom: none; }

        /* Artifacts collapse */
        details.artifact-details {
            border: 1px solid var(--neutral-200);
            border-radius: 10px;
            background: white;
            overflow: hidden;
        }
        details.artifact-details + details.artifact-details { margin-top: 0.75rem; }
        summary.artifact-summary {
            cursor: pointer;
            padding: 0.85rem 1rem;
            font-weight: 600;
            list-style: none;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            background: var(--neutral-50);
            border-bottom: 1px solid var(--neutral-200);
        }
        summary.artifact-summary::-webkit-details-marker { display: none; }
        .artifact-summary-meta {
            font-weight: 500;
            font-size: 0.85rem;
            color: var(--neutral-500);
            white-space: nowrap;
        }
        details.artifact-details .artifact-card { border: none; box-shadow: none; margin: 0; }
        
        /* Executive Summary */
        .executive-summary { 
            background: linear-gradient(135deg, var(--neutral-50) 0%, #f0f9ff 100%);
            border-left: 4px solid var(--accent);
        }
        .exec-summary-content { margin-bottom: 1.5rem; }
        .exec-summary-content p { 
            margin-bottom: 1rem; 
            line-height: 1.8; 
            color: var(--neutral-700);
        }
        
        /* Executive Summary Dashboard */
        .exec-summary-narrative { margin-bottom: 1.5rem; }
        .exec-summary-narrative p { margin-bottom: 0.75rem; line-height: 1.7; color: var(--neutral-700); }
        
        .exec-summary-dashboard { }
        
        .exec-risk-card {
            border-radius: 12px;
            padding: 1rem 1.25rem;
            margin-bottom: 1.5rem;
        }
        .risk-header {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        .risk-icon { font-size: 2rem; }
        .risk-title span { font-size: 1.1rem; display: block; margin-bottom: 0.25rem; }
        .risk-description { font-size: 0.9rem; color: var(--neutral-600); margin: 0; }
        
        .exec-charts-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }
        @media (max-width: 768px) {
            .exec-charts-row { grid-template-columns: 1fr; }
        }
        
        .exec-chart-card {
            background: white;
            border-radius: 12px;
            padding: 1.25rem;
            border: 1px solid var(--neutral-200);
        }
        .exec-chart-card h4 {
            margin: 0 0 1rem 0;
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--neutral-700);
        }
        
        /* Mini Severity Bars */
        .mini-severity-bars { display: flex; flex-direction: column; gap: 0.5rem; }
        .mini-bar-row {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .mini-label {
            width: 60px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .mini-bar-container {
            flex: 1;
            height: 18px;
            background: var(--neutral-100);
            border-radius: 4px;
            overflow: hidden;
        }
        .mini-bar-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.5s ease;
        }
        .mini-count {
            width: 25px;
            text-align: right;
            font-weight: 700;
            font-size: 0.9rem;
            color: var(--neutral-700);
        }
        
        /* Pie Chart */
        .pie-chart-container {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 1.5rem;
        }
        .pie-chart {
            width: 120px;
            height: 120px;
        }
        .pie-legend {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        .pie-legend-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.85rem;
            color: var(--neutral-700);
        }
        .pie-legend-color {
            width: 12px;
            height: 12px;
            border-radius: 3px;
        }
        
        /* Quick Stats */
        .exec-quick-stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
        }
        @media (max-width: 768px) {
            .exec-quick-stats { grid-template-columns: repeat(2, 1fr); }
        }
        .quick-stat {
            text-align: center;
            padding: 1rem;
            border-radius: 10px;
            background: var(--neutral-50);
            border: 1px solid var(--neutral-200);
        }
        .quick-stat.critical-high { background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); border-color: #fecaca; }
        .quick-stat.total { background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%); border-color: #bae6fd; }
        .quick-stat.app { background: linear-gradient(135deg, #f5f3ff 0%, #ede9fe 100%); border-color: #ddd6fe; }
        .quick-stat.network { background: linear-gradient(135deg, #ecfeff 0%, #cffafe 100%); border-color: #a5f3fc; }
        .stat-number {
            display: block;
            font-size: 1.75rem;
            font-weight: 800;
            color: var(--neutral-800);
        }
        .quick-stat.critical-high .stat-number { color: #dc2626; }
        .quick-stat.total .stat-number { color: #0369a1; }
        .quick-stat.app .stat-number { color: #7c3aed; }
        .quick-stat.network .stat-number { color: #0891b2; }
        .stat-label {
            font-size: 0.75rem;
            font-weight: 500;
            color: var(--neutral-500);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        /* Severity Chart */
        .severity-chart-container {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1.5rem 0;
            border: 1px solid var(--neutral-200);
        }
        .severity-chart-title {
            font-size: 1rem;
            font-weight: 600;
            color: var(--neutral-700);
            margin-bottom: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .severity-chart {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }
        .severity-bar {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .severity-label {
            width: 80px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .severity-label.critical { color: var(--danger-dark); }
        .severity-label.high { color: #ea580c; }
        .severity-label.medium { color: var(--warning); }
        .severity-label.low { color: var(--success); }
        .severity-label.info { color: var(--info); }
        .bar-container {
            flex: 1;
            height: 28px;
            background: var(--neutral-100);
            border-radius: 6px;
            overflow: hidden;
            position: relative;
        }
        .bar-fill {
            height: 100%;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 0.75rem;
            color: white;
            font-weight: 700;
            font-size: 0.85rem;
            min-width: 35px;
            transition: width 0.5s ease;
        }
        .bar-fill.critical { background: linear-gradient(90deg, var(--danger-dark) 0%, var(--danger) 100%); }
        .bar-fill.high { background: linear-gradient(90deg, #ea580c 0%, #f97316 100%); }
        .bar-fill.medium { background: linear-gradient(90deg, #d97706 0%, var(--warning) 100%); }
        .bar-fill.low { background: linear-gradient(90deg, #059669 0%, var(--success) 100%); }
        .bar-fill.info { background: linear-gradient(90deg, #4f46e5 0%, var(--info) 100%); }
        .bar-count {
            width: 50px;
            text-align: right;
            font-weight: 700;
            font-size: 1.1rem;
            color: var(--neutral-800);
        }
        
        /* Stats Cards */
        .findings-summary {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            margin: 1.5rem 0;
        }
        .stat-card {
            text-align: center;
            padding: 1.25rem 1rem;
            border-radius: 12px;
            color: white;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            position: relative;
            overflow: hidden;
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 50%;
            height: 100%;
            background: rgba(255,255,255,0.1);
            clip-path: polygon(30% 0, 100% 0, 100% 100%, 0% 100%);
        }
        .stat-card.critical { background: linear-gradient(135deg, var(--danger-dark) 0%, var(--danger) 100%); }
        .stat-card.high { background: linear-gradient(135deg, #ea580c 0%, #f97316 100%); }
        .stat-card.medium { background: linear-gradient(135deg, #d97706 0%, var(--warning) 100%); color: var(--neutral-800); }
        .stat-card.low { background: linear-gradient(135deg, #059669 0%, var(--success) 100%); }
        .stat-card.info { background: linear-gradient(135deg, #4f46e5 0%, var(--info) 100%); }
        .stat-card .number { 
            font-size: 2.5rem; 
            font-weight: 800; 
            line-height: 1;
            position: relative;
        }
        .stat-card .label { 
            text-transform: uppercase; 
            font-size: 0.7rem; 
            font-weight: 700;
            letter-spacing: 1px;
            margin-top: 0.5rem;
            opacity: 0.9;
        }
        
        /* Findings */
        .finding {
            border: 1px solid var(--neutral-200);
            border-radius: 12px;
            margin-bottom: 1.5rem;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }
        .finding-header {
            padding: 1rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-header.critical { background: linear-gradient(90deg, var(--danger-dark) 0%, var(--danger) 100%); color: white; }
        .finding-header.high { background: linear-gradient(90deg, #ea580c 0%, #f97316 100%); color: white; }
        .finding-header.medium { background: linear-gradient(90deg, #d97706 0%, var(--warning) 100%); color: var(--neutral-800); }
        .finding-header.low { background: linear-gradient(90deg, #059669 0%, var(--success) 100%); color: white; }
        .finding-header.info { background: linear-gradient(90deg, #4f46e5 0%, var(--info) 100%); color: white; }
        .finding-title { 
            font-weight: 700; 
            font-size: 1.05rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .finding-body { padding: 1.5rem; }
        .finding-body h4 { 
            color: var(--neutral-600); 
            margin: 1.25rem 0 0.5rem; 
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 700;
        }
        .finding-body p { margin-bottom: 1rem; color: var(--neutral-700); }
        .finding-meta {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid var(--neutral-200);
        }
        .finding-meta-item {
            display: flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.85rem;
            color: var(--neutral-600);
            background: var(--neutral-100);
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
        }
        .finding-screenshot {
            margin: 1rem 0;
            border-radius: 8px;
            overflow: hidden;
            border: 2px solid var(--neutral-200);
        }
        .finding-screenshot img {
            width: 100%;
            display: block;
        }
        .finding-screenshot-caption {
            background: var(--neutral-100);
            padding: 0.5rem 1rem;
            font-size: 0.85rem;
            color: var(--neutral-600);
            font-style: italic;
        }
        
        /* Code blocks */
        pre {
            background: var(--neutral-900);
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.85rem;
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            margin: 0.75rem 0;
        }
        code {
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 0.9em;
        }
        .command-block { 
            background: var(--neutral-900); 
            color: #e2e8f0; 
            padding: 1rem 1.25rem; 
            border-radius: 8px; 
            margin: 0.5rem 0; 
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; 
            font-size: 0.85rem; 
            overflow-x: auto; 
            border-left: 4px solid var(--accent);
            position: relative;
        }
        .command-label { 
            color: var(--accent); 
            margin-bottom: 0.25rem; 
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        /* Tags */
        .tag {
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
            padding: 0.25rem 0.75rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-right: 0.5rem;
            background: rgba(255,255,255,0.25);
        }
        
        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            table-layout: fixed;
        }
        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--neutral-200);
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        th { 
            background: var(--neutral-100); 
            font-weight: 700; 
            color: var(--neutral-700);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        tr:hover { background: var(--neutral-50); }
        
        .scope-table { margin-bottom: 1.5rem; overflow-x: auto; }
        .scope-table table { min-width: 100%; }
        .scope-table th { 
            background: var(--primary); 
            color: white; 
        }
        .scope-table td { 
            font-family: 'JetBrains Mono', monospace; 
            font-size: 0.85rem;
        }
        .scope-type-header { 
            background: var(--neutral-200) !important; 
            font-weight: 700; 
            color: var(--neutral-700); 
        }
        
        /* Infrastructure Tables - Fixed Overflow */
        .infrastructure-table { 
            margin-bottom: 2rem;
            overflow-x: auto;
        }
        .infrastructure-table h3 { 
            color: var(--primary); 
            margin-bottom: 1rem; 
            font-size: 1.05rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .infrastructure-table table { 
            width: 100%;
            min-width: 600px;
            border-collapse: collapse; 
            margin-top: 0.5rem;
            table-layout: fixed;
        }
        .infrastructure-table th { 
            background: var(--primary); 
            color: white; 
            padding: 0.75rem 1rem; 
            text-align: left; 
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .infrastructure-table td { 
            padding: 0.65rem 1rem; 
            border-bottom: 1px solid var(--neutral-200); 
            font-size: 0.85rem;
            word-break: break-word;
            overflow-wrap: break-word;
        }
        .infrastructure-table tr:nth-child(even) { background: var(--neutral-50); }
        .infrastructure-table code { 
            background: var(--neutral-200); 
            padding: 0.15rem 0.4rem; 
            border-radius: 4px; 
            font-size: 0.8rem;
            word-break: break-all;
        }
        .port-open { color: var(--success); font-weight: 700; }
        .port-filtered { color: #ea580c; font-weight: 700; }
        .port-closed { color: var(--danger); font-weight: 700; }
        
        /* Recon Section */
        .recon-section { 
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border-left: 4px solid var(--info);
        }
        .recon-data-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.25rem;
            margin-top: 1.5rem;
        }
        .recon-data-card {
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border: 1px solid var(--neutral-200);
        }
        .recon-data-header {
            background: var(--primary);
            color: white;
            padding: 0.75rem 1rem;
            font-weight: 600;
            font-size: 0.9rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .recon-data-count { 
            background: rgba(255,255,255,0.2); 
            padding: 0.2rem 0.6rem; 
            border-radius: 20px; 
            font-size: 0.8rem;
            font-weight: 700;
        }
        .recon-data-list {
            max-height: 250px;
            overflow-y: auto;
            padding: 0.5rem;
        }
        .recon-data-list code {
            display: block;
            padding: 0.4rem 0.75rem;
            font-size: 0.8rem;
            border-bottom: 1px solid var(--neutral-100);
            word-break: break-all;
            background: transparent;
            color: var(--neutral-700);
        }
        .recon-data-list code:last-child { border-bottom: none; }
        .recon-data-list code:hover { background: var(--neutral-50); }
        
        /* Tools Section */
        .tools-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        .tool-card {
            background: var(--neutral-50);
            border: 1px solid var(--neutral-200);
            border-radius: 10px;
            padding: 1.25rem 1rem;
            text-align: center;
            transition: all 0.2s;
        }
        .tool-card:hover {
            background: white;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        .tool-card .tool-icon { 
            font-size: 1.5rem; 
            margin-bottom: 0.5rem;
            filter: grayscale(0);
        }
        .tool-card .tool-name { 
            font-weight: 700; 
            color: var(--neutral-700);
            font-size: 0.95rem;
        }
        
        /* Artifacts Section */
        .artifacts-section { 
            background: linear-gradient(135deg, #f0f9ff 0%, #faf5ff 100%);
            border-left: 4px solid #8b5cf6;
        }
        .artifacts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }
        .artifact-card {
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border: 1px solid var(--neutral-200);
        }
        .artifact-header {
            background: var(--primary);
            color: white;
            padding: 0.75rem 1rem;
            font-weight: 600;
            font-size: 0.9rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .artifact-header.screenshot { background: linear-gradient(90deg, #7c3aed 0%, #8b5cf6 100%); }
        .artifact-header.tool-output { background: linear-gradient(90deg, #059669 0%, var(--success) 100%); }
        .artifact-body { padding: 1rem; }
        .artifact-body img { 
            max-width: 100%; 
            height: auto; 
            border-radius: 6px;
            border: 1px solid var(--neutral-200);
            cursor: pointer;
            transition: transform 0.2s;
        }
        .artifact-body img:hover { transform: scale(1.02); }
        .artifact-body pre {
            max-height: 280px;
            overflow: auto;
            font-size: 0.75rem;
            margin: 0;
            border-radius: 6px;
        }
        .artifact-meta { 
            font-size: 0.8rem; 
            color: var(--neutral-500); 
            margin-top: 0.75rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .download-btn {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            background: var(--primary);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            text-decoration: none;
            font-size: 0.85rem;
            font-weight: 600;
            margin-top: 0.75rem;
            transition: all 0.2s;
        }
        .download-btn:hover { 
            background: var(--primary-light);
            transform: translateY(-1px);
        }
        
        /* Conclusion Section */
        .conclusion-section { 
            background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%);
            border-left: 4px solid var(--success);
        }
        .conclusion-grid { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 1.5rem; 
            margin-top: 1.5rem; 
        }
        .conclusion-card { 
            background: white; 
            border-radius: 10px; 
            padding: 1.5rem; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            border: 1px solid var(--neutral-200);
        }
        .conclusion-card h4 { 
            color: #065f46; 
            margin-bottom: 1rem; 
            display: flex; 
            align-items: center; 
            gap: 0.5rem;
            font-size: 1rem;
        }
        .conclusion-card ul { margin: 0; padding-left: 1.25rem; }
        .conclusion-card li { 
            margin-bottom: 0.5rem;
            color: var(--neutral-700);
        }
        .priority-badge { 
            display: inline-block; 
            padding: 0.2rem 0.6rem; 
            border-radius: 20px; 
            font-size: 0.7rem; 
            font-weight: 700; 
            margin-left: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .priority-immediate { background: var(--danger); color: white; }
        .priority-short { background: #f97316; color: white; }
        .priority-medium { background: var(--warning); color: var(--neutral-800); }
        .priority-long { background: var(--success); color: white; }
        
        /* References */
        .references-list { list-style: none; padding: 0; margin: 0.5rem 0; }
        .references-list li { 
            padding: 0.5rem 0; 
            border-bottom: 1px solid var(--neutral-100);
        }
        .references-list li:last-child { border-bottom: none; }
        .references-list a { 
            color: var(--info); 
            text-decoration: none;
            font-weight: 500;
        }
        .references-list a:hover { text-decoration: underline; }
        
        /* Steps List */
        .steps-list { 
            counter-reset: step-counter; 
            list-style: none; 
            padding-left: 0; 
        }
        .steps-list li { 
            counter-increment: step-counter; 
            margin-bottom: 0.75rem; 
            padding-left: 2.5rem; 
            position: relative;
            color: var(--neutral-700);
        }
        .steps-list li::before { 
            content: counter(step-counter); 
            position: absolute; 
            left: 0; 
            background: var(--primary); 
            color: white; 
            width: 1.75rem; 
            height: 1.75rem; 
            border-radius: 50%; 
            text-align: center; 
            font-size: 0.85rem; 
            line-height: 1.75rem;
            font-weight: 700;
        }
        
        .report-note {
            border-left: 3px solid var(--warning);
            background: #fffbeb;
            color: var(--neutral-700);
            padding: 0.65rem 0.85rem;
            border-radius: 0 6px 6px 0;
            margin: 0.5rem 0 1rem;
            font-size: 0.9rem;
        }
        .finding-body table { table-layout: auto; }
        .finding-body table th { width: 22%; }
        @page { size: A4; margin: 16mm 14mm; }
        /* Print Styles */
        @media print {
            body { background: white; font-size: 12px; }
            .container { max-width: 100%; padding: 0; }
            .section { 
                break-inside: avoid; 
                box-shadow: none;
                border: 1px solid #ddd;
                margin-bottom: 1rem;
            }
            .report-header { 
                background: var(--primary) !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            .finding { break-inside: avoid; }
            .section h2, .finding h4 { break-after: avoid; }
            .report-note { border: 1px solid #b45309; background: #fff; }
            .recon-data-list { max-height: none; }
            .artifact-body pre { max-height: none; }
            .infrastructure-table { break-inside: avoid; }
            .stat-card {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
        }
        
        /* Responsive */
        @media (max-width: 768px) { 
            .container { padding: 1rem; }
            .report-header { padding: 2rem 1.5rem; }
            .report-header h1 { font-size: 1.75rem; }
            .findings-summary { grid-template-columns: repeat(3, 1fr); }
            .conclusion-grid { grid-template-columns: 1fr; }
            .artifacts-grid { grid-template-columns: 1fr; }
            .infrastructure-table table { min-width: 500px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>{{title}}</h1>
            <div class="subtitle">{{subtitle}}</div>
            <div class="meta">
                <div class="meta-item">
                    <svg class="meta-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                    </svg>
                    <span>{{target}}</span>
                </div>
                <div class="meta-item">
                    <svg class="meta-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>
                    </svg>
                    <span>{{date}}</span>
                </div>
                <div class="meta-item">
                    <svg class="meta-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
                    </svg>
                    <span>{{author}}</span>
                </div>
            </div>
        </div>
        
        <div class="section executive-summary">
            <h2>
                <span class="section-icon">📋</span>
                Executive Summary
            </h2>
            
            <div class="exec-summary-content">
                {{executive_summary_html}}
            </div>
            
            <!-- Severity Distribution Chart -->
            <div class="severity-chart-container">
                <div class="severity-chart-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>
                    </svg>
                    Vulnerability Distribution by Severity
                </div>
                <div class="severity-chart">
                    <div class="severity-bar">
                        <span class="severity-label critical">Critical</span>
                        <div class="bar-container">
                            <div class="bar-fill critical" style="width: {{critical_percent}}%;">{{critical_count}}</div>
                        </div>
                        <span class="bar-count">{{critical_count}}</span>
                    </div>
                    <div class="severity-bar">
                        <span class="severity-label high">High</span>
                        <div class="bar-container">
                            <div class="bar-fill high" style="width: {{high_percent}}%;">{{high_count}}</div>
                        </div>
                        <span class="bar-count">{{high_count}}</span>
                    </div>
                    <div class="severity-bar">
                        <span class="severity-label medium">Medium</span>
                        <div class="bar-container">
                            <div class="bar-fill medium" style="width: {{medium_percent}}%;">{{medium_count}}</div>
                        </div>
                        <span class="bar-count">{{medium_count}}</span>
                    </div>
                    <div class="severity-bar">
                        <span class="severity-label low">Low</span>
                        <div class="bar-container">
                            <div class="bar-fill low" style="width: {{low_percent}}%;">{{low_count}}</div>
                        </div>
                        <span class="bar-count">{{low_count}}</span>
                    </div>
                    <div class="severity-bar">
                        <span class="severity-label info">Info</span>
                        <div class="bar-container">
                            <div class="bar-fill info" style="width: {{info_percent}}%;">{{info_count}}</div>
                        </div>
                        <span class="bar-count">{{info_count}}</span>
                    </div>
                </div>
            </div>
            
            <div class="findings-summary">
                <div class="stat-card critical">
                    <div class="number">{{critical_count}}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="number">{{high_count}}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="number">{{medium_count}}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="number">{{low_count}}</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat-card info">
                    <div class="number">{{info_count}}</div>
                    <div class="label">Info</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>
                <span class="section-icon">🎯</span>
                Scope & Methodology
            </h2>
            <h3>Targets in Scope</h3>
            {{scope_table}}
            
            <h3>Testing Methodology</h3>
            <p>{{methodology}}</p>
        </div>
        
        {{recon_section}}
        
        <div class="section">
            <h2>
                <span class="section-icon">🔍</span>
                Detailed Findings
            </h2>
            {{findings_html}}
        </div>
        
        <div class="section conclusion-section">
            <h2>
                <span class="section-icon">📝</span>
                Conclusion & Recommendations
            </h2>
            {{conclusion_html}}
        </div>
        
        <div class="section">
            <h2>
                <span class="section-icon">🛠️</span>
                Tools Used
            </h2>
            <p>The following tools were used during this assessment:</p>
            <div class="tools-grid">
                {{tools_used}}
            </div>
        </div>
        
        {{artifacts_section}}
        
        <div class="section">
            <h2>
                <span class="section-icon">📚</span>
                References
            </h2>
            <ul class="references-list">
                {{references}}
            </ul>
        </div>
    </div>
</body>
</html>'''
