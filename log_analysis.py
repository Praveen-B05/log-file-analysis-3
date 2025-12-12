from flask import Flask, request, render_template_string
import os
app = Flask(__name__)
THREATS = {
    "malware": {
        "score": 80,
        "desc": "Malware is malicious software designed to damage, disrupt, or gain unauthorized access to systems.",
        "impact": "Can steal data, delete files, corrupt systems, or give attackers remote access.",
        "severity": "HIGH",
        "fix": "Delete the file immediately. Run a full antivirus scan. Patch all software and reboot system."
    },
    "virus": {
        "score": 60,
        "desc": "A computer virus attaches itself to clean files and spreads, often damaging or deleting data.",
        "impact": "Replicates across files, slows system, corrupts data.",
        "severity": "HIGH",
        "fix": "Disconnect internet, boot in safe mode, run antivirus scan."
    },
    "trojan": {
        "score": 90,
        "desc": "A Trojan hides inside normal files and creates a secret backdoor for hackers.",
        "impact": "Allows remote control, data theft, ransomware installation.",
        "severity": "CRITICAL",
        "fix": "Isolate computer from network, remove file, change all passwords."
    },
    "payload": {
        "score": 70,
        "desc": "A malicious payload is code inside malware that performs harmful actions.",
        "impact": "Deletes files, encrypts data, installs additional malware.",
        "severity": "HIGH",
        "fix": "Immediately scan entire system; restore from backup if needed."
    },
    "exploit": {
        "score": 50,
        "desc": "An exploit targets software vulnerabilities to break security controls.",
        "impact": "Can bypass authentication or run unauthorized commands.",
        "severity": "MEDIUM",
        "fix": "Update OS/software ASAP. Apply patches. Enable firewall."
    },
    "shell": {
        "score": 65,
        "desc": "A shell-backdoor allows attackers to control your system remotely.",
        "impact": "Gives full attacker access: commands, file access, surveillance.",
        "severity": "HIGH",
        "fix": "Block network connections, remove backdoors, rotate passwords."
    },
    "attack": {
        "score": 40,
        "desc": "Attack signatures indicate attempts to break your system security.",
        "impact": "May lead to system compromise or data theft.",
        "severity": "MEDIUM",
        "fix": "Enable firewall, inspect logs, tighten access control."
    },
    "hack": {
        "score": 55,
        "desc": "Hacking indicators reveal attempts to bypass system protections.",
        "impact": "Possible unauthorized access attempt.",
        "severity": "MEDIUM",
        "fix": "Change passwords, activate 2FA, review access logs."
    }
}
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Log Analysis Report</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
    body { margin: 0; font-family: Arial; background: #eee; }
    .main-title { text-align:center; padding:20px; font-size:34px; background:black; color:white; }
    .layout { display:flex; height:100vh; }

    .left-panel {
        width:35%; background:black; color:white; padding:25px;
        display:flex; flex-direction:column; gap:25px; overflow-y:auto;
    }

    .left-box {
        background:rgba(255,255,255,0.05);
        border:2px solid white;
        padding:20px;
        border-radius:10px;
    }

    h2 { margin-bottom:10px; color:white; }

    .right-panel { flex:1; background:white; padding:40px; }
    .chart-container { height:80%; }
    input[type=file] { color:white; }
    button { background:white; border:2px solid black; padding:10px 20px; cursor:pointer; }
    button:hover { background:black; color:white; }
</style>
</head>

<body>

<div class="main-title">LOG ANALYSIS REPORT</div>

<div class="layout">

    <!-- LEFT SIDE -->
    <div class="left-panel">

        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="file"><br><br>
            <button type="submit">SCAN FILE</button>
        </form>

        <div class="left-box">
            <h2>📁 FILE DETAILS</h2>
            {{ details|safe }}
        </div>

        <div class="left-box">
            <h2>⚠ FULL REPORT</h2>
            {{ report|safe }}
        </div>

    </div>

    <!-- RIGHT SIDE -->
    <div class="right-panel">
        <h2 style="color:#333;">Security Level Chart</h2>
        <p style="color:#666;">Threat levels detected in scanned file</p>
        <div class="chart-container">
            <canvas id="chart"></canvas>
        </div>
    </div>

</div>

<script>
let labels = {{ labels|safe }};
let values = {{ values|safe }};
let colors = {{ colors|safe }};

new Chart(document.getElementById('chart'), {
    type: 'bar',
    data: {
        labels: labels,
        datasets: [{
            label:"Threat Level",
            data: values,
            backgroundColor: colors,
            borderColor:"black",
            borderWidth:2,
            borderRadius:5
        }]
    },
    options:{
        scales:{ y:{ beginAtZero:true } }
    }
});
</script>

</body>
</html>
"""
def analyze_file(path, filename):
    text = open(path, "r", errors="ignore").read().lower()

    labels = []
    values = []
    colors = []
    report = ""

    for key, info in THREATS.items():
        labels.append(key)
        if key in text:
            values.append(info["score"])
            colors.append("red")

            # Add full report details
            report += f"""
            <b style='color:red; font-size:20px;'>{key.upper()} DETECTED</b><br>
            <b>Description:</b> {info['desc']}<br>
            <b>Impact:</b> {info['impact']}<br>
            <b>Severity:</b> {info['severity']}<br>
            <b>Recommended Action:</b> {info['fix']}<br>
            <hr>
            """
        else:
            values.append(5)
            colors.append("green")

    if report == "":
        report = """
        <b style='color:lightgreen; font-size:20px;'>✔ SAFE FILE</b><br>
        No malicious indicators found.<br>
        Security Risk: LOW<br>
        """

    details = f"""
        <p><b>Name:</b> {filename}</p>
        <p><b>Size:</b> {os.path.getsize(path)} bytes</p>
    """

    return details, report, labels, values, colors
@app.route("/", methods=["GET", "POST"])
def home():

    details = "<p>No file uploaded</p>"
    report  = "<p>Upload a file to generate report</p>"
    labels = list(THREATS.keys())
    values = [0] * len(labels)
    colors = ["green"] * len(labels)

    if request.method == "POST":
        file = request.files["file"]
        file.save("uploaded.txt")
        details, report, labels, values, colors = analyze_file("uploaded.txt", file.filename)

    return render_template_string(
        HTML,
        details=details,
        report=report,
        labels=labels,
        values=values,
        colors=colors
    )

if __name__ == "__main__":
    app.run(debug=True)

