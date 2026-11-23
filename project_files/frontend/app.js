const API_BASE_URL = "http://127.0.0.1:8000";
let currentNonce = null;
let activeHolderDID = null;

function toggleSetupGuide() {
    document.getElementById('setup-guide').classList.toggle('hidden');
}

function appendConsoleLog(message, isError = false) {
    const consoleBox = document.getElementById("audit-log-console");
    if (consoleBox) {
        const entry = document.createElement("div");
        entry.className = isError ? "text-rose-400 font-mono text-[11px] py-0.5" : "text-emerald-400 font-mono text-[11px] py-0.5";
        entry.innerText = `[${new Date().toLocaleTimeString()}] > ${message}`;
        consoleBox.appendChild(entry);
        consoleBox.scrollTop = consoleBox.scrollHeight;
    }
}

// --- 1. Automatic Backend DID Creation & PDF Hash Binding ---
async function autoCreateDidAndUploadPdf() {
    const fileInput = document.getElementById("holder-pdf-input");
    const walletInput = document.getElementById("user-wallet-did");

    if (!fileInput || fileInput.files.length === 0) return;
    const file = fileInput.files[0];

    appendConsoleLog(`[Wallet]: Uploaded '${file.name}'. Requesting sovereign DID from backend...`);
    walletInput.value = "Communicating with FastAPI core...";

    try {
        const res = await fetch(`${API_BASE_URL}/api/create-wallet`, { method: "POST" });
        const data = await res.json();
        
        activeHolderDID = data.did;
        walletInput.value = activeHolderDID;

        appendConsoleLog(`[Wallet SUCCESS]: Created keypair -> ${activeHolderDID.substring(0, 24)}...`);
        document.getElementById("workflow-status-text").innerText = "Step 2: DID generated. Now run the Verifier Handshake or Sign & Dispatch VC.";

    } catch (err) {
        appendConsoleLog("[Error]: Could not connect to backend to generate wallet.", true);
    }
}

// --- 2. Backend Verifier Handshake & Replay Detection ---
async function runLegitimateHandshake() {
    if (!activeHolderDID) {
        alert("Please upload your PDF marks card first to generate a Holder DID!");
        return;
    }

    const startTime = performance.now();
    currentNonce = "nonce_" + Math.random().toString(36).substring(2, 12);
    appendConsoleLog(`[Verifier]: Sending authentication challenge with dynamic nonce...`);

    try {
        const res = await fetch(`${API_BASE_URL}/api/verify-handshake`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ holder_did: activeHolderDID, nonce: currentNonce })
        });

        const duration = Math.round(performance.now() - startTime);
        const data = await res.json();

        appendConsoleLog(`Verifier Result: ${data.status} | Risk Score: ${data.risk_score} | ${data.reason}`);
        updateDashboardUI({ verification_speed_ms: duration, decision: data.status, risk_score: data.risk_score });

    } catch (err) {
        appendConsoleLog("[Verifier Error]: Handshake verification endpoint failed.", true);
    }
}

async function runReplayThreatTest() {
    if (!currentNonce || !activeHolderDID) {
        appendConsoleLog("[Warning]: Run a legitimate handshake first to register a nonce baseline.", true);
        return;
    }

    const startTime = performance.now();
    appendConsoleLog(`[Threat Simulation]: Replaying identical nonce to trigger AI Anomaly Engine...`);

    try {
        const res = await fetch(`${API_BASE_URL}/api/verify-handshake`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ holder_did: activeHolderDID, nonce: currentNonce })
        });

        const duration = Math.round(performance.now() - startTime);
        const data = await res.json();

        appendConsoleLog(`THREAT INTERCEPTED: ${data.status} | Risk Score: ${data.risk_score} | ${data.reason}`, true);
        updateDashboardUI({ verification_speed_ms: duration, decision: data.status, risk_score: data.risk_score });

    } catch (err) {
        appendConsoleLog("[Error]: Threat simulation failed.", true);
    }
}

// --- 3. Backend Issuer PDF Hash Binding & VC Issuance ---
async function dispatchCredentialFromBackend() {
    const fileInput = document.getElementById("holder-pdf-input");
    const schemaSelect = document.getElementById("credential-schema-select");

    if (!activeHolderDID) {
        alert("No active Holder DID found. Please upload your PDF marks card first!");
        return;
    }

    if (!fileInput || fileInput.files.length === 0) {
        alert("Please select your PDF marks card file first!");
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    formData.append("holder_did", activeHolderDID);

    appendConsoleLog(`[Issuer]: Computing SHA-256 hash of PDF and signing with Issuer private key...`);

    try {
        const res = await fetch(`${API_BASE_URL}/api/issue-credential-pdf`, {
            method: "POST",
            body: formData
        });

        const data = await res.json();

        if (res.ok) {
            appendConsoleLog(`[Issuer SUCCESS]: VC signed! Doc Hash: ${data.document_hash.substring(0, 16)}... Student: ${data.student_name}`);
            
            const container = document.getElementById("vc-storage-container");
            document.getElementById("vc-count-badge").innerText = "1 stored";
            container.innerHTML = `
                <div class="p-2.5 bg-slate-900 rounded-lg border border-emerald-500/40 text-left text-xs space-y-1 font-mono">
                    <div class="text-emerald-400 font-bold">✓ ${schemaSelect ? schemaSelect.value : data.credential.type}</div>
                    <div class="text-[10px] text-slate-400">VC ID: ${data.credential.vc_id}</div>
                    <div class="text-[10px] text-slate-400">Hash: <span class="text-cyan-400">${data.document_hash.substring(0, 18)}...</span></div>
                    <div class="text-[9px] text-slate-500">Student: ${data.student_name}</div>
                </div>
            `;
        } else {
            appendConsoleLog(`[Issuance Error]: ${data.detail}`, true);
        }

    } catch (err) {
        appendConsoleLog("[Network Error]: Could not reach backend issuer endpoint.", true);
    }
}

// --- 4. Automated Vulnerability Scanning Hook ---
async function triggerVulnerabilityScan(codeSnippet) {
    const vulnStatusEl = document.getElementById("vuln-scan-status");
    const vulnLogEl = document.getElementById("vuln-audit-log");

    if (vulnStatusEl) vulnStatusEl.innerText = "SCANNING...";

    const logToMitigationConsole = (message, isError = false) => {
        if (vulnLogEl) {
            const entry = document.createElement("div");
            entry.className = isError ? "text-rose-400 font-bold" : "text-emerald-400";
            entry.innerText = `[${new Date().toLocaleTimeString()}] ${message}`;
            vulnLogEl.appendChild(entry);
            vulnLogEl.scrollTop = vulnLogEl.scrollHeight;
        }
    };

    try {
        logToMitigationConsole("[Vulnerability Engine]: Executing real-time automated code scan against FastAPI core...");

        const response = await fetch(`${API_BASE_URL}/api/vulnerability/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code_snippet: codeSnippet })
        });

        const result = await response.json();
        const isVulnerable = result.has_vulnerability === true || result.status === "VULNERABILITY_FOUND";

        if (isVulnerable) {
            document.getElementById("control-replay").innerText = "INTERCEPTED";
            document.getElementById("control-replay").className = "text-xs font-bold text-rose-400";
            document.getElementById("control-replay-dot").className = "w-2 h-2 rounded-full bg-rose-500 animate-ping";

            document.getElementById("control-revocation").innerText = "SANDBOXED";
            document.getElementById("control-revocation").className = "text-xs font-bold text-rose-400";
            document.getElementById("control-revocation-dot").className = "w-2 h-2 rounded-full bg-rose-500";

            logToMitigationConsole(`[Vulnerability Engine]: ⚠️ ${result.message || 'Vulnerability detected and neutralized!'} (${result.vulnerabilities_found} threat pattern(s) matched)`, true);
            if (vulnStatusEl) {
                vulnStatusEl.innerText = "THREAT MITIGATED";
                vulnStatusEl.className = "text-[10px] bg-rose-950 text-rose-300 border border-rose-800/50 px-2.5 py-1 rounded-full font-semibold uppercase tracking-wider";
            }
        } else {
            document.getElementById("control-replay").innerText = "ACTIVE";
            document.getElementById("control-replay").className = "text-xs font-bold text-emerald-400";
            document.getElementById("control-replay-dot").className = "w-2 h-2 rounded-full bg-emerald-500";

            document.getElementById("control-revocation").innerText = "PASSED";
            document.getElementById("control-revocation").className = "text-xs font-bold text-emerald-400";
            document.getElementById("control-revocation-dot").className = "w-2 h-2 rounded-full bg-emerald-500";

            logToMitigationConsole("[Vulnerability Engine]: Dynamic scan finished. No threats found.");
            if (vulnStatusEl) {
                vulnStatusEl.innerText = "PASSED";
                vulnStatusEl.className = "text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800/50 px-2.5 py-1 rounded-full font-semibold uppercase tracking-wider";
            }
        }

        return result;
    } catch (error) {
        logToMitigationConsole("[Vulnerability Engine]: Scan error or connection failed.", true);
        if (vulnStatusEl) vulnStatusEl.innerText = "ERROR";
    }
}

function updateDashboardUI(data) {
    if (!data) return;
    if (data.verification_speed_ms !== undefined) {
        document.getElementById("verification-speed").innerText = `${Math.round(data.verification_speed_ms)} ms`;
    }
    if (data.decision) {
        const dec = document.getElementById("model-decision");
        dec.innerText = data.decision;
        dec.className = `text-sm font-bold ${data.decision === "ALLOW" ? "text-emerald-400" : "text-rose-400"}`;
    }
    if (data.risk_score !== undefined) {
        document.getElementById("dynamic-risk-score").innerText = `${(data.risk_score * 100).toFixed(1)}%`;
    }
}