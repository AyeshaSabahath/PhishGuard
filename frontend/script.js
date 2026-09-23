const urlInput = document.getElementById("urlInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const sampleBtn = document.getElementById("sampleBtn");
const resultSection = document.getElementById("resultSection");

sampleBtn.addEventListener("click", () => {
    urlInput.value = "http://secure-login-verify.example.xyz/account/update";
    urlInput.focus();
});

analyzeBtn.addEventListener("click", analyze);

urlInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") analyze();
});

async function analyze() {
    const url = urlInput.value.trim();

    if (!url) {
        showError("Please enter a URL.");
        return;
    }

    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = "Analyzing...";

    try {
        const response = await fetch("/api/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to analyze URL.");
        }

        renderResult(data);
    } catch (error) {
        showError(error.message);
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = 'Analyze URL <span>→</span>';
    }
}

function renderResult(data) {
    resultSection.classList.remove("hidden");

    const phishing = data.prediction.toLowerCase() === "phishing";
    document.getElementById("resultTitle").textContent =
        phishing ? "Potential Phishing URL" : "Likely Benign URL";

    document.getElementById("resultUrl").textContent = data.url;

    const badge = document.getElementById("badge");
    badge.textContent = phishing ? "🔴 PHISHING" : "🟢 BENIGN";
    badge.className = "badge " + (phishing ? "danger" : "safe");

    document.getElementById("riskScore").textContent = `${data.riskScore}%`;
    document.getElementById("confidence").textContent = `${data.confidence}%`;
    document.getElementById("riskBar").style.width = `${data.riskScore}%`;
    document.getElementById("confidenceBar").style.width = `${data.confidence}%`;

    const list = document.getElementById("indicatorList");
    list.innerHTML = "";

    data.indicators.forEach(indicator => {
        const div = document.createElement("div");
        div.className = "indicator";
        div.textContent = "• " + indicator;
        list.appendChild(div);
    });

    resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function showError(message) {
    resultSection.classList.remove("hidden");
    document.getElementById("resultTitle").textContent = "Analysis Error";
    document.getElementById("resultUrl").textContent = message;

    const badge = document.getElementById("badge");
    badge.textContent = "⚠ ERROR";
    badge.className = "badge danger";

    document.getElementById("riskScore").textContent = "—";
    document.getElementById("confidence").textContent = "—";
    document.getElementById("riskBar").style.width = "0";
    document.getElementById("confidenceBar").style.width = "0";
    document.getElementById("indicatorList").innerHTML = "";
}
