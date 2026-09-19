// Function to check if the current page is likely a privacy policy or terms of service
function isPolicyPage() {
    const url = window.location.href.toLowerCase();
    const title = document.title.toLowerCase();
    const keywords = ['privacy', 'terms', 'condition', 'policy', 'legal'];
    
    return keywords.some(kw => url.includes(kw) || title.includes(kw));
}

// Function to extract text from the main body of the page
function extractPageText() {
    // Clone body to manipulate safely
    const clone = document.body.cloneNode(true);
    
    // Remove scripts, styles, navs, footers to clean up text
    const tagsToRemove = ['script', 'style', 'noscript', 'nav', 'footer', 'header'];
    tagsToRemove.forEach(tag => {
        const elements = clone.getElementsByTagName(tag);
        while(elements.length > 0){
            elements[0].parentNode.removeChild(elements[0]);
        }
    });

    return clone.innerText.trim();
}

// Inject the sidebar HTML into the page
function injectSidebar() {
    if (document.getElementById('policy-safeguard-sidebar')) return;

    // Sidebar Container
    const sidebar = document.createElement('div');
    sidebar.id = 'policy-safeguard-sidebar';
    sidebar.innerHTML = `
        <div class="ps-header">
            <h2>🛡️ Policy Safeguard</h2>
            <button class="ps-close-btn" id="ps-close">&times;</button>
        </div>
        <div class="ps-content" id="ps-content">
            <div class="ps-loading">
                <div class="ps-spinner"></div>
                <p>Analyzing policy text...</p>
            </div>
        </div>
    `;
    document.body.appendChild(sidebar);

    // Floating Trigger Button
    const triggerBtn = document.createElement('button');
    triggerBtn.id = 'policy-safeguard-trigger';
    triggerBtn.innerHTML = '🛡️ Analyze Policy';
    document.body.appendChild(triggerBtn);

    // Event Listeners
    document.getElementById('ps-close').addEventListener('click', () => {
        sidebar.classList.remove('open');
    });

    triggerBtn.addEventListener('click', () => {
        sidebar.classList.add('open');
        analyzePolicy();
    });
}

// Map severity string to emoji
function getSeverityEmoji(severity) {
    if (severity === 'red') return '🔴';
    if (severity === 'yellow') return '🟡';
    return '🟢';
}

// Render the API response into the sidebar
function renderReport(report) {
    const contentDiv = document.getElementById('ps-content');
    
    // Create Score Card
    const scoreCard = `
        <div class="ps-score-card ${report.risk_level}">
            <div class="ps-score-value">${report.overall_risk_score}/100</div>
            <div>${report.risk_level.toUpperCase()}</div>
        </div>
        <div class="ps-summary">${report.summary}</div>
    `;

    // Create Match Cards (only red and yellow to save space)
    let matchesHtml = '<h3>Detected Clauses</h3>';
    
    if (report.matches.length === 0) {
        matchesHtml += '<p>No significant risks found. This policy looks relatively standard.</p>';
    } else {
        report.matches.forEach(match => {
            if (match.severity === 'green') return; // Skip green to avoid cluttering UX
            
            matchesHtml += `
                <div class="ps-match-card ${match.severity}">
                    <div class="ps-match-category">
                        ${getSeverityEmoji(match.severity)} ${match.category}
                    </div>
                    <div class="ps-match-desc">${match.description}</div>
                    <div class="ps-match-snippet">"...${match.matched_text}..."</div>
                </div>
            `;
        });
    }

    contentDiv.innerHTML = scoreCard + matchesHtml;
}

// Main function to fetch analysis from backend
async function analyzePolicy() {
    const text = extractPageText();
    
    // Prevent sending massive payloads (cap at ~50k chars)
    const payloadText = text.length > 50000 ? text.substring(0, 50000) : text;

    try {
        const response = await fetch('http://localhost:8000/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                text: payloadText,
                url: window.location.href
            })
        });

        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const data = await response.json();
        renderReport(data);

    } catch (error) {
        console.error('Policy Safeguard Analysis Error:', error);
        document.getElementById('ps-content').innerHTML = `
            <div class="ps-loading">
                <p>❌ Failed to connect to the backend analyzer.</p>
                <p style="font-size: 12px">Make sure your FastAPI server is running on localhost:8000.</p>
            </div>
        `;
    }
}

// Auto-inject and optionally auto-trigger if on a policy page
if (isPolicyPage()) {
    injectSidebar();
    // Auto-open is aggressive, so we just show the floating button by default
    // user clicks it to scan.
}

// Listen for messages from popup if user clicks manual scan
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scan_now") {
        injectSidebar(); // Ensure it exists
        const sidebar = document.getElementById('policy-safeguard-sidebar');
        sidebar.classList.add('open');
        analyzePolicy();
        sendResponse({status: "started"});
    }
});
