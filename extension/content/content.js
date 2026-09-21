// ==========================================================================
// Policy Safeguard - Content Script (Category Grouping & Glassmorphic UI)
// ==========================================================================

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
            <div class="ps-header-title">
                <span class="ps-header-icon">🛡️</span>
                <h2>Policy Safeguard</h2>
            </div>
            <button class="ps-close-btn" id="ps-close" title="Close Sidebar" aria-label="Close">&times;</button>
        </div>
        <div class="ps-content" id="ps-content">
            <div class="ps-loading">
                <div class="ps-spinner"></div>
                <div class="ps-loading-title">Analyzing Policy Text...</div>
                <p class="ps-loading-sub">Scanning clauses for predatory terms and privacy risks</p>
            </div>
        </div>
    `;
    document.body.appendChild(sidebar);

    // Floating Glassmorphic Trigger Button
    const triggerBtn = document.createElement('button');
    triggerBtn.id = 'policy-safeguard-trigger';
    triggerBtn.innerHTML = `
        <span class="ps-btn-icon">🛡️</span>
        <span class="ps-btn-text">Analyze Policy</span>
    `;
    document.body.appendChild(triggerBtn);

    // Event Listeners
    document.getElementById('ps-close').addEventListener('click', () => {
        sidebar.classList.remove('open');
        document.body.style.overflow = ''; // Allow page scrolling
    });

    triggerBtn.addEventListener('click', () => {
        sidebar.classList.add('open');
        document.body.style.overflow = 'hidden'; // Prevent page scrolling
        analyzePolicy();
    });
}

// Helper to safely escape HTML entities
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Format snippet with optional highlight of the matched keyword/clause
function formatSnippet(snippet, matchedText, severity) {
    if (!snippet) return '';
    const safeSnippet = escapeHtml(snippet);
    if (!matchedText) return safeSnippet;
    
    const safeMatched = escapeHtml(matchedText.trim());
    if (!safeMatched) return safeSnippet;

    const highlightClass = severity === 'red' ? 'ps-highlight-red' : 'ps-highlight-yellow';
    
    try {
        const escaped = safeMatched.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(`(${escaped})`, 'i');
        if (regex.test(safeSnippet)) {
            return safeSnippet.replace(regex, `<mark class="${highlightClass}">$1</mark>`);
        }
    } catch (e) {
        // Fallback to plain escaped text on regex error
    }

    return safeSnippet;
}

// Render the API response into the sidebar with category grouping
function renderReport(report) {
    const contentDiv = document.getElementById('ps-content');
    if (!contentDiv) return;

    // Determine risk level badge & display text
    const riskLevel = (report.risk_level || 'safe').toLowerCase();
    const riskScore = typeof report.overall_risk_score === 'number' ? report.overall_risk_score : 0;
    
    let levelLabel = 'SAFE';
    if (riskLevel === 'dangerous') {
        levelLabel = 'HIGH RISK';
    } else if (riskLevel === 'caution') {
        levelLabel = 'MODERATE RISK';
    } else if (riskLevel === 'safe') {
        levelLabel = 'LOW RISK';
    }

    // Counts breakdown
    const redCount = report.severity_counts ? (report.severity_counts.red || 0) : 0;
    const yellowCount = report.severity_counts ? (report.severity_counts.yellow || 0) : 0;
    const greenCount = report.severity_counts ? (report.severity_counts.green || 0) : 0;

    // Score Card HTML with sleek modern gradient & breakdown
    const scoreCardHtml = `
        <div class="ps-score-card ${riskLevel}">
            <div class="ps-score-header">
                <span class="ps-score-badge-pill">${levelLabel}</span>
                <span class="ps-score-ratio">Risk Index</span>
            </div>
            <div class="ps-score-main">
                <span class="ps-score-value">${riskScore}</span>
                <span class="ps-score-max">/100</span>
            </div>
            <div class="ps-score-counts">
                <span class="ps-badge-counter">${redCount} Critical</span>
                <span class="ps-badge-counter">${yellowCount} Warning</span>
                <span class="ps-badge-counter">${greenCount} Info</span>
            </div>
        </div>
        ${report.summary ? `
            <div class="ps-summary-card">
                <div class="ps-summary-header">
                    <span>📋 Key Findings</span>
                </div>
                <p class="ps-summary-text">${escapeHtml(report.summary)}</p>
            </div>
        ` : ''}
    `;

    // Group matches by category
    const categoryGroups = {};
    const matches = Array.isArray(report.matches) ? report.matches : [];

    matches.forEach(match => {
        // Skip green clauses to focus user attention on actionable risks
        if (match.severity === 'green') return;

        const cat = match.category || 'General Risk';
        if (!categoryGroups[cat]) {
            categoryGroups[cat] = {
                category: cat,
                severity: match.severity || 'yellow',
                descriptions: new Set(),
                recommendations: new Set(),
                snippets: []
            };
        }

        const grp = categoryGroups[cat];

        // Elevate category severity to red if any match in it is red
        if (match.severity === 'red') {
            grp.severity = 'red';
        }

        if (match.description) {
            grp.descriptions.add(match.description);
        }
        if (match.recommendation) {
            grp.recommendations.add(match.recommendation);
        }

        const snippetText = match.context_snippet || match.matched_text;
        if (snippetText) {
            // Deduplicate exact snippets within the same category
            const alreadyExists = grp.snippets.some(s => s.context === snippetText);
            if (!alreadyExists) {
                grp.snippets.push({
                    context: snippetText,
                    matched: match.matched_text || ''
                });
            }
        }
    });

    // Sort categories: red (critical) first, then yellow (warning)
    const severityRank = { red: 0, yellow: 1, green: 2 };
    const sortedCategories = Object.values(categoryGroups).sort((a, b) => {
        return (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99);
    });

    // Build Grouped Cards Section
    let cardsHtml = '';

    if (sortedCategories.length === 0) {
        cardsHtml = `
            <div class="ps-empty-state">
                <div class="ps-empty-icon">🛡️</div>
                <div class="ps-empty-title">No Critical Threats Detected</div>
                <div class="ps-empty-desc">No high or moderate risk clauses were identified. This policy looks relatively standard.</div>
            </div>
        `;
    } else {
        const totalClauses = sortedCategories.reduce((sum, g) => sum + g.snippets.length, 0);
        cardsHtml += `
            <div class="ps-section-header">
                <h3 class="ps-section-title">Detected Threat Categories</h3>
                <span class="ps-section-counter">${totalClauses} clause${totalClauses > 1 ? 's' : ''} in ${sortedCategories.length} categor${sortedCategories.length > 1 ? 'ies' : 'y'}</span>
            </div>
        `;

        sortedCategories.forEach(grp => {
            const isRed = grp.severity === 'red';
            const badgeIcon = isRed ? '🔴' : '⚠️';
            const badgeClass = isRed ? 'ps-badge-red' : 'ps-badge-yellow';
            const badgeLabel = isRed ? 'Critical Risk' : 'Warning';

            // Distinct descriptions
            const descHtml = Array.from(grp.descriptions)
                .map(d => `<p class="ps-match-desc">${escapeHtml(d)}</p>`)
                .join('');

            // Distinct recommendations grouped cleanly
            const recsArray = Array.from(grp.recommendations);
            let recHtml = '';
            if (recsArray.length > 0) {
                recHtml = `
                    <div class="ps-recommendation-box ${grp.severity}">
                        <div class="ps-rec-header">
                            <span class="ps-rec-icon">💡</span>
                            <span class="ps-rec-title">Actionable Recommendation</span>
                        </div>
                        <div class="ps-rec-content">
                            ${recsArray.map(r => `<div>${escapeHtml(r)}</div>`).join('')}
                        </div>
                    </div>
                `;
            }

            // Excerpts list (supporting up to 500 characters context snippets)
            let snippetsHtml = '';
            if (grp.snippets.length > 0) {
                snippetsHtml = `
                    <div class="ps-snippets-container">
                        <div class="ps-snippets-header">
                            Detected Policy Excerpts (${grp.snippets.length})
                        </div>
                        <div class="ps-snippets-list">
                            ${grp.snippets.map((snip, idx) => {
                                const formatted = formatSnippet(snip.context, snip.matched, grp.severity);
                                return `
                                    <div class="ps-snippet-card">
                                        ${grp.snippets.length > 1 ? `<div class="ps-snippet-num">Excerpt #${idx + 1}</div>` : ''}
                                        <blockquote class="ps-snippet-quote">${formatted}</blockquote>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    </div>
                `;
            }

            cardsHtml += `
                <div class="ps-match-card ${grp.severity}">
                    <div class="ps-match-card-top">
                        <div class="ps-match-category">
                            ${escapeHtml(grp.category)}
                        </div>
                        <span class="ps-severity-pill ${badgeClass}">
                            ${badgeIcon} ${badgeLabel}
                        </span>
                    </div>
                    ${descHtml}
                    ${recHtml}
                    ${snippetsHtml}
                </div>
            `;
        });
    }

    contentDiv.innerHTML = scoreCardHtml + cardsHtml;
}

// Main function to fetch analysis from backend
async function analyzePolicy() {
    const contentDiv = document.getElementById('ps-content');
    if (contentDiv) {
        contentDiv.innerHTML = `
            <div class="ps-loading">
                <div class="ps-spinner"></div>
                <div class="ps-loading-title">Analyzing Policy Text...</div>
                <p class="ps-loading-sub">Scanning clauses for predatory terms and privacy risks</p>
            </div>
        `;
    }

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
            throw new Error(`Server returned HTTP ${response.status}`);
        }

        const data = await response.json();
        renderReport(data);

    } catch (error) {
        console.error('Policy Safeguard Analysis Error:', error);
        if (contentDiv) {
            contentDiv.innerHTML = `
                <div class="ps-error-state">
                    <div class="ps-error-icon">⚠️</div>
                    <div class="ps-error-title">Analysis Failed</div>
                    <p class="ps-error-msg">Failed to connect to the backend analyzer.</p>
                    <p class="ps-error-sub">Make sure your FastAPI server is running on <code>localhost:8000</code>.</p>
                    <button class="ps-retry-btn" id="ps-retry-btn">Retry Scan</button>
                </div>
            `;
            const retryBtn = document.getElementById('ps-retry-btn');
            if (retryBtn) {
                retryBtn.addEventListener('click', () => {
                    analyzePolicy();
                });
            }
        }
    }
}

// Auto-inject and optionally auto-trigger if on a policy page
if (isPolicyPage()) {
    injectSidebar();
}

// Listen for messages from popup if user clicks manual scan
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scan_now") {
        injectSidebar(); // Ensure sidebar exists
        const sidebar = document.getElementById('policy-safeguard-sidebar');
        if (sidebar) {
            sidebar.classList.add('open');
            document.body.style.overflow = 'hidden';
        }
        analyzePolicy();
        sendResponse({ status: "started" });
    }
});
