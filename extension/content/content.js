// ==========================================================================
// Policy Safeguard v2.0 — Content Script
// Dark Glass UI | Separate AI Analysis Button
// ==========================================================================

// ── Page Detection ──────────────────────────────────────────────────
function isPolicyPage() {
  const url   = window.location.href.toLowerCase();
  const title = document.title.toLowerCase();
  const kws   = ['privacy', 'terms', 'condition', 'policy', 'legal', 'tos', 'gdpr', 'cookie'];
  return kws.some(k => url.includes(k) || title.includes(k));
}

// ── Text Extraction ─────────────────────────────────────────────────
function extractPageText() {
  const clone = document.body.cloneNode(true);
  ['script','style','noscript','nav','footer','header'].forEach(tag => {
    [...clone.getElementsByTagName(tag)].forEach(el => el.remove());
  });
  return clone.innerText.trim();
}

// ── HTML escape ─────────────────────────────────────────────────────
function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

// ── Highlight matched text in snippet ──────────────────────────────
function highlightSnip(snippet, matched, severity) {
  if (!snippet) return '';
  const safe    = escHtml(snippet);
  if (!matched) return safe;
  const esc     = escHtml(matched.trim()).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const cls     = severity === 'red' ? 'ps-highlight-red' : 'ps-highlight-yellow';
  try {
    return safe.replace(new RegExp(`(${esc})`,'i'), `<mark class="${cls}">$1</mark>`);
  } catch {
    return safe;
  }
}

// ── Inject sidebar HTML into page ────────────────────────────────────
function injectSidebar() {
  if (document.getElementById('policy-safeguard-sidebar')) return;

  const sidebar = document.createElement('div');
  sidebar.id = 'policy-safeguard-sidebar';
  sidebar.innerHTML = `
    <div class="ps-header">
      <div class="ps-header-left">
        <div class="ps-logo">🛡️</div>
        <div class="ps-header-text">
          <div class="ps-header-title">Policy Safeguard</div>
          <div class="ps-header-sub">Context-Aware Threat Analyzer</div>
        </div>
      </div>
      <button class="ps-close-btn" id="ps-close" title="Close" aria-label="Close">✕</button>
    </div>

    <div class="ps-content" id="ps-content">
      <div class="ps-loading">
        <div class="ps-spinner"></div>
        <div class="ps-loading-title">Scanning Policy…</div>
        <p class="ps-loading-sub">Running 42+ threat detection rules across 12 risk categories</p>
      </div>
    </div>

    <div class="ps-footer">
      <div class="ps-footer-brand">
        <div class="ps-live-dot"></div>
        Policy Safeguard v2.0
      </div>
      <div class="ps-url-chip" id="ps-url-chip">${escHtml(window.location.hostname)}</div>
    </div>
  `;
  document.body.appendChild(sidebar);

  // Floating trigger button
  const btn = document.createElement('button');
  btn.id = 'policy-safeguard-trigger';
  btn.innerHTML = `<span class="ps-btn-icon">🛡️</span><span>Analyze Policy</span>`;
  document.body.appendChild(btn);

  // Close
  document.getElementById('ps-close').addEventListener('click', () => {
    sidebar.classList.remove('open');
    document.body.style.overflow = '';
  });

  // Open + scan
  btn.addEventListener('click', () => {
    sidebar.classList.add('open');
    document.body.style.overflow = 'hidden';
    analyzePolicy();
  });
}

// ── Render the risk report ────────────────────────────────────────────
function renderReport(report) {
  const contentDiv = document.getElementById('ps-content');
  if (!contentDiv) return;

  const lvl   = report.risk_level || 'safe';
  const score = report.overall_risk_score || 0;
  const sc    = report.severity_counts || {};
  const redN  = sc.red || 0;
  const yelN  = sc.yellow || 0;
  const grnN  = sc.green || 0;

  // Score ring math: circumference=283, fill based on score
  const offset = Math.round(283 - (score / 100) * 283);

  // Headline text based on level
  const headlines = {
    safe:      '✅ Looks Safe',
    caution:   '⚠️ Caution Advised',
    dangerous: '🚨 High Risk Detected',
  };
  const taglines = {
    safe:      'No major threats found. Review below for minor notes.',
    caution:   'Some concerning clauses detected. Read before agreeing.',
    dangerous: 'Critical predatory clauses found. Do NOT agree blindly.',
  };

  // ── Score Section ────────────────────────────────────────────────
  const scoreHtml = `
    <div class="ps-score-section ${lvl}">
      <div class="ps-ring-wrap">
        <svg width="108" height="108" viewBox="0 0 108 108">
          <circle class="ps-ring-bg" cx="54" cy="54" r="45"/>
          <circle class="ps-ring-fill ${lvl}" cx="54" cy="54" r="45"
            id="ps-score-ring"
            style="stroke-dashoffset: ${offset}"/>
        </svg>
        <div class="ps-ring-center">
          <div class="ps-ring-num ${lvl}">${score}</div>
          <div class="ps-ring-of">/100</div>
        </div>
      </div>

      <div class="ps-score-right">
        <div class="ps-risk-badge ${lvl}">
          ${lvl === 'safe' ? '● Safe' : lvl === 'caution' ? '⚠ Caution' : '⛔ Dangerous'}
        </div>
        <div class="ps-score-headline">${headlines[lvl] || 'Analysis Complete'}</div>
        <div class="ps-score-tagline">${taglines[lvl] || ''}</div>
        <div class="ps-pills">
          ${redN > 0 ? `<div class="ps-pill red"><span class="ps-pill-dot"></span>${redN} Critical</div>` : ''}
          ${yelN > 0 ? `<div class="ps-pill yellow"><span class="ps-pill-dot"></span>${yelN} Warning</div>` : ''}
          ${grnN > 0 ? `<div class="ps-pill green"><span class="ps-pill-dot"></span>${grnN} Info</div>` : ''}
          ${(redN + yelN + grnN) === 0 ? `<div class="ps-pill green"><span class="ps-pill-dot"></span>All Clear</div>` : ''}
        </div>
      </div>
    </div>
  `;

  // ── AI Analysis Card ────────────────────────────────────────────
  const pageText = extractPageText();
  const aiCardHtml = `
    <div class="ps-ai-card">
      <div class="ps-ai-card-head">
        <div class="ps-ai-card-left">
          <div class="ps-ai-icon">✨</div>
          <div>
            <div class="ps-ai-title">AI Policy Lawyer</div>
            <div class="ps-ai-sub">Powered by Google Gemini</div>
          </div>
        </div>
        <span class="ps-ai-beta">AI</span>
      </div>
      <div class="ps-ai-body">
        <button class="ps-ai-analyze-btn" id="ps-ai-btn">
          <span class="ps-ai-btn-sparkle">✨</span>
          <span>Analyze with AI — Get Plain English Summary</span>
        </button>
        <div class="ps-ai-thinking" id="ps-ai-thinking">
          <div class="ps-ai-dots"><span></span><span></span><span></span></div>
          <span>AI is reading the policy…</span>
        </div>
        <div class="ps-ai-result" id="ps-ai-result">
          <div class="ps-ai-result-label">🤖 AI Analysis</div>
          <div class="ps-ai-result-text" id="ps-ai-result-text"></div>
        </div>
      </div>
    </div>
  `;

  // ── Threat Cards (grouped by category) ──────────────────────────
  let cardsHtml = '';
  const matches = report.matches || [];

  if (matches.length === 0) {
    cardsHtml = `
      <div class="ps-empty">
        <div class="ps-empty-icon">✅</div>
        <div class="ps-empty-title">No Threats Detected</div>
        <div class="ps-empty-desc">No high or moderate risk clauses identified. This policy appears relatively standard and safe.</div>
      </div>
    `;
  } else {
    // Group by category
    const groups = {};
    matches.forEach(m => {
      const cat = m.category || 'Unknown';
      if (!groups[cat]) groups[cat] = { category: cat, severity: m.severity, descriptions: new Set(), recommendations: new Set(), snippets: [] };
      if (m.severity === 'red') groups[cat].severity = 'red';
      if (m.description)    groups[cat].descriptions.add(m.description);
      if (m.recommendation) groups[cat].recommendations.add(m.recommendation);
      const snipText = m.context_snippet || m.matched_text;
      if (snipText && !groups[cat].snippets.some(s => s.ctx === snipText)) {
        groups[cat].snippets.push({ ctx: snipText, matched: m.matched_text || '' });
      }
    });

    const sevOrder = { red: 0, yellow: 1, green: 2 };
    const sorted   = Object.values(groups).sort((a,b) => (sevOrder[a.severity]??9) - (sevOrder[b.severity]??9));
    const totalClauses = sorted.reduce((s,g) => s + g.snippets.length, 0);

    const sectionBar = `
      <div class="ps-section-bar">
        <div class="ps-section-label">🔍 Detected Threats</div>
        <div class="ps-section-count">${totalClauses} clauses · ${sorted.length} categories</div>
      </div>
    `;

    const cards = sorted.map((grp, idx) => {
      const isRed  = grp.severity === 'red';
      const sevCls = isRed ? 'ps-sev-red' : grp.severity === 'green' ? 'ps-sev-green' : 'ps-sev-yellow';
      const sevLabel = isRed ? '⛔ Critical Risk' : grp.severity === 'green' ? '✅ Info' : '⚠️ Warning';

      const descHtml = [...grp.descriptions].map(d => `<div class="ps-card-desc">${escHtml(d)}</div>`).join('');

      const recHtml = grp.recommendations.size > 0 ? `
        <div class="ps-rec-box ${grp.severity}">
          <div class="ps-rec-label">💡 Recommendation</div>
          ${[...grp.recommendations].map(r => `<div>${escHtml(r)}</div>`).join('')}
        </div>
      ` : '';

      const snippetsHtml = grp.snippets.length > 0 ? `
        <div class="ps-snip-head">📄 Policy Excerpts (${grp.snippets.length})</div>
        ${grp.snippets.map((s, i) => `
          <blockquote class="ps-snippet-quote">
            ${grp.snippets.length > 1 ? `<small style="opacity:.5;font-size:10px">Excerpt ${i+1}</small><br>` : ''}
            ${highlightSnip(s.ctx, s.matched, grp.severity)}
          </blockquote>
        `).join('')}
      ` : '';

      return `
        <div class="ps-match-card ${grp.severity}" style="animation-delay:${idx * 60}ms">
          <div class="ps-card-inner">
            <div class="ps-card-top">
              <div class="ps-card-cat">${escHtml(grp.category)}</div>
              <span class="ps-sev-pill ${sevCls}">${sevLabel}</span>
            </div>
            ${descHtml}${recHtml}${snippetsHtml}
          </div>
        </div>
      `;
    }).join('');

    cardsHtml = `${sectionBar}<div class="ps-cards-list">${cards}</div>`;
  }

  // ── Assemble ─────────────────────────────────────────────────────
  contentDiv.innerHTML = scoreHtml + aiCardHtml + cardsHtml;

  // Animate score ring after render
  requestAnimationFrame(() => {
    const ring = document.getElementById('ps-score-ring');
    if (ring) {
      ring.style.transition = 'stroke-dashoffset 1.6s cubic-bezier(.16,1,.3,1)';
      ring.style.strokeDashoffset = String(offset);
    }
  });

  // ── AI Button handler ────────────────────────────────────────────
  const aiBtn      = document.getElementById('ps-ai-btn');
  const aiThinking = document.getElementById('ps-ai-thinking');
  const aiResult   = document.getElementById('ps-ai-result');
  const aiResText  = document.getElementById('ps-ai-result-text');

  if (aiBtn) {
    aiBtn.addEventListener('click', async () => {
      aiBtn.disabled = true;
      aiBtn.style.display = 'none';
      aiThinking.classList.add('active');

      try {
        const resp = await fetch('http://localhost:8000/ai-summary', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: pageText.substring(0, 50000) }),
        });

        if (!resp.ok) throw new Error(`Server error ${resp.status}`);
        const data = await resp.json();
        aiThinking.classList.remove('active');
        aiResText.textContent = data.summary || 'AI could not generate a summary.';
        aiResult.classList.add('visible');
      } catch (err) {
        aiThinking.classList.remove('active');
        aiResText.textContent = `⚠️ AI request failed: ${err.message}. Make sure your backend is running and GEMINI_API_KEY is set.`;
        aiResult.classList.add('visible');
        // Show button again for retry
        aiBtn.disabled = false;
        aiBtn.style.display = 'flex';
        aiBtn.innerHTML = `<span class="ps-ai-btn-sparkle">🔄</span><span>Retry AI Analysis</span>`;
      }
    });
  }
}

// ── Main analyze function ─────────────────────────────────────────────
async function analyzePolicy() {
  const contentDiv = document.getElementById('ps-content');
  if (contentDiv) {
    contentDiv.innerHTML = `
      <div class="ps-loading">
        <div class="ps-spinner"></div>
        <div class="ps-loading-title">Scanning Policy…</div>
        <p class="ps-loading-sub">Running 42+ threat detection rules across 12 risk categories</p>
      </div>
    `;
  }

  const text        = extractPageText();
  const payloadText = text.length > 50000 ? text.substring(0, 50000) : text;

  try {
    const response = await fetch('http://localhost:8000/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: payloadText, url: window.location.href }),
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    renderReport(data);

  } catch (error) {
    console.error('[PolicySafeguard] Error:', error);
    if (contentDiv) {
      contentDiv.innerHTML = `
        <div class="ps-error">
          <div class="ps-error-icon">⚡</div>
          <div class="ps-error-title">Connection Failed</div>
          <div class="ps-error-msg">Could not reach the analyzer backend.</div>
          <div class="ps-error-code">localhost:8000 — ${escHtml(error.message)}</div>
          <p class="ps-error-msg" style="font-size:11px">Make sure your FastAPI server is running:<br>
            <code style="font-size:10px;color:rgba(255,255,255,.3)">uvicorn app.main:app --reload</code>
          </p>
          <button class="ps-retry-btn" id="ps-retry">↺ Retry</button>
        </div>
      `;
      document.getElementById('ps-retry')?.addEventListener('click', analyzePolicy);
    }
  }
}

// ── Auto-inject on policy pages ──────────────────────────────────────
if (isPolicyPage()) {
  injectSidebar();
}

// ── Listen for manual scan from popup ────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scan_now') {
    injectSidebar();
    const sidebar = document.getElementById('policy-safeguard-sidebar');
    if (sidebar) {
      sidebar.classList.add('open');
      document.body.style.overflow = 'hidden';
    }
    analyzePolicy();
    sendResponse({ status: 'started' });
  }
});
