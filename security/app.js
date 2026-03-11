// ── State ──────────────────────────────────────────────────
let current = 0;

// ── Build a VS Code-style editor block ─────────────────────
function buildCodeBlock(ex, phaseColor) {
  // Split raw HTML code into lines (spans never cross line boundaries)
  const rawLines = ex.code.split('\n');
  // Remove trailing empty line if present
  if (rawLines.length && rawLines[rawLines.length - 1].trim() === '') rawLines.pop();

  const totalLines = rawLines.length;
  const padWidth   = String(totalLines).length; // digits needed

  // Build gutter (line numbers)
  const gutterHTML = rawLines.map((_, i) => {
    const n = String(i + 1).padStart(padWidth, ' ');
    return `<span class="vsc-ln">${n}</span>`;
  }).join('');

  // Build code lines (each in a hoverable row)
  const codeHTML = rawLines.map(line =>
    `<span class="cl-row">${line || ' '}</span>`
  ).join('');

  // Detect language for status bar
  const isP = ex.file.endsWith('.py');
  const langLabel = isP ? '🐍 Python' : ex.lang;
  const fileIcon  = isP ? '🐍' : '📄';

  return `
  <div class="code-block">
    <!-- Window chrome -->
    <div class="vsc-chrome">
      <div class="vsc-dot red"></div>
      <div class="vsc-dot yellow"></div>
      <div class="vsc-dot green"></div>
      <div class="vsc-chrome-spacer"></div>
      <div class="vsc-chrome-title">${ex.file}</div>
      <div class="vsc-chrome-spacer"></div>
    </div>

    <!-- Tab bar -->
    <div class="vsc-tabs" style="--phase-color-main:${phaseColor}">
      <div class="vsc-tab">
        <span class="vsc-tab-icon">${fileIcon}</span>
        <span class="vsc-tab-name">${ex.file}</span>
        <span class="vsc-tab-close">×</span>
      </div>
      <div class="vsc-tab-rest"></div>
    </div>

    <!-- Breadcrumb -->
    <div class="vsc-breadcrumb">
      <span>security</span>
      <span>›</span>
      <span>${ex.file}</span>
    </div>

    <!-- Editor: gutter + code -->
    <div class="vsc-editor">
      <div class="vsc-gutter">${gutterHTML}</div>
      <div class="vsc-code-area">
        <pre>${codeHTML}</pre>
      </div>
    </div>

    <!-- Status bar -->
    <div class="vsc-status">
      <div class="vsc-status-left">
        <span class="vsc-status-item">⎇ main</span>
        <span class="vsc-status-item">✓ No problems</span>
      </div>
      <div class="vsc-status-right">
        <span class="vsc-status-item">Ln 1, Col 1</span>
        <span class="vsc-status-item">Spaces: 4</span>
        <span class="vsc-status-item">UTF-8</span>
        <span class="vsc-status-item">LF</span>
        <span class="vsc-status-item">${langLabel}</span>
        <span class="vsc-status-item">${totalLines} lines</span>
      </div>
    </div>
  </div>`;
}

// ── Entry point ────────────────────────────────────────────
function startApp() {
  document.getElementById('hero').style.display = 'none';
  document.getElementById('app').style.display  = 'block';
  renderNav();
  renderPhase(0);
}

// ── Top bar ────────────────────────────────────────────────
function renderTopbar(p) {
  const pct = Math.round((current / (phases.length - 1)) * 100);
  document.getElementById('topbarLabel').textContent = p.label + ' · ' + p.level;
  document.getElementById('topbarTitle').textContent = p.title;
  document.getElementById('topbarFill').style.width  = pct + '%';
  document.getElementById('topbarPct').textContent   = current + ' / ' + (phases.length - 1);
}

// ── Sidebar navigation ─────────────────────────────────────
function renderNav() {
  const nav = document.getElementById('phaseNav');

  const sectionDefs = [
    { label:'FOUNDATION',        test: p => p.id === 0 },
    { label:'7 SECURITY LAYERS', test: p => p.layer >= 1 && p.layer <= 7 },
    { label:'ADVANCED',          test: p => p.id >= 8 },
  ];

  let html = '';
  sectionDefs.forEach(sec => {
    const list = phases.filter(sec.test);
    if (!list.length) return;
    html += `<div class="sidebar-section-label">${sec.label}</div>`;
    list.forEach(p => {
      const i = p.id;
      html += `
        <div class="phase-nav-item ${i === current ? 'active' : ''}"
             style="--phase-color:${p.color}"
             onclick="showPhase(${i})">
          <div class="phase-dot"></div>
          <div class="phase-nav-text">
            <div class="phase-nav-num">${p.label}</div>
            <div class="phase-nav-name">${p.navName}</div>
          </div>
          <div class="phase-nav-badge"
               style="background:${p.color}18;color:${p.color};border:1px solid ${p.color}33">
            ${p.badge}
          </div>
        </div>`;
    });
  });

  nav.innerHTML = html;

  const pct = Math.round((current / (phases.length - 1)) * 100);
  document.getElementById('progFill').style.width    = pct + '%';
  document.getElementById('progText').textContent    = `Phase ${current} of ${phases.length - 1}`;
}

// ── Render a phase ─────────────────────────────────────────
function renderPhase(i) {
  const p       = phases[i];
  const content = document.getElementById('content');
  content.style.setProperty('--phase-color-main', p.color);

  // Update top bar
  renderTopbar(p);

  // Concepts
  const conceptsHTML = p.concepts.map(c => `
    <div class="concept-card">
      <span class="concept-icon">${c.icon}</span>
      <div class="concept-name">${c.name}</div>
      <div class="concept-desc">${c.desc}</div>
    </div>`).join('');

  // Code examples — VS Code style
  const examplesHTML = p.examples.map(ex => buildCodeBlock(ex, p.color)).join('');

  // Steps
  const stepsHTML = p.steps.map((s, idx) => `
    <div class="road-step">
      <div class="road-circle">${idx + 1}</div>
      <div class="road-body">
        <div class="road-title">${s.title}</div>
        <div class="road-desc">${s.desc}</div>
        ${s.install ? `<div class="road-install">$ ${s.install}</div>` : ''}
      </div>
    </div>`).join('');

  // Libraries
  const libsHTML = p.libs.map(l =>
    `<div class="lib-pill"><b>${l.name}</b> — ${l.desc}</div>`).join('');

  const calloutIcon = { info:'ℹ️', warn:'⚠️', danger:'🚨', tip:'💡' };

  // Optional layer tag
  const layerTag = p.layer
    ? `<div class="layer-tag"><b>LAYER ${p.layer}</b>&nbsp;&nbsp;${p.layerDesc}</div>` : '';

  // Phase number (padded)
  const phaseNum = String(i).padStart(2, '0');

  content.innerHTML = `
    <div class="phase-header">
      <div class="phase-header-left">
        <div class="phase-badge">
          <div class="phase-badge-dot"></div>
          ${p.label} &nbsp;·&nbsp; ${p.level}
        </div>
        <h1 class="phase-title">${p.title}</h1>
        <p class="phase-desc">${p.desc}</p>
        <div class="phase-tags">
          ${layerTag}
          <div class="level-tag">${p.level}</div>
        </div>
      </div>
      <div class="phase-number-bg">${phaseNum}</div>
    </div>

    <div class="section-title">Core Concepts</div>
    <div class="concepts-grid">${conceptsHTML}</div>

    <div class="callout ${p.callout.type}">
      <div class="callout-label">${calloutIcon[p.callout.type]} &nbsp;${p.callout.label}</div>
      <p>${p.callout.text}</p>
    </div>

    <div class="section-title">Python Code Examples</div>
    ${examplesHTML}

    <div class="section-title">Learning Roadmap</div>
    <div class="roadmap">${stepsHTML}</div>

    <div class="section-title">Python Libraries</div>
    <div class="libs-wrap">${libsHTML}</div>

    <div class="phase-footer">
      <button class="nav-btn" onclick="showPhase(${i - 1})" ${i === 0 ? 'disabled' : ''}>
        ← ${i > 0 ? phases[i - 1].navName : ''}
      </button>
      <span style="font-size:11px;color:var(--muted);letter-spacing:1px">
        ${i + 1} / ${phases.length}
      </span>
      <button class="nav-btn primary" onclick="showPhase(${i + 1})"
              ${i === phases.length - 1 ? 'disabled' : ''}>
        ${i < phases.length - 1 ? phases[i + 1].navName + ' →' : '🎉 Complete!'}
      </button>
    </div>
  `;

  document.getElementById('sidebar').classList.remove('open');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ── Navigate ───────────────────────────────────────────────
function showPhase(i) {
  if (i < 0 || i >= phases.length) return;
  current = i;
  renderNav();
  renderPhase(i);
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

// ── Sync gutter highlight on code-row hover ────────────────
document.addEventListener('mouseover', e => {
  const row = e.target.closest('.cl-row');
  if (!row) return;
  const pre   = row.closest('pre');
  const area  = row.closest('.vsc-code-area');
  const gutter= area ? area.previousElementSibling : null;
  if (!gutter) return;

  const rows   = Array.from(pre.querySelectorAll('.cl-row'));
  const idx    = rows.indexOf(row);
  const lnSpans= gutter.querySelectorAll('.vsc-ln');

  lnSpans.forEach((s, i) => s.classList.toggle('active-ln', i === idx));
});
document.addEventListener('mouseout', e => {
  const row = e.target.closest('.cl-row');
  if (!row) return;
  const area  = row.closest('.vsc-code-area');
  const gutter= area ? area.previousElementSibling : null;
  if (!gutter) return;
  gutter.querySelectorAll('.vsc-ln').forEach(s => s.classList.remove('active-ln'));
});
