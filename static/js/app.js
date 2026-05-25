/* ─────────────────────────────────────────────────────────────
 *  E-Health Crypto Simulator — Frontend (Kelompok 7)
 * ───────────────────────────────────────────────────────────── */

/* ── STATE ────────────────────────────────────────── */
const chatHistory = []; // {from:'doctor'|'patient', text, attachment, time}

/* ── INLINE ICONS ─────────────────────────────────── */
const ICONS = {
  check: '<svg class="icon-inline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
  cross: '<svg class="icon-inline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  warn:  '<svg class="icon-inline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  lock:  '<svg class="icon-inline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  shield:'<svg class="icon-inline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
};

/* ── TAB NAVIGATION ───────────────────────────────── */
function switchTab(name) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
  });
  document.getElementById('tab-' + name).classList.add('active');
  const btn = document.getElementById('btn-' + name);
  btn.classList.add('active');
  btn.setAttribute('aria-selected', 'true');
}

/* ── KEY DISPLAY ──────────────────────────────────── */
async function loadKeyPreview() {
  try {
    const r = await fetch('/api/key_preview');
    const d = await r.json();
    setKeyDisplay(d.last5);
  } catch (e) {
    setKeyDisplay('?????');
  }
}
function setKeyDisplay(last5) {
  document.getElementById('keyLast5').textContent = last5 || '?????';
}
async function resetKey() {
  const display = document.getElementById('keyLast5');
  display.textContent = '...';
  try {
    const r = await fetch('/api/reset_key', { method: 'POST' });
    const d = await r.json();
    setKeyDisplay(d.last5);
  } catch (e) {
    setKeyDisplay('ERR');
    alert('Reset key gagal: ' + e.message);
  }
}

/* ── MITM TOGGLE ──────────────────────────────────── */
function onMitmToggle() {
  const on = document.getElementById('mitmToggle').checked;
  document.getElementById('mitmPanel').classList.toggle('open', on);
}

/* ─────────────────────────────────────────────────────────────
 *  CHAT
 * ───────────────────────────────────────────────────────────── */

function renderChat() {
  const doctorBody = document.getElementById('chatDoctor');
  const patientBody = document.getElementById('chatPatient');
  doctorBody.innerHTML = '';
  patientBody.innerHTML = '';

  if (chatHistory.length === 0) {
    doctorBody.innerHTML = emptyChatHTML('Belum ada pesan. Kirim resep atau teks ke pasien.');
    patientBody.innerHTML = emptyChatHTML('Menunggu pesan dari dokter...');
    return;
  }

  chatHistory.forEach(msg => {
    // Failed messages only appear in the sender's history
    if (!msg.failed || msg.from === 'doctor')  doctorBody.appendChild(buildMsgRow(msg, 'doctor'));
    if (!msg.failed || msg.from === 'patient') patientBody.appendChild(buildMsgRow(msg, 'patient'));
  });

  doctorBody.scrollTop = doctorBody.scrollHeight;
  patientBody.scrollTop = patientBody.scrollHeight;
}

function emptyChatHTML(text) {
  return `<div class="chat-empty">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
    </svg>
    <span>${text}</span>
  </div>`;
}

const FAILURE_REASON = {
  mac_failed:    'Auth Tag tidak cocok (MITM)',
  hash_mismatch: 'Hash tidak cocok (integritas gagal)'
};

function buildMsgRow(msg, viewer) {
  const isSelf = msg.from === viewer;
  const row = document.createElement('div');
  row.className = 'msg-row ' + (isSelf ? 'self' : 'other');

  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';
  if (msg.failed) bubble.classList.add('msg-failed');

  let html = '';
  if (msg.attachment) {
    html += buildAttachCard(msg.attachment);
  }
  if (msg.text) {
    html += `<div>${escapeHTML(msg.text)}</div>`;
  }
  const time = msg.time || '—';
  const status = msg.failed
    ? `<span class="with-icon">${ICONS.warn} Tidak terkirim · ${FAILURE_REASON[msg.error] || 'verifikasi gagal'}</span>`
    : `<span class="with-icon">${ICONS.check} Terenkripsi</span>`;
  html += `<div class="msg-meta">${time} ${status}</div>`;

  bubble.innerHTML = html;
  row.appendChild(bubble);
  return row;
}

function buildAttachCard(a) {
  return `<div class="attach-card">
    <div class="attach-card-title">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
        <polyline points="14 2 14 8 20 8"/>
      </svg>
      Resep Medis
    </div>
    <div class="attach-row"><span class="k">Pasien:</span><span class="v">${escapeHTML(a.pasien)}</span></div>
    <div class="attach-row"><span class="k">Diagnosis:</span><span class="v">${escapeHTML(a.diagnosis)}</span></div>
    <div class="attach-row"><span class="k">Obat:</span><span class="v">${escapeHTML(a.obat)}</span></div>
    <div class="attach-row"><span class="k">Dosis:</span><span class="v">${escapeHTML(a.dosis)}</span></div>
    <div class="attach-row"><span class="k">Durasi:</span><span class="v">${escapeHTML(a.durasi)}</span></div>
  </div>`;
}

function escapeHTML(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function currentTime() {
  const d = new Date();
  return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
}

function clearChat() {
  chatHistory.length = 0;
  renderChat();
  clearActivityLog();
}

/* ── BUILD MESSAGE PAYLOAD ───────────────────────── */
function buildPayloadText(text, attachment) {
  if (!attachment) return text || '';
  const parts = [
    '[RESEP MEDIS]',
    `Pasien: ${attachment.pasien}`,
    `Diagnosis: ${attachment.diagnosis}`,
    `Obat: ${attachment.obat}`,
    `Dosis: ${attachment.dosis}`,
    `Durasi: ${attachment.durasi}`,
  ];
  if (text) parts.push(`Catatan: ${text}`);
  return parts.join('. ');
}

/* ── SEND MESSAGE ─────────────────────────────────── */
async function sendMessage(from, text, attachment) {
  if (!text && !attachment) return;

  const payloadText = buildPayloadText(text, attachment);
  const payload = {
    message: payloadText,
    mitm_enabled: document.getElementById('mitmToggle').checked,
    mitm_byte_pos: parseInt(document.getElementById('mitmSlider').value) || 30,
    tamper_hash: document.getElementById('tamperToggle').checked
  };

  clearActivityLog();
  setSendButtonsDisabled(true);

  try {
    const resp = await fetch('/process', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await resp.json();

    // Animate activity log
    const list = document.getElementById('stepList');
    const ph = document.getElementById('stepPlaceholder');
    if (ph) ph.remove();

    let delay = 0;
    for (const step of data.steps) {
      delay += step.delay_ms || 250;
      setTimeout(() => {
        list.appendChild(buildStepEl(step));
        list.parentElement.scrollTop = list.parentElement.scrollHeight;
      }, delay);
    }

    setTimeout(() => {
      chatHistory.push({
        from,
        text: text || null,
        attachment: attachment || null,
        time: currentTime(),
        failed: !data.result.is_valid,
        error: data.result.error || null
      });
      renderChat();
      setSendButtonsDisabled(false);
    }, delay + 200);

  } catch (err) {
    setSendButtonsDisabled(false);
    alert('Error: ' + err.message);
  }
}

function setSendButtonsDisabled(disabled) {
  document.getElementById('btnDoctorSend').disabled = disabled;
  document.getElementById('btnDoctorAttach').disabled = disabled;
  document.getElementById('btnPatientSend').disabled = disabled;
}

/* ── DOCTOR / PATIENT SEND BUTTONS ───────────────── */
function onDoctorSend() {
  const ta = document.getElementById('doctorInput');
  const text = ta.value.trim();
  if (!text) return;
  ta.value = '';
  sendMessage('doctor', text, null);
}
function onPatientSend() {
  const ta = document.getElementById('patientInput');
  const text = ta.value.trim();
  if (!text) return;
  ta.value = '';
  sendMessage('patient', text, null);
}

/* ── ATTACH MODAL ─────────────────────────────────── */
function openAttachModal() {
  document.getElementById('attachModal').classList.add('open');
  document.getElementById('attachPasien').focus();
}
function closeAttachModal() {
  document.getElementById('attachModal').classList.remove('open');
}
function submitAttach(ev) {
  if (ev) ev.preventDefault();
  const a = {
    pasien:    document.getElementById('attachPasien').value.trim(),
    diagnosis: document.getElementById('attachDiagnosis').value.trim(),
    obat:      document.getElementById('attachObat').value.trim(),
    dosis:     document.getElementById('attachDosis').value.trim(),
    durasi:    document.getElementById('attachDurasi').value.trim()
  };
  if (!a.pasien || !a.diagnosis || !a.obat || !a.dosis || !a.durasi) {
    alert('Semua field resep wajib diisi.');
    return;
  }
  const note = document.getElementById('attachNote').value.trim();
  closeAttachModal();
  // reset form
  document.getElementById('attachForm').reset();
  sendMessage('doctor', note || '', a);
}

/* ── ACTIVITY LOG ─────────────────────────────────── */
function clearActivityLog() {
  const list = document.getElementById('stepList');
  list.innerHTML = `<div class="step-placeholder" id="stepPlaceholder">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
    <span>Kirim pesan untuk melihat proses kriptografi...</span>
  </div>`;
}
function buildStepEl(step) {
  const el = document.createElement('div');
  el.className = 'step-item ' + step.type;
  let detailHTML = '';
  if (step.detail) {
    detailHTML = '<div class="step-details">';
    for (const [k, v] of Object.entries(step.detail)) {
      detailHTML += `<span><span class="step-key">${escapeHTML(k)}:</span>${escapeHTML(v)}</span>`;
    }
    detailHTML += '</div>';
  }
  el.innerHTML = `<div class="step-badge ${step.type}">${step.type}</div>
    <div class="step-title">${escapeHTML(step.title)}</div>${detailHTML}`;
  return el;
}

/* ─────────────────────────────────────────────────────────────
 *  SECURITY TESTS (Tab 2 & 3)
 * ───────────────────────────────────────────────────────────── */
const TEST_CONFIG = {
  sha3:            { url: '/api/test/avalanche_sha3',  btn: 'btnSha3', spn: 'spnSha3', res: 'resSha3',  render: renderAvalanche.bind(null, 'Sha3', 256) },
  aes:             { url: '/api/test/avalanche_aes',   btn: 'btnAes',  spn: 'spnAes',  res: 'resAes',   render: renderAvalanche.bind(null, 'Aes', 128) },
  collision:       { url: '/api/test/collision',       btn: 'btnCol',  spn: 'spnCol',  res: 'resCol',   render: renderCollision },
  performance:     { url: '/api/test/performance',     btn: 'btnPerf', spn: 'spnPerf', res: 'resPerf',  render: renderPerfTable },
  hash_throughput: { url: '/api/test/hash_throughput', btn: 'btnThr',  spn: 'spnThr',  res: 'resThr',   render: renderThroughputTable }
};

function getTestPayload(name) {
  if (name === 'sha3')            return { iterations: parseInt(document.getElementById('sha3Iter').value) || 100 };
  if (name === 'aes')             return { iterations: parseInt(document.getElementById('aesIter').value)  || 100 };
  if (name === 'collision')       return { pairs:      parseInt(document.getElementById('colPairs').value) || 1000 };
  if (name === 'hash_throughput') return { repeats:    parseInt(document.getElementById('thrRepeats').value) || 100 };
  return {};
}

async function runTest(name) {
  const cfg = TEST_CONFIG[name];
  if (!cfg) return;
  const btn = document.getElementById(cfg.btn);
  const spn = document.getElementById(cfg.spn);
  btn.disabled = true;
  spn.classList.add('active');
  try {
    const resp = await fetch(cfg.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(getTestPayload(name))
    });
    const data = await resp.json();
    document.getElementById(cfg.res).classList.add('visible');
    cfg.render(data);
  } catch (e) {
    alert('Pengujian gagal: ' + e.message);
  } finally {
    btn.disabled = false;
    spn.classList.remove('active');
  }
}

/* ── RENDER AVALANCHE ────────────────────────────── */
function renderAvalanche(suffix, totalBits, data) {
  const mean = data.mean ?? 0;
  const std  = data.std  ?? 0;
  const mn   = data.min  ?? 0;
  const mx   = data.max  ?? 0;
  const N    = data.iterations ?? (data.distribution ? data.distribution.length : 0);
  const sac  = (mean >= 45 && mean <= 55);

  const badge = document.getElementById('badge' + suffix);
  badge.innerHTML = sac
    ? `<span class="with-icon">SAC PASS ${ICONS.check}</span>`
    : `<span class="with-icon">SAC FAIL ${ICONS.cross}</span>`;
  badge.className   = 'test-status-badge ' + (sac ? 'pass' : 'fail');

  document.getElementById('stats' + suffix).innerHTML =
    stat('Mean', mean.toFixed(2) + '%') +
    stat('Std Dev', std.toFixed(2) + '%') +
    stat('Min / Max', mn.toFixed(1) + ' / ' + mx.toFixed(1) + '%');

  // Histogram
  const hist = document.getElementById('hist' + suffix);
  hist.innerHTML = '';
  const dist = data.distribution || [];
  if (dist.length > 0) {
    const lo = Math.min(...dist), hi = Math.max(...dist);
    const bins = 12;
    const counts = new Array(bins).fill(0);
    dist.forEach(v => {
      const i = Math.min(bins - 1, Math.floor(((v - lo) / (hi - lo + 0.001)) * bins));
      counts[i]++;
    });
    const maxC = Math.max(...counts, 1);
    counts.forEach(c => {
      const bar = document.createElement('div');
      bar.className = 'hbar';
      bar.style.height = Math.max(4, Math.round((c / maxC) * 56)) + 'px';
      bar.title = c + ' iterasi';
      hist.appendChild(bar);
    });
  }

  // Computation trace
  const trace = document.getElementById('trace' + suffix);
  const exampleVal = dist[0] != null ? dist[0] : mean;
  const exampleBits = Math.round((exampleVal / 100) * totalBits);
  const expandedSum = (mean * N).toFixed(2);
  trace.innerHTML = `
    <div class="ctitle">Perhitungan</div>
    <div>N (iterasi)   = ${N}</div>
    <div>Total bit out = ${totalBits} bit</div>
    <div>Contoh iter 1 : changed = ${exampleBits} bit  →  ${exampleBits}/${totalBits} × 100% = <code>${exampleVal.toFixed(2)}%</code></div>
    <div>Σ percentage  ≈ ${expandedSum}</div>
    <div>mean          = Σ / N = ${expandedSum} / ${N} = <code>${mean.toFixed(2)}%</code></div>
    <div>std           = √(Σ(xᵢ − mean)² / N) = <code>${std.toFixed(2)}%</code></div>
    <div>SAC criterion : 45% ≤ mean ≤ 55%  →  <code>${sac ? 'LULUS' : 'GAGAL'}</code></div>
  `;
  trace.style.display = 'block';
}

function stat(label, val) {
  return `<div class="test-stat"><div class="ts-label">${label}</div><div class="ts-val">${val}</div></div>`;
}
function statHTML(label, htmlVal) {
  return `<div class="test-stat"><div class="ts-label">${label}</div><div class="ts-val">${htmlVal}</div></div>`;
}

/* ── RENDER COLLISION ─────────────────────────────── */
function renderCollision(data) {
  const collisions = data.collisions ?? 0;
  const pairs      = data.pairs_tested ?? data.pairs ?? 0;
  const unique     = data.unique_hashes ?? pairs;
  const pass       = collisions === 0;

  const badge = document.getElementById('badgeCol');
  badge.innerHTML = pass
    ? `<span class="with-icon">ZERO COLLISION ${ICONS.check}</span>`
    : `<span class="with-icon">${collisions} COLLISION ${ICONS.cross}</span>`;
  badge.className   = 'test-status-badge ' + (pass ? 'pass' : 'fail');

  document.getElementById('statsCol').innerHTML =
    stat('Pasang diuji', pairs) +
    stat('Collision', collisions) +
    statHTML('Status', pass
      ? `<span class="with-icon">${ICONS.check} Aman</span>`
      : `<span class="with-icon">${ICONS.cross} Gagal</span>`);

  // birthday-bound estimate: P ≈ N² / (2 × 2^256)
  // log10(P) ≈ 2 log10(N) − log10(2) − 256 log10(2)
  const log10P = pairs > 0
    ? (2 * Math.log10(pairs) - Math.log10(2) - 256 * Math.log10(2))
    : 0;
  const probStr = pairs > 0 ? `≈ 10^${log10P.toFixed(1)}` : '—';

  const trace = document.getElementById('traceCol');
  trace.innerHTML = `
    <div class="ctitle">Perhitungan</div>
    <div>N (pasang)        = ${pairs}</div>
    <div>Unique hash       = ${unique}</div>
    <div>Collision count   = ${collisions}</div>
    <div>Birthday bound    = N² / (2 · 2²⁵⁶)</div>
    <div>                  = ${pairs}² / (2 · 2²⁵⁶) <code>${probStr}</code></div>
    <div>Status            = (collision == 0) → <code>${pass ? 'AMAN' : 'GAGAL'}</code></div>
  `;
  trace.style.display = 'block';
}

/* ── RENDER PERFORMANCE TABLE ─────────────────────── */
function renderPerfTable(data) {
  const rows = data.results || [];
  if (!rows.length) return;
  let html = '<table class="data-table"><thead><tr><th>Ukuran (char)</th><th>Enc (ms)</th><th>Dec (ms)</th><th>Throughput (MB/s)</th><th>Status</th></tr></thead><tbody>';
  rows.forEach(r => {
    const ok = (r.enc_ms ?? 0) < 5;
    const pill = ok
      ? `<span class="pass-pill ok"><span class="with-icon">${ICONS.check} &lt; 5 ms</span></span>`
      : `<span class="pass-pill fail"><span class="with-icon">${ICONS.cross} &gt; 5 ms</span></span>`;
    html += `<tr>
      <td>${r.size ?? '—'}</td>
      <td>${(r.enc_ms ?? 0).toFixed(3)}</td>
      <td>${(r.dec_ms ?? 0).toFixed(3)}</td>
      <td>${(r.throughput_mbs ?? 0).toFixed(2)}</td>
      <td>${pill}</td>
    </tr>`;
  });
  html += '</tbody></table>';
  document.getElementById('tablePerfWrap').innerHTML = html;

  // sample trace from first row
  const r0 = rows[0];
  const trace = document.getElementById('tracePerf');
  trace.innerHTML = `
    <div class="ctitle">Perhitungan</div>
    <div>R (repeats)   = ${data.repeats}</div>
    <div>Contoh size   = ${r0.size} byte</div>
    <div>enc_ms        = (1/R) · Σᵢ encᵢ(ms) = <code>${r0.enc_ms.toFixed(3)} ms</code></div>
    <div>dec_ms        = (1/R) · Σᵢ decᵢ(ms) = <code>${r0.dec_ms.toFixed(3)} ms</code></div>
    <div>size_MB       = ${r0.size} / (1024·1024) = ${(r0.size / (1024*1024)).toExponential(2)} MB</div>
    <div>throughput    = size_MB / (enc_ms / 1000) = <code>${r0.throughput_mbs.toFixed(2)} MB/s</code></div>
    <div>Kriteria      = enc_ms < 5 ms → <code>${r0.enc_ms < 5 ? 'LULUS' : 'GAGAL'}</code></div>
  `;
  trace.style.display = 'block';
  document.getElementById('resPerf').classList.add('visible');
}

/* ── RENDER THROUGHPUT TABLE ──────────────────────── */
function renderThroughputTable(data) {
  const rows = data.results || [];
  if (!rows.length) return;
  let html = '<table class="data-table"><thead><tr><th>Ukuran (KB)</th><th>Waktu (ms)</th><th>Throughput (MB/s)</th><th>Status</th></tr></thead><tbody>';
  rows.forEach(r => {
    const ok = (r.throughput_mbs ?? 0) > 50;
    const pill = ok
      ? `<span class="pass-pill ok">${ICONS.check}</span>`
      : `<span class="pass-pill fail">${ICONS.cross}</span>`;
    html += `<tr>
      <td>${r.size_kb ?? '—'}</td>
      <td>${(r.time_ms ?? 0).toFixed(3)}</td>
      <td>${(r.throughput_mbs ?? 0).toFixed(2)}</td>
      <td>${pill}</td>
    </tr>`;
  });
  html += '</tbody></table>';
  document.getElementById('tableThrWrap').innerHTML = html;

  const r0 = rows[0];
  const trace = document.getElementById('traceThr');
  trace.innerHTML = `
    <div class="ctitle">Perhitungan</div>
    <div>R (repeats)    = ${data.repeats}</div>
    <div>Contoh size    = ${r0.size_kb} KB</div>
    <div>mean_time_s    = (1/R) · Σᵢ tᵢ(s) = <code>${(r0.time_ms / 1000).toExponential(2)} s</code></div>
    <div>size_MB        = ${r0.size_kb} / 1024 = ${(r0.size_kb / 1024).toFixed(4)} MB</div>
    <div>throughput     = size_MB / mean_time_s = <code>${r0.throughput_mbs.toFixed(2)} MB/s</code></div>
    <div>Kriteria       = throughput > 50 MB/s → <code>${r0.throughput_mbs > 50 ? 'LULUS' : 'GAGAL'}</code></div>
  `;
  trace.style.display = 'block';
  document.getElementById('resThr').classList.add('visible');
}

/* ── INIT ─────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  loadKeyPreview();
  renderChat();

  // Submit on Enter (no shift) in chat inputs
  document.getElementById('doctorInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onDoctorSend(); }
  });
  document.getElementById('patientInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onPatientSend(); }
  });

  // Close modal on overlay click
  document.getElementById('attachModal').addEventListener('click', (e) => {
    if (e.target.id === 'attachModal') closeAttachModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAttachModal();
  });

  // MITM slider live label
  const mitmSlider = document.getElementById('mitmSlider');
  if (mitmSlider) {
    mitmSlider.addEventListener('input', () => {
      document.getElementById('mitmSliderVal').textContent = mitmSlider.value;
    });
  }
});
