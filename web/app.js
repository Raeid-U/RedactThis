'use strict';

const presets = {
  light: { max: 25000, help: 'Uses less memory and returns sooner on lightweight machines.' },
  balanced: { max: 100000, help: 'Suitable for stack traces, emails, and messages.' },
  large: { max: 250000, help: 'Supports very large pastes, with longer processing time.' }
};

const input = document.querySelector('#input');
const output = document.querySelector('#output');
const preset = document.querySelector('#preset');
const inputCount = document.querySelector('#input-count');
const presetHelp = document.querySelector('#preset-help');
const redactButton = document.querySelector('#redact');
const clearButton = document.querySelector('#clear');
const copyButton = document.querySelector('#copy');
const resultStatus = document.querySelector('#result-status');
const modelStatus = document.querySelector('#model-status');
const summary = document.querySelector('#summary');
const findings = document.querySelector('#findings');

function charCount(value) { return Array.from(value).length; }

function updateCount() {
  const option = presets[preset.value];
  const count = charCount(input.value);
  inputCount.textContent = `${count.toLocaleString()} / ${option.max.toLocaleString()}`;
  inputCount.style.color = count > option.max ? 'var(--danger)' : '';
  presetHelp.textContent = option.help;
}

function setBusy(busy) {
  redactButton.disabled = busy;
  clearButton.disabled = busy;
  preset.disabled = busy;
  input.readOnly = busy;
  if (busy) copyButton.disabled = true;
}

function resetResult() {
  output.value = '';
  copyButton.disabled = true;
  summary.replaceChildren();
  findings.replaceChildren();
  resultStatus.className = 'status';
}

function renderSummary(counts, chunks) {
  summary.replaceChildren();
  for (const [category, count] of Object.entries(counts || {}).sort()) {
    const item = document.createElement('span');
    item.textContent = `${category.replaceAll('_', ' ')}: ${count}`;
    summary.append(item);
  }
  const processed = document.createElement('span');
  processed.textContent = `${chunks} model chunk${chunks === 1 ? '' : 's'} processed`;
  summary.append(processed);
}

function renderFindings(items) {
  findings.replaceChildren();
  items.forEach((item, index) => {
    const button = document.createElement('button');
    button.className = 'finding';
    button.type = 'button';
    button.textContent = item.start >= 0 ? `${item.category.replaceAll('_', ' ')} · location ${index + 1}` : `${item.category.replaceAll('_', ' ')} · location unavailable`;
    if (item.start >= 0) {
      button.addEventListener('click', () => {
        output.focus();
        output.setSelectionRange(item.start, item.end);
      });
    } else {
      button.disabled = true;
    }
    findings.append(button);
  });
}

async function redact() {
  resetResult();
  const count = charCount(input.value);
  if (!count) {
    resultStatus.className = 'status error';
    resultStatus.textContent = 'Paste some text before running redaction.';
    input.focus();
    return;
  }
  if (count > presets[preset.value].max) {
    resultStatus.className = 'status error';
    resultStatus.textContent = 'The text exceeds the selected size. Choose a larger preset or shorten it.';
    return;
  }

  setBusy(true);
  resultStatus.className = 'status';
  resultStatus.textContent = 'Running deterministic redaction and two local model passes…';
  try {
    const response = await fetch('/api/redact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: input.value, sizePreset: preset.value })
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 422 && data.status === 'review_required') {
      output.value = data.text;
      renderSummary(data.counts, data.chunksProcessed);
      renderFindings(data.findings || []);
      resultStatus.className = 'status warning';
      resultStatus.textContent = 'Verification found possible sensitive data. Review the marked locations, edit the original, and run again. Copy remains disabled.';
      return;
    }
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    output.value = data.text;
    copyButton.disabled = false;
    renderSummary(data.counts, data.chunksProcessed);
    resultStatus.className = 'status success';
    resultStatus.textContent = 'Verified: both redaction passes completed without finding remaining sensitive data.';
  } catch (error) {
    resultStatus.className = 'status error';
    resultStatus.textContent = error instanceof Error ? error.message : 'Redaction failed.';
  } finally {
    setBusy(false);
  }
}

async function checkStatus() {
  try {
    const response = await fetch('/api/status');
    const data = await response.json();
    if (!response.ok) throw new Error();
    modelStatus.className = 'badge ready';
    modelStatus.textContent = `${data.model} · ${data.backend.toUpperCase()} · ready`;
    redactButton.disabled = false;
  } catch {
    modelStatus.className = 'badge error';
    modelStatus.textContent = 'Local model unavailable';
    redactButton.disabled = true;
  }
}

input.addEventListener('input', updateCount);
preset.addEventListener('change', updateCount);
redactButton.addEventListener('click', redact);
clearButton.addEventListener('click', () => {
  input.value = '';
  resetResult();
  updateCount();
  resultStatus.textContent = 'Ready. Your text is processed by the self-hosted service only.';
  input.focus();
});
copyButton.addEventListener('click', async () => {
  await navigator.clipboard.writeText(output.value);
  copyButton.textContent = 'Copied';
  setTimeout(() => { copyButton.textContent = 'Copy'; }, 1200);
});

updateCount();
checkStatus();
