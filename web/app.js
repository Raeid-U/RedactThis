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
const rerunButton = document.querySelector('#rerun');
const cancelButton = document.querySelector('#cancel');
const resultStatus = document.querySelector('#result-status');
const progress = document.querySelector('#progress');
const modelStatus = document.querySelector('#model-status');
const summary = document.querySelector('#summary');
const findings = document.querySelector('#findings');
let activeController = null;
let elapsedTimer = null;
let startedAt = 0;
let resultIsPartial = false;
let copyConfirmationExpires = 0;

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
  cancelButton.hidden = !busy;
  progress.classList.toggle('active', busy);
  progress.setAttribute('aria-busy', String(busy));
  rerunButton.disabled = busy || !output.value;
  copyButton.disabled = busy || !output.value;
}

function resetResult() {
  output.value = '';
  copyButton.disabled = true;
  copyButton.textContent = 'Copy';
  rerunButton.disabled = true;
  resultIsPartial = false;
  copyConfirmationExpires = 0;
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

function updateWorkingStatus() {
  const elapsed = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
  const minutes = Math.floor(elapsed / 60);
  const seconds = String(elapsed % 60).padStart(2, '0');
  resultStatus.textContent = `Processing locally… deterministic scan and two model passes · ${minutes}:${seconds} elapsed`;
}

async function redact(sourceText = input.value, preserveResult = false) {
  if (!preserveResult) resetResult();
  copyConfirmationExpires = 0;
  copyButton.textContent = 'Copy';
  const count = charCount(sourceText);
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
  activeController = new AbortController();
  startedAt = Date.now();
  updateWorkingStatus();
  elapsedTimer = setInterval(updateWorkingStatus, 1000);
  try {
    const response = await fetch('/api/redact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: sourceText, sizePreset: preset.value }),
      signal: activeController.signal
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 422 && data.status === 'review_required') {
      output.value = data.text;
      renderSummary(data.counts, data.chunksProcessed);
      renderFindings(data.findings || []);
      resultIsPartial = true;
      copyButton.disabled = false;
      rerunButton.disabled = false;
      resultStatus.className = 'status warning';
      resultStatus.textContent = 'Partially redacted: verification still found possible sensitive data. Review the marked locations, redact again, or use the two-step copy confirmation.';
      return;
    }
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    output.value = data.text;
    resultIsPartial = false;
    copyButton.disabled = false;
    rerunButton.disabled = false;
    renderSummary(data.counts, data.chunksProcessed);
    resultStatus.className = 'status success';
    resultStatus.textContent = 'Verified: both redaction passes completed without finding remaining sensitive data.';
  } catch (error) {
    resultStatus.className = 'status error';
    resultStatus.textContent = error && error.name === 'AbortError'
      ? 'Redaction cancelled. No result was copied or saved.'
      : `Redaction failed: ${error instanceof Error ? error.message : 'unknown error'}. Check that the local model is running, then try again.`;
  } finally {
    clearInterval(elapsedTimer);
    elapsedTimer = null;
    activeController = null;
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
redactButton.addEventListener('click', () => redact());
clearButton.addEventListener('click', () => {
  input.value = '';
  resetResult();
  updateCount();
  resultStatus.textContent = 'Ready. Your text is processed by the self-hosted service only.';
  input.focus();
});
cancelButton.addEventListener('click', () => activeController?.abort());
rerunButton.addEventListener('click', () => {
  if (output.value) redact(output.value, true);
});
copyButton.addEventListener('click', async () => {
  if (resultIsPartial && Date.now() > copyConfirmationExpires) {
    copyConfirmationExpires = Date.now() + 5000;
    copyButton.textContent = 'Confirm partial copy';
    resultStatus.className = 'status warning';
    resultStatus.textContent = 'This output may still contain sensitive data. Click “Confirm partial copy” within 5 seconds to copy it.';
    setTimeout(() => {
      if (Date.now() >= copyConfirmationExpires && copyButton.textContent === 'Confirm partial copy') copyButton.textContent = 'Copy';
    }, 5100);
    return;
  }
  try {
    await navigator.clipboard.writeText(output.value);
    copyConfirmationExpires = 0;
    copyButton.textContent = 'Copied';
    setTimeout(() => { copyButton.textContent = 'Copy'; }, 1200);
  } catch {
    resultStatus.className = 'status error';
    resultStatus.textContent = 'Could not access the clipboard. Select the redacted text and copy it manually.';
  }
});

updateCount();
checkStatus();
