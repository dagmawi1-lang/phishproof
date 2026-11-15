(function () {
  const $ = (id) => document.getElementById(id);
  const { analyze } = globalThis.PhishProof;
  const SAMPLES = globalThis.PHISHPROOF_SAMPLES;
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const LABEL = { 'likely-phishing': 'Likely phishing', suspicious: 'Suspicious', 'no-red-flags': 'No red flags found' };

  // ---- tabs (keyboard accessible) ----
  const tabs = [$('tab-check'), $('tab-practice')];
  function select(tab) {
    tabs.forEach((t) => {
      const on = t === tab;
      t.setAttribute('aria-selected', on);
      t.tabIndex = on ? 0 : -1;
      $(t.getAttribute('aria-controls')).hidden = !on;
    });
    tab.focus();
  }
  tabs.forEach((t, i) => {
    t.addEventListener('click', () => select(t));
    t.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { e.preventDefault(); select(tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length]); }
    });
  });

  // ---- check mode ----
  function renderFlags(list, el) {
    el.innerHTML = list.length ? list.map((f) => `
      <li class="flag ${f.severity}">
        <p class="ft"><span class="badge ${f.severity}">${f.severity === 'high' ? 'High risk' : f.severity === 'medium' ? 'Warning' : 'Minor'}</span> ${esc(f.title)}</p>
        <p>${esc(f.detail)}</p>
        <p class="tip"><b>Tip:</b> ${esc(f.tip)}</p>
      </li>`).join('') : '<li class="flag none">No common red flags were found. That doesn\'t guarantee it\'s safe, so still verify anything unexpected.</li>';
  }

  function check() {
    const text = $('msg').value.trim();
    if (!text) { $('msg-help').textContent = 'Paste a message first.'; $('msg-help').classList.add('warn'); $('msg').focus(); return; }
    const r = analyze(text);
    $('result').hidden = false;
    $('verdict').className = 'verdict ' + r.verdict;
    $('verdict-text').textContent = LABEL[r.verdict];
    $('risk').textContent = `Risk score ${r.risk}/100 · ${r.flags.length} red flag${r.flags.length === 1 ? '' : 's'}`;
    $('meter-fill').style.width = Math.max(4, r.risk) + '%';
    renderFlags(r.flags, $('flags'));
    $('result-h').focus();
  }
  $('check').addEventListener('click', check);
  $('example').addEventListener('click', () => { $('msg').value = SAMPLES[5].text; check(); });

  // ---- practice mode ----
  let i = 0, score = 0, answered = false;
  $('q-total').textContent = SAMPLES.length;
  function show() {
    answered = false;
    $('q-num').textContent = i + 1;
    $('q-text').textContent = SAMPLES[i].text;
    $('feedback').innerHTML = '';
    $('next').hidden = true;
    $('ans-phish').disabled = $('ans-safe').disabled = false;
  }
  function answer(sayPhish) {
    if (answered) return;
    answered = true;
    const s = SAMPLES[i];
    const right = sayPhish === s.phish;
    if (right) score++;
    $('q-score').textContent = `${score}/${i + 1}`;
    const r = analyze(s.text);
    $('feedback').innerHTML = `<p class="${right ? 'good' : 'bad'}"><b>${right ? 'Correct!' : 'Not quite.'}</b> This one is ${s.phish ? 'phishing' : 'legitimate'}. ${esc(s.why)}</p>
      ${r.flags.length ? `<p class="small">PhishProof found ${r.flags.length} red flag${r.flags.length === 1 ? '' : 's'}:</p><ol class="flags small">${r.flags.map((f) => `<li class="flag ${f.severity}">${esc(f.title)}</li>`).join('')}</ol>` : '<p class="small">PhishProof found no red flags in this one.</p>'}`;
    $('ans-phish').disabled = $('ans-safe').disabled = true;
    if (i < SAMPLES.length - 1) { $('next').hidden = false; $('next').focus(); }
    else $('feedback').insertAdjacentHTML('beforeend', `<p class="final"><b>You scored ${score}/${SAMPLES.length}.</b> ${score === SAMPLES.length ? 'Phish-proof! 🎉' : 'Try again any time. Spotting these gets easier with practice.'}</p><button id="restart" type="button" class="secondary">Start over</button>`);
  }
  $('ans-phish').addEventListener('click', () => answer(true));
  $('ans-safe').addEventListener('click', () => answer(false));
  $('next').addEventListener('click', () => { i++; show(); $('q-text').focus(); });
  $('feedback').addEventListener('click', (e) => { if (e.target.id === 'restart') { i = 0; score = 0; $('q-score').textContent = '0'; show(); $('q-text').focus(); } });
  show();
})();
