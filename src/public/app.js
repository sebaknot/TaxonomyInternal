// Minimal progressive enhancement. No frameworks in Build 1.
document.addEventListener('click', async (ev) => {
  const btn = ev.target.closest('[data-reveal-ssn]');
  if (!btn) return;
  ev.preventDefault();
  const out = document.getElementById(btn.dataset.target);
  if (out && out.dataset.revealed === '1') { out.textContent = out.dataset.masked; out.dataset.revealed = '0'; btn.textContent = 'Reveal'; return; }
  if (!confirm('Reveal the full SSN? This action is recorded in the audit log.')) return;
  const body = { which: btn.dataset.which || 'client', dependent_id: btn.dataset.dependent || undefined };
  const res = await fetch(btn.dataset.revealSsn, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': document.querySelector('meta[name=csrf]').content, Accept: 'application/json' }, body: JSON.stringify(body) });
  if (!res.ok) { alert('Could not reveal SSN.'); return; }
  const data = await res.json();
  if (out) { out.dataset.masked = out.textContent; out.textContent = data.ssn || '(none on file)'; out.dataset.revealed = '1'; btn.textContent = 'Hide'; }
});
document.querySelectorAll('[data-confirm]').forEach((f) => f.addEventListener('submit', (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));
document.querySelectorAll('[data-add-dependent-row]').forEach((btn) => btn.addEventListener('click', () => {
  const tpl = document.getElementById('dep-row-template');
  btn.parentElement.insertBefore(tpl.content.cloneNode(true), btn);
}));
