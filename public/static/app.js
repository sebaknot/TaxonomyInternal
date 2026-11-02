// Build 1: minimal progressive enhancement, no frameworks.
// Document uploads/downloads are end-to-end encrypted in the browser with WebCrypto AES-256-GCM.
// The server hands out a per-file key over the authenticated session; Supabase Storage only ever
// holds ciphertext.
(function () {
  const csrf = () => (document.querySelector('meta[name=csrf]') || {}).content || '';
  const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const hex = (buf) => Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');

  async function postJson(url, body) {
    const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-CSRF-Token': csrf() }, body: JSON.stringify(body) });
    let data = null;
    try { data = await res.json(); } catch (_) {}
    if (!res.ok) throw new Error((data && data.error) || ('Request failed (' + res.status + ')'));
    return data;
  }

  async function encryptedUpload(form, status) {
    const fileInput = form.querySelector('input[type=file]');
    const file = fileInput && fileInput.files[0];
    if (!file) throw new Error('Choose a file first.');
    if (!window.crypto || !crypto.subtle) throw new Error('This browser does not support secure uploads. Please use a current browser.');
    const fields = {};
    new FormData(form).forEach((v, k) => { if (k !== 'file' && k !== '_csrf') fields[k] = v; });
    status.textContent = 'Preparing…';
    const init = await postJson(form.dataset.initUrl, Object.assign({ filename: file.name, size: file.size, mime: file.type || null }, fields));
    status.textContent = 'Encrypting…';
    const plaintext = await file.arrayBuffer();
    const sha256 = hex(await crypto.subtle.digest('SHA-256', plaintext));
    const key = await crypto.subtle.importKey('raw', b64ToBytes(init.key), { name: 'AES-GCM' }, false, ['encrypt']);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: b64ToBytes(init.iv) }, key, plaintext);
    status.textContent = 'Uploading…';
    const put = await fetch(init.uploadUrl, { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: ciphertext });
    if (!put.ok) throw new Error('Upload to storage failed (' + put.status + ').');
    status.textContent = 'Finishing…';
    const done = await postJson(form.dataset.completeUrl.replace('VERSION_ID', init.versionId), { sha256: sha256, size: file.size });
    window.location.href = done.redirect || window.location.href;
  }

  document.querySelectorAll('form[data-encrypted-upload]').forEach((form) => {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const status = form.querySelector('[data-upload-status]') || form.appendChild(Object.assign(document.createElement('span'), { className: 'muted' }));
      const btn = form.querySelector('button[type=submit]');
      if (btn) btn.disabled = true;
      try { await encryptedUpload(form, status); }
      catch (err) { status.textContent = ''; alert(err.message || 'Upload failed.'); if (btn) btn.disabled = false; }
    });
  });

  async function encryptedDownload(btn) {
    const grant = await postJson(btn.dataset.download, {});
    const res = await fetch(grant.url);
    if (!res.ok) throw new Error('Could not fetch the file (' + res.status + ').');
    const ciphertext = await res.arrayBuffer();
    const key = await crypto.subtle.importKey('raw', b64ToBytes(grant.key), { name: 'AES-GCM' }, false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(grant.iv) }, key, ciphertext);
    const blob = new Blob([plaintext], { type: 'application/octet-stream' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = grant.filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  document.addEventListener('click', async (ev) => {
    const dl = ev.target.closest('[data-download]');
    if (dl) {
      ev.preventDefault();
      const label = dl.textContent;
      dl.textContent = 'Decrypting…';
      dl.disabled = true;
      try { await encryptedDownload(dl); } catch (err) { alert(err.message || 'Download failed.'); }
      dl.textContent = label;
      dl.disabled = false;
      return;
    }
    const btn = ev.target.closest('[data-reveal-ssn]');
    if (!btn) return;
    ev.preventDefault();
    const out = document.getElementById(btn.dataset.target);
    if (out && out.dataset.revealed === '1') { out.textContent = out.dataset.masked; out.dataset.revealed = '0'; btn.textContent = 'Reveal'; return; }
    if (!confirm('Reveal the full SSN? This action is recorded in the audit log.')) return;
    try {
      const data = await postJson(btn.dataset.revealSsn, { which: btn.dataset.which || 'client', dependent_id: btn.dataset.dependent || undefined });
      if (out) { out.dataset.masked = out.textContent; out.textContent = data.ssn || '(none on file)'; out.dataset.revealed = '1'; btn.textContent = 'Hide'; }
    } catch (err) { alert('Could not reveal SSN.'); }
  });

  document.querySelectorAll('[data-confirm]').forEach((f) => f.addEventListener('submit', (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));
  document.querySelectorAll('[data-add-dependent-row]').forEach((btn) => btn.addEventListener('click', () => {
    const tpl = document.getElementById('dep-row-template');
    btn.parentElement.insertBefore(tpl.content.cloneNode(true), btn);
  }));
})();
