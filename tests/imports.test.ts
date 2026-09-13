import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import ExcelJS from 'exceljs';
import { startTestApp, Client, seedUser, login, type TestApp } from './helpers.js';
import { suggestMapping } from '../src/services/imports.js';

let app: TestApp;
let admin: ReturnType<typeof seedUser>;
before(async () => {
  app = await startTestApp();
  admin = seedUser(app.ctx, 'admin@example.com', 'admin');
});
after(async () => app.close());

test('header aliases are auto-suggested', () => {
  const m = suggestMapping(['TP First Name', 'TP Last Name', 'SSN', 'Birth Date', 'Cell Phone', 'E-mail', 'Filing Status', 'Weird Column']);
  assert.equal(m['TP First Name'], 'first_name');
  assert.equal(m['TP Last Name'], 'last_name');
  assert.equal(m['SSN'], 'ssn');
  assert.equal(m['Birth Date'], 'dob');
  assert.equal(m['Cell Phone'], 'phone');
  assert.equal(m['E-mail'], 'email');
  assert.equal(m['Filing Status'], 'filing_status');
  assert.equal(m['Weird Column'], 'skip');
});

test('CSV import with column mapping creates records and reports failed rows', async () => {
  const c = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await c.get('/imports');
  const csv = [
    'First,Last,Social Security,DOB,Phone,Email,Tags,Ignore',
    'Ana,Lopez,111-22-3333,03/04/1975,555-0100,ana@x.com,"Real Estate, Crypto",zzz',
    ',,222-33-4444,1980-01-01,555-0101,noname@x.com,,zzz',
    'Bob,Reyes,12345,1990-12-12,555-0102,bob@x.com,Construction,zzz',
    'Carla,Diaz,333-44-5555,5/6/88,555-0103,carla@x.com,,zzz',
  ].join('\n');
  const up = await c.upload('/imports', {}, { name: 'taxwise-export.csv', content: csv, type: 'text/csv' });
  assert.equal(up.status, 302);
  const importId = up.location!.split('/').pop()!;
  const mapPage = await c.get(`/imports/${importId}`);
  assert.equal(mapPage.status, 200);
  assert.match(mapPage.text, /4 data row\(s\)/);
  // Suggested mapping is pre-selected; "Ignore" column stays skipped.
  assert.match(mapPage.text, /<option value="first_name" selected>/);
  const run = await c.post(`/imports/${importId}/run`, {
    'map[First]': 'first_name', 'map[Last]': 'last_name', 'map[Social Security]': 'ssn', 'map[DOB]': 'dob', 'map[Phone]': 'phone', 'map[Email]': 'email', 'map[Tags]': 'tags', 'map[Ignore]': 'skip',
  });
  assert.equal(run.status, 302);
  const summary = await c.get(`/imports/${importId}`);
  assert.match(summary.text, /<h3>2<\/h3>client record\(s\) created/);
  assert.match(summary.text, /<h3>2<\/h3>row\(s\) failed/);
  assert.match(summary.text, /<td>3<\/td><td><\/td><td>Missing required field: legal name/);
  assert.match(summary.text, /<td>4<\/td><td>Bob Reyes<\/td><td>SSN must have 9 digits/);
  const ana = app.ctx.db.prepare("SELECT * FROM clients WHERE legal_name = 'Ana Lopez'").get() as any;
  assert.equal(ana.ssn_last4, '3333');
  assert.equal(ana.dob, '1975-03-04');
  assert.equal(ana.created_via, 'import');
  const carla = app.ctx.db.prepare("SELECT * FROM clients WHERE legal_name = 'Carla Diaz'").get() as any;
  assert.equal(carla.dob, '1988-05-06');
  const tags = app.ctx.db.prepare('SELECT t.name FROM client_tags ct JOIN tags t ON t.id = ct.tag_id WHERE ct.client_id = ? ORDER BY t.name').all(ana.id) as any[];
  assert.deepEqual(tags.map((t) => t.name), ['Crypto', 'Real Estate']);
  // Staged file with SSNs removed after the run.
  const rec = app.ctx.db.prepare('SELECT stored_name FROM imports WHERE id = ?').get(importId) as any;
  const fs = await import('node:fs');
  assert.ok(!fs.existsSync(`${app.ctx.importsDir}/${rec.stored_name}`));
});

test('Excel import works and requires a name mapping', async () => {
  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('Clients');
  ws.addRow(['Client Name', 'SSN', 'Date of Birth', 'City']);
  ws.addRow(['Dora Explorer', '444-55-6666', new Date(Date.UTC(1970, 6, 8)), 'Miami']);
  ws.addRow(['Ed Nygma', '555-66-7777', '1966-01-02', 'Gotham']);
  const buf = Buffer.from(await wb.xlsx.writeBuffer());
  const c = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await c.get('/imports');
  const up = await c.upload('/imports', {}, { name: 'clients.xlsx', content: buf, type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  const importId = up.location!.split('/').pop()!;
  await c.get(`/imports/${importId}`);
  const noName = await c.post(`/imports/${importId}/run`, { 'map[Client Name]': 'skip', 'map[SSN]': 'ssn', 'map[Date of Birth]': 'dob', 'map[City]': 'city' });
  assert.equal(noName.status, 400);
  assert.match(noName.text, /Map a column to (&#34;|")Legal name/);
  const run = await c.post(`/imports/${importId}/run`, { 'map[Client Name]': 'legal_name', 'map[SSN]': 'ssn', 'map[Date of Birth]': 'dob', 'map[City]': 'city' });
  assert.equal(run.status, 302);
  const dora = app.ctx.db.prepare("SELECT * FROM clients WHERE legal_name = 'Dora Explorer'").get() as any;
  assert.equal(dora.dob, '1970-07-08');
  assert.equal(dora.city, 'Miami');
  assert.equal(dora.ssn_last4, '6666');
});
