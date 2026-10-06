import http from 'node:http';
import { readFileSync } from 'node:fs';
const theme = readFileSync(new URL('./retro.css', import.meta.url), 'utf8');

import { DatabaseSync } from 'node:sqlite';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const escape = x => String(x ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const signed = (value, secret) => `${value}.${createHmac('sha256', secret).update(value).digest('base64url')}`;
function verify(value, secret) {
  if (!value) return null;
  const i = value.lastIndexOf('.'); if (i < 1) return null;
  const token = value.slice(0, i), expected = signed(token, secret).slice(i + 1), actual = value.slice(i + 1);
  if (actual.length !== expected.length || !timingSafeEqual(Buffer.from(actual), Buffer.from(expected))) return null;
  try { const x = JSON.parse(Buffer.from(token, 'base64url').toString()); return x.exp > Date.now() ? x : null; } catch { return null; }
}
const validUrl = x => { try { const u = new URL(x); return u.protocol === 'https:' && Boolean(u.hostname) && !u.username && !u.password && x.length <= 500; } catch { return false; } };
const validDeadline = x => !x || /^\d{4}-\d\d-\d\d$/.test(x) && !Number.isNaN(Date.parse(`${x}T00:00:00Z`)) && new Date(`${x}T00:00:00Z`).toISOString().slice(0, 10) === x;
const onHost = (url, hosts) => !url || validUrl(url) && hosts.includes(new URL(url).hostname.toLowerCase());
const extraLinks = x => `X: ${link(x.x_url)} · Discord: ${link(x.discord_url)} · Website: ${link(x.website_url)} · Marketplace: ${link(x.marketplace_url)}`;
const ruleChecks = x => `A: Source provided (identity unverified) · B: Identity: unverified · C: ${x.tasks?.trim() && x.deadline ? 'Tasks and deadline provided' : 'Tasks or deadline unverified'}`;
const page = (title, body) => `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} · ThreeLabs</title><meta name="theme-color" content="#0d0b08"><style>${theme}</style><body class="three-editorial${title === 'ThreeLabs' ? ' three-home' : ''}"><main><nav><a href="/">Home</a><a href="/opportunities">Opportunities</a><a href="/submissions/new">Submit</a><a href="/mine">My submissions</a><a href="/projects">Projects</a><a href="/reviews">Review</a><a href="/progress">Member usage</a><form method="post" action="/logout" style="margin:0;padding:0;background:none"><button>Logout</button></form></nav><h1>${escape(title)}</h1>${body}</main></html>`;
const field = (name, label, type = 'text', required = false) => `<label>${label}<input name="${name}" type="${type}" ${required ? 'required' : ''}></label>`;
const link = x => validUrl(x) ? `<a href="${escape(x)}" target="_blank" rel="noopener noreferrer">Source</a>` : '';
const redirect = (res, target) => { res.writeHead(303, { Location: target }); res.end(); };
const send = (res, status, html) => { res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" }); res.end(html); };
const form = (action, fields, button = 'Save') => `<form method="post" action="${action}">${fields}<button>${button}</button></form>`;

export function createApp({ dbPath = 'radar.db', adminIds = [], secret, origin, clientId, clientSecret, testMode = false }) {
  if (!secret || !origin) throw new Error('SESSION_SECRET and ORIGIN required');
  const db = new DatabaseSync(dbPath); db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');
  db.exec(`CREATE TABLE IF NOT EXISTS members(id TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('member','admin')));
CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY, submitter TEXT NOT NULL, title TEXT NOT NULL, source TEXT NOT NULL, project TEXT NOT NULL, x_url TEXT NOT NULL DEFAULT '', deadline TEXT NOT NULL DEFAULT '', tasks TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, x_url TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'needs review', notes TEXT NOT NULL DEFAULT '', checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS opportunities(id INTEGER PRIMARY KEY, submission_id INTEGER UNIQUE NOT NULL REFERENCES submissions(id), project_id INTEGER NOT NULL REFERENCES projects(id), published_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), source TEXT NOT NULL, note TEXT NOT NULL, author TEXT NOT NULL, checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS task_progress(member_id TEXT NOT NULL, opportunity_id INTEGER NOT NULL REFERENCES opportunities(id), task_number INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('todo','done')), PRIMARY KEY(member_id,opportunity_id,task_number));
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`);
  for (const [table, columns] of Object.entries({ submissions: ['category', 'discord_url', 'website_url', 'marketplace_url'] })) for (const column of columns) if (!db.prepare(`PRAGMA table_info(${table})`).all().some(x => x.name === column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} TEXT NOT NULL DEFAULT ''`);
  for (const id of adminIds) db.prepare("INSERT INTO members(id,role) VALUES(?,'admin') ON CONFLICT(id) DO UPDATE SET role='admin'").run(id);
  const base = new URL(origin);
  const server = http.createServer(async (req, res) => {
    try {
      const path = new URL(req.url, base).pathname;
      const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim().split('=')));
      const session = verify(cookies.radar_session, secret);
      const user = testMode && req.socket.remoteAddress?.includes('127.0.0.1') && req.headers['x-test-user'] ? String(req.headers['x-test-user']) : session?.id;
      const member = user && db.prepare('SELECT role FROM members WHERE id=?').get(user);
      const admin = member?.role === 'admin';
      const post = req.method === 'POST';
      if (path === '/login' && !post) {
        if (member) return redirect(res, '/opportunities');
        if (!clientId || !clientSecret) return send(res, 503, page('Login unavailable', '<p>Discord OAuth not configured.</p>'));
        const state = randomBytes(24).toString('base64url');
        const stateValue = Buffer.from(JSON.stringify({ value: state, exp: Date.now() + 600000 })).toString('base64url');
        res.setHeader('set-cookie', `radar_state=${signed(stateValue, secret)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600${base.protocol === 'https:' ? '; Secure' : ''}`);
        const u = new URL('https://discord.com/oauth2/authorize'); u.search = new URLSearchParams({ client_id: clientId, redirect_uri: `${origin}/callback`, response_type: 'code', scope: 'identify', state }).toString();
        res.writeHead(302, { Location: u.toString() }); return res.end();
      }
      if (path === '/callback' && !post) {
        const query = new URL(req.url, base).searchParams, stateCookie = verify(cookies.radar_state, secret);
        if (!stateCookie || query.get('state') !== stateCookie.value || !query.get('code')) return send(res, 400, page('Invalid login', '<p>Retry Discord login.</p>'));
        res.setHeader('set-cookie', `radar_state=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${base.protocol === 'https:' ? '; Secure' : ''}`);
        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, grant_type: 'authorization_code', code: query.get('code'), redirect_uri: `${origin}/callback` }) });
        if (!tokenResponse.ok) return send(res, 502, page('Discord error', '<p>OAuth failed.</p>'));
        const token = await tokenResponse.json();
        const profileResponse = await fetch('https://discord.com/api/users/@me', { headers: { authorization: `Bearer ${token.access_token}` } });
        if (!profileResponse.ok) return send(res, 502, page('Discord error', '<p>Profile request failed.</p>'));
        const profile = await profileResponse.json();
        if (!/^\d{15,25}$/.test(profile.id)) return send(res, 502, page('Discord error', '<p>Invalid account.</p>'));
        const allowed = db.prepare('SELECT role FROM members WHERE id=?').get(profile.id);
        if (!allowed) return send(res, 403, page('Access pending', `<p>Your Discord ID: ${escape(profile.id)}. Ask admin for whitelist access.</p>`));
        const value = Buffer.from(JSON.stringify({ id: profile.id, exp: Date.now() + 7 * 86400000 })).toString('base64url');
        res.setHeader('set-cookie', [`radar_state=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${base.protocol === 'https:' ? '; Secure' : ''}`, `radar_session=${signed(value, secret)}; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax${base.protocol === 'https:' ? '; Secure' : ''}`]); return redirect(res, '/opportunities');
      }
      if (path === '/logout' && post) {
        if (req.headers.origin !== origin && !testMode) return send(res, 403, page('Forbidden', '<p>Invalid origin.</p>'));
        res.setHeader('set-cookie', `radar_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${base.protocol === 'https:' ? '; Secure' : ''}`); return redirect(res, '/');
      }
      if (path === '/') return send(res, 200, page('ThreeLabs', member ? '<p>Curated opportunities and auditable project history.</p><p><a href="/opportunities">Open opportunities</a></p>' : '<p>Members only. Discord login and admin whitelist required.</p><p><a href="/login">Login with Discord</a></p>'));
      if (!user) return send(res, 401, page('Login required', '<a href="/login">Login with Discord</a>'));
      if (!member) return send(res, 403, page('Access pending', '<p>Ask admin to whitelist your Discord ID.</p>'));
      if (post && req.headers.origin !== origin && !testMode) return send(res, 403, page('Forbidden', '<p>Invalid origin.</p>'));
      if (post && req.headers['sec-fetch-site'] === 'cross-site') return send(res, 403, page('Forbidden', '<p>Invalid origin.</p>'));
      let data;
      if (post) {
        if (!req.headers['content-type']?.startsWith('application/x-www-form-urlencoded')) return send(res, 415, page('Unsupported input', ''));
        let body = ''; for await (const chunk of req) { body += chunk; if (body.length > 15000) return send(res, 413, page('Too large', '')); }
        data = Object.fromEntries(new URLSearchParams(body));
      }
      if (path === '/mine' && !post) return send(res, 200, page('My submissions', db.prepare('SELECT title,status,created_at FROM submissions WHERE submitter=? ORDER BY id DESC').all(user).map(x => `<article>${escape(x.title)} · ${escape(x.status)} · ${escape(x.created_at)}</article>`).join('') || '<p>No submissions yet.</p>'));
      if (path === '/submissions/new' && !post) return send(res, 200, page('Submit opportunity', form('/submissions', field('title', 'Title', 'text', true) + field('source', 'Official source URL', 'url', true) + field('project', 'Project', 'text', true) + '<label>Category<select name="category"><option>Airdrop</option><option>NFT</option><option>Testnet</option><option>Other</option></select></label>' + field('x_url', 'X account URL', 'url') + field('discord_url', 'Discord invite URL', 'url') + field('website_url', 'Website URL', 'url') + field('marketplace_url', 'Marketplace collection URL', 'url') + field('deadline', 'Deadline', 'date') + '<label>Tasks, one per line<textarea name="tasks"></textarea></label>', 'Submit for review')));
      if (path === '/submissions' && post) {
        if (!data.title?.trim() || data.title.length > 150 || !data.project?.trim() || data.project.length > 100 || !validUrl(data.source) || !['Airdrop','NFT','Testnet','Other'].includes(data.category || 'Other') || !onHost(data.x_url, ['x.com','twitter.com']) || !onHost(data.discord_url, ['discord.gg','discord.com']) || (data.website_url && !validUrl(data.website_url)) || !onHost(data.marketplace_url, ['opensea.io','magiceden.io','blur.io']) || !validDeadline(data.deadline) || (data.tasks || '').length > 3000) return send(res, 400, page('Invalid submission', '<p>Check title, project, URLs, tasks, and deadline.</p>'));
        const created = db.prepare('INSERT INTO submissions(submitter,title,source,project,x_url,deadline,tasks,category,discord_url,website_url,marketplace_url) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(user, data.title.trim(), data.source, data.project.trim(), data.x_url || '', data.deadline || '', data.tasks || '', data.category || 'Other', data.discord_url || '', data.website_url || '', data.marketplace_url || '');
        db.prepare('INSERT INTO audit(actor,action,target) VALUES(?,?,?)').run(user, 'submit', `submission:${created.lastInsertRowid}`);
        return redirect(res, '/mine');
      }
      if (path === '/reviews') {
        if (!admin) return send(res, 403, page('Forbidden', ''));
        const rows = db.prepare("SELECT * FROM submissions WHERE status='pending' ORDER BY id DESC").all();
        return send(res, 200, page('Review queue', rows.map(x => `<article><h2>${escape(x.title)}</h2><p>${escape(x.project)} · ${escape(x.category || 'Other')} · Official: ${link(x.source)} · ${extraLinks(x)} · Deadline: ${escape(x.deadline || 'Unknown')}</p><p>${ruleChecks(x)}</p><p>Tasks: ${escape(x.tasks)}</p>${form(`/reviews/${x.id}`, '<label>Reason / evidence<input name="reason" required></label><label>Decision<select name="decision"><option value="approve">Approve</option><option value="reject">Reject</option></select></label>', 'Review')}</article>`).join('') || '<p>Queue empty.</p>'));
      }
      let m = path.match(/^\/reviews\/(\d+)$/);
      if (m && post) {
        if (!admin) return send(res, 403, page('Forbidden', ''));
        if (!['approve', 'reject'].includes(data.decision) || !data.reason?.trim() || data.reason.length > 500) return send(res, 400, page('Invalid review', ''));
        const x = db.prepare("SELECT * FROM submissions WHERE id=? AND status='pending'").get(Number(m[1])); if (!x) return send(res, 404, page('Not found', ''));
        db.exec('BEGIN IMMEDIATE'); try {
          db.prepare('UPDATE submissions SET status=? WHERE id=?').run(data.decision, x.id);
          if (data.decision === 'approve') {
            db.prepare('INSERT INTO projects(name,x_url) VALUES(?,?) ON CONFLICT(name) DO NOTHING').run(x.project, x.x_url);
            const projectId = db.prepare('SELECT id FROM projects WHERE name=?').get(x.project).id;
            db.prepare('INSERT INTO opportunities(submission_id,project_id) VALUES(?,?)').run(x.id, projectId);
            db.prepare('INSERT INTO evidence(project_id,source,note,author) VALUES(?,?,?,?)').run(projectId, x.source, data.reason, user);
          }
          db.prepare('INSERT INTO audit(actor,action,target) VALUES(?,?,?)').run(user, data.decision, `submission:${x.id}`);
          db.exec('COMMIT');
        } catch (e) { db.exec('ROLLBACK'); throw e; }
        return redirect(res, '/reviews');
      }
      if (path === '/opportunities') {
        const params = new URL(req.url, base).searchParams, category = params.get('category') || '', before = params.get('before') || '';
        if (category && !['Airdrop','NFT','Testnet','Other'].includes(category) || !validDeadline(before)) return send(res, 400, page('Invalid filter', ''));
        const rows = db.prepare(`SELECT o.id,s.title,s.deadline,s.category,p.name,p.status,s.source FROM opportunities o JOIN submissions s ON s.id=o.submission_id JOIN projects p ON p.id=o.project_id WHERE (?='' OR s.category=?) AND (?='' OR s.deadline<>'' AND s.deadline<=?) ORDER BY s.deadline='',s.deadline,o.id DESC`).all(category,category,before,before);
        return send(res, 200, page('Opportunities', '<form method="get"><label>Category<select name="category"><option value="">All</option><option>Airdrop</option><option>NFT</option><option>Testnet</option><option>Other</option></select></label>' + field('before', 'Deadline on or before', 'date') + '<button>Filter</button></form>' + (rows.map(x => `<article><h2><a href="/opportunities/${x.id}">${escape(x.title)}</a></h2><p>${escape(x.name)} · ${escape(x.category || 'Other')} · ${escape(x.status)} · Deadline: ${escape(x.deadline || 'Unknown')}</p>${link(x.source)}</article>`).join('') || '<p>No reviewed opportunities yet.</p>')));
      }
      m = path.match(/^\/opportunities\/(\d+)$/);
      if (m && !post) {
        const x = db.prepare('SELECT o.id,s.title,s.source,s.deadline,s.tasks,s.category,s.x_url,s.discord_url,s.website_url,s.marketplace_url,s.created_at,p.id project_id,p.name,p.status FROM opportunities o JOIN submissions s ON s.id=o.submission_id JOIN projects p ON p.id=o.project_id WHERE o.id=?').get(Number(m[1])); if (!x) return send(res, 404, page('Not found', ''));
        const tasks = x.tasks.split('\n').map(t => t.trim()).filter(Boolean);
        const progress = db.prepare('SELECT task_number,status FROM task_progress WHERE member_id=? AND opportunity_id=?').all(user, x.id);
        return send(res, 200, page(x.title, `<p><a href="/projects/${x.project_id}">${escape(x.name)}</a> · ${escape(x.status)} · ${escape(x.category || 'Other')} · Deadline ${escape(x.deadline || 'Unknown')} · ${link(x.source)}</p><p>${extraLinks(x)}</p><p>${ruleChecks(x)} · Submitted: ${escape(x.created_at)}</p>${tasks.map((t, i) => { const done = progress.find(p => p.task_number === i)?.status === 'done'; return `<article>${escape(t)} · ${done ? 'done' : 'todo'}${form(`/tasks/${x.id}/${i}`, `<input type="hidden" name="status" value="${done ? 'todo' : 'done'}">`, done ? 'Reset' : 'Mark done')}</article>`; }).join('')}`));
      }
      m = path.match(/^\/tasks\/(\d+)\/(\d+)$/);
      if (m && post) {
        const x = db.prepare('SELECT s.tasks FROM opportunities o JOIN submissions s ON s.id=o.submission_id WHERE o.id=?').get(Number(m[1]));
        if (!x || !['todo','done'].includes(data.status) || !x.tasks.split('\n').map(t => t.trim()).filter(Boolean)[Number(m[2])]) return send(res, 400, page('Invalid task', ''));
        db.prepare('INSERT INTO task_progress(member_id,opportunity_id,task_number,status) VALUES(?,?,?,?) ON CONFLICT(member_id,opportunity_id,task_number) DO UPDATE SET status=excluded.status').run(user, Number(m[1]), Number(m[2]), data.status);
        return redirect(res, `/opportunities/${m[1]}`);
      }
      if (path === '/projects') {
        const params = new URL(req.url, base).searchParams, q = (params.get('q') || '').slice(0, 100), status = params.get('status') || '';
        const rows = db.prepare(`SELECT * FROM projects WHERE (name LIKE ? OR x_url LIKE ?) AND (?='' OR status=?) ORDER BY name`).all(`%${q}%`, `%${q}%`, status, status);
        return send(res, 200, page('Project history', '<form method="get" action="/projects"><label>Project / X account<input name="q" value="' + escape(q) + '"></label><label>Status<select name="status"><option value="">All</option><option>needs review</option><option>verified</option><option>high risk</option></select></label><button>Filter</button></form>' + (rows.map(x => `<article><a href="/projects/${x.id}">${escape(x.name)}</a> · ${escape(x.status)} · ${link(x.x_url)}</article>`).join('') || '<p>No matching projects.</p>')));
      }
      m = path.match(/^\/projects\/(\d+)$/);
      if (m && !post) {
        const x = db.prepare('SELECT * FROM projects WHERE id=?').get(Number(m[1])); if (!x) return send(res, 404, page('Not found', ''));
        const evidence = db.prepare('SELECT * FROM evidence WHERE project_id=? ORDER BY id DESC').all(x.id);
        return send(res, 200, page(x.name, `<p>Status: ${escape(x.status)} · Checked: ${escape(x.checked_at)} · ${link(x.x_url)}</p><p>${escape(x.notes)}</p><h2>Evidence history</h2>${evidence.map(e => `<article>${escape(e.checked_at)} · ${escape(e.note)} · ${link(e.source)}</article>`).join('')}${admin ? form(`/projects/${x.id}`, '<label>Status<select name="status"><option>needs review</option><option>verified</option><option>high risk</option></select></label>' + field('source', 'Evidence URL', 'url', true) + field('note', 'Reason', 'text', true) + field('x_url', 'X account URL', 'url'), 'Record review') : ''}`));
      }
      if (m && post) {
        if (!admin) return send(res, 403, page('Forbidden', ''));
        const x = db.prepare('SELECT id FROM projects WHERE id=?').get(Number(m[1])); if (!x) return send(res, 404, page('Not found', ''));
        if (!['needs review','verified','high risk'].includes(data.status) || !validUrl(data.source) || !data.note?.trim() || data.note.length > 500 || (data.x_url && !validUrl(data.x_url))) return send(res, 400, page('Invalid review', ''));
        db.exec('BEGIN IMMEDIATE'); try {
          db.prepare(`UPDATE projects SET status=?,notes=?,checked_at=CURRENT_TIMESTAMP,x_url=CASE WHEN ?='' THEN x_url ELSE ? END WHERE id=?`).run(data.status,data.note,data.x_url || '',data.x_url || '',x.id);
          db.prepare('INSERT INTO evidence(project_id,source,note,author) VALUES(?,?,?,?)').run(x.id,data.source,data.note,user);
          db.prepare('INSERT INTO audit(actor,action,target) VALUES(?,?,?)').run(user,'project_review',`project:${x.id}`);
          db.exec('COMMIT');
        } catch (e) { db.exec('ROLLBACK'); throw e; }
        return redirect(res, `/projects/${x.id}`);
      }
      m = path.match(/^\/members\/([^/]+)$/);
      if (m && post) {
        if (!admin) return send(res, 403, page('Forbidden', ''));
        if (!/^\d{15,25}$/.test(m[1]) && !testMode) return send(res, 400, page('Invalid Discord ID', ''));
        if (!['member','admin','remove'].includes(data.role) || m[1] === user && data.role !== 'admin') return send(res, 400, page('Invalid role', ''));
        if (data.role === 'remove') db.prepare('DELETE FROM members WHERE id=?').run(m[1]); else db.prepare('INSERT INTO members(id,role) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET role=excluded.role').run(m[1],data.role);
        db.prepare('INSERT INTO audit(actor,action,target) VALUES(?,?,?)').run(user,`member_${data.role}`,m[1]); return redirect(res, '/members');
      }
      if (path === '/progress' && !post) {
        if (!admin) return send(res, 403, page('Forbidden', ''));
        const rows = db.prepare(`SELECT m.id, COUNT(t.opportunity_id) tracked, SUM(CASE WHEN t.status='done' THEN 1 ELSE 0 END) done FROM members m LEFT JOIN task_progress t ON t.member_id=m.id WHERE m.role='member' GROUP BY m.id ORDER BY m.id`).all();
        return send(res, 200, page('Member task usage', '<p>Checklist activity is not proof of task completion or reward eligibility.</p>' + rows.map(x => `<article>${escape(x.id)} · ${x.done} / ${x.tracked} tracked tasks marked done</article>`).join('')));
      }
      if (path === '/members' && !post) {
        if (!admin) return send(res, 403, page('Forbidden', ''));
        return send(res, 200, page('Members', form('/members/add', field('id', 'Discord user ID', 'text', true) + '<label>Role<select name="role"><option>member</option><option>admin</option></select></label>', 'Whitelist') + db.prepare('SELECT * FROM members ORDER BY id').all().map(x => `<article>${escape(x.id)} · ${escape(x.role)}</article>`).join('')));
      }
      if (path === '/members/add' && post) {
        if (!admin) return send(res, 403, page('Forbidden', ''));
        if (!/^\d{15,25}$/.test(data.id || '') || !['member','admin'].includes(data.role)) return send(res, 400, page('Invalid member', ''));
        db.prepare('INSERT INTO members(id,role) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET role=excluded.role').run(data.id,data.role);
        db.prepare('INSERT INTO audit(actor,action,target) VALUES(?,?,?)').run(user,`member_${data.role}`,data.id); return redirect(res, '/members');
      }
      return send(res, 404, page('Not found', ''));
    } catch (e) { console.error('request error:', e); send(res, 500, page('Server error', '<p>Try again later.</p>')); }
  });
  return Object.assign(server, { db });
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const { SESSION_SECRET, ORIGIN, DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, ADMIN_DISCORD_IDS, DB_PATH, PORT } = process.env;
  const app = createApp({ dbPath: DB_PATH || 'radar.db', adminIds: (ADMIN_DISCORD_IDS || '').split(',').filter(Boolean), secret: SESSION_SECRET, origin: ORIGIN, clientId: DISCORD_CLIENT_ID, clientSecret: DISCORD_CLIENT_SECRET });
  app.listen(Number(PORT || 3000), '127.0.0.1', () => console.log(`ThreeLabs listening on 127.0.0.1:${PORT || 3000}`));
}
