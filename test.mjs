import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from './app.mjs';

const setup = async () => {
  const dir = mkdtempSync(join(tmpdir(), 'airdrop-'));
  const app = createApp({ dbPath: join(dir, 'app.db'), adminIds: ['admin'], secret: 'local-test-secret', origin: 'http://127.0.0.1:0', testMode: true });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = (url, user, options = {}) => fetch(base + url, { ...options, headers: { ...(user ? { 'x-test-user': user } : {}), ...(options.headers || {}) }, redirect: 'manual' });
  return { app, request, close: async () => { await new Promise(r => server.close(r)); app.db.close(); rmSync(dir, { recursive: true, force: true }); } };
};
const post = (request, url, user, data) => request(url, user, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(data) });

test('Discord OAuth binds callback to short-lived signed state', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'airdrop-oauth-'));
  const app = createApp({ dbPath: join(dir, 'app.db'), adminIds: [], secret: 'test-secret', origin: 'http://127.0.0.1:4000', clientId: 'client', clientSecret: 'secret' });
  app.listen(0, '127.0.0.1'); await new Promise(r => app.once('listening', r));
  const base = `http://127.0.0.1:${app.address().port}`;
  try {
    const login = await fetch(base + '/login', { redirect: 'manual' });
    assert.equal(login.status, 302);
    const state = new URL(login.headers.get('location')).searchParams.get('state');
    assert.ok(state);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    assert.equal((await fetch(base + '/callback?code=x&state=wrong', { headers: { cookie }, redirect: 'manual' })).status, 400);
    assert.equal((await fetch(base + `/callback?code=x&state=${state}`, { headers: { cookie: cookie + 'tampered' }, redirect: 'manual' })).status, 400);
  } finally { await new Promise(r => app.close(r)); app.db.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('anonymous and non-whitelisted users cannot read or mutate data', async () => {
  const { request, close } = await setup();
  try {
    assert.equal((await request('/')).status, 200);
    assert.equal((await request('/opportunities')).status, 401);
    assert.equal((await post(request, '/submissions', 'stranger', { title: 'Scam', source: 'https://x.com/a/status/1' })).status, 403);
  } finally { await close(); }
});

test('member submits, admin reviews, member tracks tasks, evidence retained', async () => {
  const { app, request, close } = await setup();
  try {
    app.db.prepare('INSERT INTO members (id, role) VALUES (?, ?)').run('member', 'member');
    assert.equal((await post(request, '/submissions', 'member', { title: 'Testnet', source: 'https://x.com/project/status/1', project: 'Example', x_url: 'https://x.com/project', deadline: '2030-01-01', tasks: 'Visit site\nComplete quest' })).status, 303);
    assert.match(await (await request('/mine', 'member')).text(), /Testnet · pending/);
    assert.doesNotMatch(await (await request('/mine', 'admin')).text(), /Testnet · pending/);
    assert.match(await (await request('/reviews', 'admin')).text(), /Testnet/);
    assert.equal((await post(request, '/reviews/1', 'member', { decision: 'approve' })).status, 403);
    assert.equal((await post(request, '/reviews/1', 'admin', { decision: 'approve', reason: 'Source confirmed' })).status, 303);
    assert.match(await (await request('/opportunities', 'member')).text(), /Testnet/);
    assert.equal((await post(request, '/tasks/1/1', 'member', { status: 'done' })).status, 303);
    assert.match(await (await request('/opportunities/1', 'member')).text(), /done/);
    assert.equal(app.db.prepare('SELECT COUNT(*) n FROM evidence').get().n, 1);
    assert.equal(app.db.prepare('SELECT COUNT(*) n FROM audit').get().n, 2);
  } finally { await close(); }
});

test('admin appends dated evidence and updates project risk without member access', async () => {
  const { app, request, close } = await setup();
  try {
    app.db.prepare('INSERT INTO members(id,role) VALUES(?,?)').run('member','member');
    app.db.prepare('INSERT INTO projects(name,x_url) VALUES(?,?)').run('Example','https://x.com/example');
    const review = { status: 'high risk', source: 'https://x.com/example/status/22', note: 'Domain changed unexpectedly', x_url: '' };
    assert.equal((await post(request, '/projects/1', 'member', review)).status, 403);
    assert.equal((await post(request, '/projects/1', 'admin', review)).status, 303);
    const html = await (await request('/projects/1', 'member')).text();
    assert.match(html, /high risk/);
    assert.match(html, /Domain changed unexpectedly/);
    assert.equal(app.db.prepare('SELECT count(*) n FROM evidence').get().n, 1);
  } finally { await close(); }
});

test('project filters find reviewed X accounts and risk labels', async () => {
  const { app, request, close } = await setup();
  try {
    app.db.prepare('INSERT INTO projects(name,x_url,status) VALUES(?,?,?)').run('Risky', 'https://x.com/risky', 'high risk');
    app.db.prepare('INSERT INTO projects(name,x_url,status) VALUES(?,?,?)').run('Clear', 'https://x.com/clear', 'verified');
    const text = await (await request('/projects?q=risky&status=high%20risk', 'admin')).text();
    assert.match(text, /Risky/);
    assert.doesNotMatch(text, /Clear/);
    assert.match(text, /x.com\/risky/);
  } finally { await close(); }
});

test('NFT links persist and rule checks never imply verified identity', async () => {
  const { app, request, close } = await setup();
  try {
    app.db.prepare('INSERT INTO members(id,role) VALUES(?,?)').run('member','member');
    const nft = { title: 'Mint', project: 'Art', category: 'NFT', source: 'https://art.example/official', x_url: 'https://x.com/art', discord_url: 'https://discord.gg/art', website_url: 'https://art.example', marketplace_url: 'https://opensea.io/collection/art', deadline: '2030-01-01', tasks: 'Mint' };
    assert.equal((await post(request, '/submissions', 'member', nft)).status, 303);
    const review = await (await request('/reviews', 'admin')).text();
    assert.match(review, /discord.gg\/art/);
    assert.match(review, /opensea.io\/collection\/art/);
    assert.match(review, /Source provided/);
    assert.match(review, /Identity: unverified/);
    assert.match(review, /Tasks and deadline provided/);
    assert.equal((await post(request, '/reviews/1', 'admin', { decision: 'approve', reason: 'Manually reviewed' })).status, 303);
    const opportunity = await (await request('/opportunities/1', 'member')).text();
    assert.match(opportunity, /discord.gg\/art/);
    assert.match(opportunity, /opensea.io\/collection\/art/);
    assert.match(opportunity, /Identity: unverified/);
    assert.equal(app.db.prepare('SELECT category,discord_url,website_url,marketplace_url FROM submissions WHERE id=1').get().category, 'NFT');
  } finally { await close(); }
});

test('NFT URL validation and category/deadline filtering', async () => {
  const { app, request, close } = await setup();
  try {
    app.db.prepare('INSERT INTO members(id,role) VALUES(?,?)').run('member','member');
    const base = { title: 'Mint', project: 'Art', category: 'NFT', source: 'https://art.example/official', tasks: 'Mint' };
    assert.equal((await post(request, '/submissions', 'member', { ...base, marketplace_url: 'javascript:alert(1)' })).status, 400);
    assert.equal((await post(request, '/submissions', 'member', { ...base, marketplace_url: 'https://evil.example/collection/art' })).status, 400);
    assert.equal((await post(request, '/submissions', 'member', { ...base, discord_url: 'https://discord.gg.evil.example/art' })).status, 400);
    assert.equal((await post(request, '/submissions', 'member', { ...base, deadline: '2030-01-01' })).status, 303);
    assert.equal((await post(request, '/reviews/1', 'admin', { decision: 'approve', reason: 'Reviewed' })).status, 303);
    assert.equal((await post(request, '/submissions', 'member', { title: 'Testnet', project: 'Other', category: 'Airdrop', source: 'https://other.example/post', deadline: '2030-02-01' })).status, 303);
    assert.equal((await post(request, '/reviews/2', 'admin', { decision: 'approve', reason: 'Reviewed' })).status, 303);
    const list = await (await request('/opportunities?category=NFT&before=2030-01-31', 'member')).text();
    assert.match(list, /Mint/);
    assert.doesNotMatch(list, /<h2><a href="\/opportunities\/2">Testnet<\/a><\/h2>/);
  } finally { await close(); }
});

test('admin can inspect member task usage, members cannot', async () => {
  const { app, request, close } = await setup();
  try {
    app.db.prepare('INSERT INTO members(id,role) VALUES(?,?)').run('member','member');
    assert.equal((await request('/progress', 'member')).status, 403);
    assert.equal((await post(request, '/submissions', 'member', { title: 'Work', project: 'Example', source: 'https://example.com', tasks: 'First task' })).status, 303);
    assert.equal((await post(request, '/reviews/1', 'admin', { decision: 'approve', reason: 'Reviewed' })).status, 303);
    assert.equal((await post(request, '/tasks/1/0', 'member', { status: 'done' })).status, 303);
    const progress = await (await request('/progress', 'admin')).text();
    assert.match(progress, /member/);
    assert.match(progress, /1 \/ 1/);
  } finally { await close(); }
});

test('risk review does not publish rejected submissions; input and admin boundaries', async () => {
  const { app, request, close } = await setup();
  try {
    app.db.prepare('INSERT INTO members (id, role) VALUES (?, ?)').run('member', 'member');
    assert.equal((await post(request, '/submissions', 'member', { title: '<script>alert(1)</script>', source: 'javascript:alert(1)' })).status, 400);
    assert.equal((await post(request, '/submissions', 'member', { title: '<script>alert(1)</script>', source: 'https://example.org/post', project: 'Project' })).status, 303);
    assert.doesNotMatch(await (await request('/reviews', 'admin')).text(), /<script>/);
    assert.equal((await post(request, '/reviews/1', 'admin', { decision: 'reject', reason: 'No official source' })).status, 303);
    assert.doesNotMatch(await (await request('/opportunities', 'member')).text(), /alert\(1\)/);
    assert.equal((await post(request, '/members/member', 'member', { role: 'admin' })).status, 403);
    assert.equal((await post(request, '/members/another', 'admin', { role: 'member' })).status, 303);
  } finally { await close(); }
});
