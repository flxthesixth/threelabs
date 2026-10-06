import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { dueReminders, sendReminders } from './reminders.mjs';

test('sends only tomorrow deadlines once and records successful deliveries', async () => {
  const db = new DatabaseSync(':memory:');
  db.exec(`CREATE TABLE submissions(id INTEGER PRIMARY KEY,title TEXT,deadline TEXT,source TEXT);
    CREATE TABLE opportunities(id INTEGER PRIMARY KEY,submission_id INTEGER);
    INSERT INTO submissions VALUES(1,'Quest','2030-01-02','https://example.org/quest'),(2,'Later','2030-01-03','https://example.org/later');
    INSERT INTO opportunities VALUES(1,1),(2,2);`);
  const date = '2030-01-01';
  assert.deepEqual(dueReminders(db,date).map(x => x.title), ['Quest']);
  const calls = [];
  const fetcher = async (_url, options) => { calls.push(JSON.parse(options.body).content); return { ok: true }; };
  assert.equal(await sendReminders(db, 'https://discord.com/api/webhooks/12345/testtoken', date, fetcher), 1);
  assert.equal(await sendReminders(db, 'https://discord.com/api/webhooks/12345/testtoken', date, fetcher), 0);
  assert.equal(calls.length, 1);
  db.close();
});
