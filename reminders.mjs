import { DatabaseSync } from 'node:sqlite';

export function dueReminders(db, today) {
  const tomorrow = new Date(`${today}T00:00:00Z`);
  if (Number.isNaN(tomorrow.getTime())) throw new Error('Invalid date');
  tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
  return db.prepare('SELECT o.id,s.title,s.deadline,s.source FROM opportunities o JOIN submissions s ON s.id=o.submission_id WHERE s.deadline=? ORDER BY o.id').all(tomorrow.toISOString().slice(0, 10));
}

export async function sendReminders(db, webhook, today, fetcher = fetch) {
  if (!/^https:\/\/(discord\.com|discordapp\.com)\/api\/webhooks\/\d+\/[\w-]+$/.test(webhook)) throw new Error('Invalid Discord webhook');
  db.exec('CREATE TABLE IF NOT EXISTS reminder_sent (opportunity_id INTEGER NOT NULL, deadline TEXT NOT NULL, PRIMARY KEY(opportunity_id,deadline))');
  let count = 0;
  for (const x of dueReminders(db, today)) {
    if (db.prepare('SELECT 1 FROM reminder_sent WHERE opportunity_id=? AND deadline=?').get(x.id, x.deadline)) continue;
    const text = `Deadline tomorrow: ${x.title.slice(0, 150)} (${x.deadline})\n${x.source}`;
    const response = await fetcher(webhook, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ content: text, allowed_mentions: { parse: [] } }) });
    if (!response.ok) throw new Error(`Discord reminder failed: HTTP ${response.status}`);
    db.prepare('INSERT OR IGNORE INTO reminder_sent(opportunity_id,deadline) VALUES(?,?)').run(x.id,x.deadline);
    count++;
  }
  return count;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const { DB_PATH = 'radar.db', DISCORD_WEBHOOK_URL } = process.env;
  const db = new DatabaseSync(DB_PATH);
  try { const today = new Date().toISOString().slice(0, 10); console.log(`Sent ${await sendReminders(db, DISCORD_WEBHOOK_URL, today)} deadline reminders`); }
  finally { db.close(); }
}
