# ThreeLabs

A Discord-whitelisted tracker for community opportunities. Members submit links and track tasks. Administrators review submissions, record evidence, and decide what appears to members. A separate reminder script can post deadlines to a Discord channel one day before they occur.

## Run locally

Requires Node.js 22+ for built-in SQLite. Set `SESSION_SECRET`, `ORIGIN`, `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, and `ADMIN_DISCORD_IDS` in your environment. Set `DB_PATH` and `PORT` to override their defaults. Register `ORIGIN/callback` as a Discord OAuth redirect URI and serve the app behind HTTPS. Never commit environment values or the SQLite database.

```sh
node --test test.mjs reminders.test.mjs
node app.mjs
```

The reminder script requires `DISCORD_WEBHOOK_URL`. Schedule `node reminders.mjs` separately if channel reminders are needed. It does not send direct messages.

URL checks validate format and selected hosts, not project identity or safety. Review labels record an administrator's judgment, not a safety guarantee. Paid API data and automated X account-history checks are not included. Local tests do not verify production OAuth, webhook delivery, or public reachability.
