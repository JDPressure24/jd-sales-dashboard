const express = require('express');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const JOBBER_CLIENT_ID = process.env.JOBBER_CLIENT_ID;
const JOBBER_CLIENT_SECRET = process.env.JOBBER_CLIENT_SECRET;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'jd-pressure-washing-secret-key-2024';
const CALLBACK_URL = `${APP_URL}/auth/callback`;
const REPS_FILE = path.join(__dirname, '.reps.json');
const ASSIGNMENTS_FILE = path.join(__dirname, '.assignments.json');
const LEAD_SOURCES_FILE = path.join(__dirname, '.lead-sources.json');
const RECURRING_SETTINGS_FILE = path.join(__dirname, '.recurring-settings.json');
const MONTHLY_GOAL = 50000;
const BUSINESS_TIMEZONE = 'America/New_York';
const DEFAULT_RECURRING_INTERVAL_DAYS = 90;
const DUE_SOON_WINDOW_DAYS = 14;

const LEAD_SOURCE_OPTIONS = [
  'Referral',
  'Google',
  'Facebook / Instagram',
  'Door Knock',
  'Yard Sign',
  'Repeat Customer',
  'Website',
  'Nextdoor',
  'Other',
];
const JOBBER_API_VERSION = '2025-04-16';

app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser(COOKIE_SECRET));

let pendingStates = {};

// ── Token helpers ─────────────────────────────────────────────────────────────

function readToken(req) {
  try {
    const raw = req.signedCookies?.jd_token || req.cookies?.jd_token;
    if (raw) return JSON.parse(raw);
  } catch (_) {}
  return null;
}

function writeToken(res, data) {
  const payload = JSON.stringify({ ...data, obtained_at: Date.now() });
  res.cookie('jd_token', payload, {
    signed: true,
    httpOnly: true,
    secure: APP_URL.startsWith('https'),
    maxAge: 365 * 24 * 60 * 60 * 1000,
    sameSite: 'lax',
  });
}

async function getAccessToken(req, res) {
  let token = readToken(req);
  if (!token) return null;

  const age = Date.now() - token.obtained_at;
  if (age > 55 * 60 * 1000) {
    try {
      const r = await axios.post('https://api.getjobber.com/api/oauth/token', {
        client_id: JOBBER_CLIENT_ID,
        client_secret: JOBBER_CLIENT_SECRET,
        refresh_token: token.refresh_token,
        grant_type: 'refresh_token',
      });
      if (res) writeToken(res, r.data);
      return r.data.access_token;
    } catch (err) {
      console.error('Token refresh failed:', err.response?.data || err.message);
      if (res) res.clearCookie('jd_token');
      return null;
    }
  }
  return token.access_token;
}

// ── OAuth routes ───────────────────────────────────────────────────────────────

app.get('/auth/jobber', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  pendingStates[state] = true;
  const url = [
    'https://api.getjobber.com/api/oauth/authorize',
    `?client_id=${JOBBER_CLIENT_ID}`,
    `&redirect_uri=${encodeURIComponent(CALLBACK_URL)}`,
    `&response_type=code`,
    `&state=${state}`,
  ].join('');
  res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!pendingStates[state]) return res.status(400).send('Invalid state — please try connecting again.');
  delete pendingStates[state];
  try {
    const response = await axios.post('https://api.getjobber.com/api/oauth/token', {
      client_id: JOBBER_CLIENT_ID,
      client_secret: JOBBER_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: CALLBACK_URL,
    });
    writeToken(res, response.data);
    res.redirect('/');
  } catch (err) {
    console.error('OAuth callback error:', err.response?.data || err.message);
    res.status(500).send('Authentication failed. Please go back and try again.');
  }
});

app.get('/auth/logout', (req, res) => {
  res.clearCookie('jd_token');
  res.redirect('/');
});

// ── Jobber GraphQL ─────────────────────────────────────────────────────────────

async function jobberQuery(token, query, variables = {}) {
  const res = await axios.post(
    'https://api.getjobber.com/api/graphql',
    { query, variables },
    {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'X-JOBBER-GRAPHQL-VERSION': JOBBER_API_VERSION,
      },
    }
  );
  if (res.data.errors) throw new Error(res.data.errors.map((e) => e.message).join(', '));
  return res.data.data;
}

// ── Quotes ────────────────────────────────────────────────────────────────────

const QUOTES_QUERY = `
  query GetQuotes($cursor: String) {
    quotes(first: 100, after: $cursor) {
      nodes {
        id
        quoteNumber
        quoteStatus
        title
        amounts { subtotal total taxAmount }
        client { name leadSource }
        createdAt
        transitionedAt
      }
      pageInfo { hasNextPage endCursor }
    }
  }
`;

async function fetchAllQuotes(token) {
  let all = [], cursor = null;
  do {
    const data = await jobberQuery(token, QUOTES_QUERY, { cursor });
    all = all.concat(data.quotes.nodes);
    cursor = data.quotes.pageInfo.hasNextPage ? data.quotes.pageInfo.endCursor : null;
  } while (cursor);
  return all;
}

// ── Invoices ──────────────────────────────────────────────────────────────────

const INVOICES_QUERY = `
  query GetInvoices($cursor: String) {
    invoices(first: 100, after: $cursor) {
      nodes {
        id
        invoiceNumber
        subject
        invoiceStatus
        amounts { subtotal total }
        client { name }
        createdAt
        issuedDate
      }
      pageInfo { hasNextPage endCursor }
    }
  }
`;

async function fetchAllInvoices(token) {
  let all = [], cursor = null;
  do {
    const data = await jobberQuery(token, INVOICES_QUERY, { cursor });
    all = all.concat(data.invoices.nodes);
    cursor = data.invoices.pageInfo.hasNextPage ? data.invoices.pageInfo.endCursor : null;
  } while (cursor);
  return all;
}

// Extended invoice query that also pulls payment records, so "revenue
// generated today" can reflect actual cash collected today rather than just
// invoice status. Kept as a separate query/function from fetchAllInvoices so
// that if the connected Jobber app doesn't have permission to read payment
// records, only this extra lookup fails — the base invoice fetch used
// elsewhere keeps working untouched.
const INVOICES_WITH_PAYMENTS_QUERY = `
  query GetInvoicesWithPayments($cursor: String) {
    invoices(first: 100, after: $cursor) {
      nodes {
        id
        invoiceStatus
        amounts { total }
        issuedDate
        createdAt
        paymentRecords(first: 20) {
          nodes { paidAt amount }
        }
      }
      pageInfo { hasNextPage endCursor }
    }
  }
`;

async function fetchAllInvoicesWithPayments(token) {
  let all = [], cursor = null;
  do {
    const data = await jobberQuery(token, INVOICES_WITH_PAYMENTS_QUERY, { cursor });
    all = all.concat(data.invoices.nodes);
    cursor = data.invoices.pageInfo.hasNextPage ? data.invoices.pageInfo.endCursor : null;
  } while (cursor);
  return all;
}

// ── Jobs ──────────────────────────────────────────────────────────────────────
// Used for the monthly goal (completed jobs, not just approved quotes), and for
// recurring-service tracking below.

const JOBS_QUERY = `
  query GetJobs($cursor: String) {
    jobs(first: 100, after: $cursor) {
      nodes {
        id
        jobNumber
        title
        jobStatus
        total
        completedAt
        client { name }
        createdAt
      }
      pageInfo { hasNextPage endCursor }
    }
  }
`;

async function fetchAllJobs(token) {
  let all = [], cursor = null;
  do {
    const data = await jobberQuery(token, JOBS_QUERY, { cursor });
    all = all.concat(data.jobs.nodes);
    cursor = data.jobs.pageInfo.hasNextPage ? data.jobs.pageInfo.endCursor : null;
  } while (cursor);
  return all;
}

// ── Sales rep helpers ──────────────────────────────────────────────────────────

function readReps() {
  try { if (fs.existsSync(REPS_FILE)) return JSON.parse(fs.readFileSync(REPS_FILE, 'utf8')); } catch (_) {}
  return [];
}
function writeReps(data) { fs.writeFileSync(REPS_FILE, JSON.stringify(data)); }

function readAssignments() {
  try { if (fs.existsSync(ASSIGNMENTS_FILE)) return JSON.parse(fs.readFileSync(ASSIGNMENTS_FILE, 'utf8')); } catch (_) {}
  return {};
}
function writeAssignments(data) { fs.writeFileSync(ASSIGNMENTS_FILE, JSON.stringify(data)); }

function readLeadSources() {
  try { if (fs.existsSync(LEAD_SOURCES_FILE)) return JSON.parse(fs.readFileSync(LEAD_SOURCES_FILE, 'utf8')); } catch (_) {}
  return {};
}
function writeLeadSources(data) { fs.writeFileSync(LEAD_SOURCES_FILE, JSON.stringify(data)); }

function readRecurringSettings() {
  try { if (fs.existsSync(RECURRING_SETTINGS_FILE)) return JSON.parse(fs.readFileSync(RECURRING_SETTINGS_FILE, 'utf8')); } catch (_) {}
  return {};
}
function writeRecurringSettings(data) { fs.writeFileSync(RECURRING_SETTINGS_FILE, JSON.stringify(data)); }

// ── Timezone-aware date helpers ─────────────────────────────────────────────────
// Railway (and most hosts) run servers on UTC. Without this, "today" and "this
// month" get computed against UTC, which silently rolls over hours before the
// business's actual local day/month ends. Everything below anchors to
// BUSINESS_TIMEZONE instead of the server's local clock.

const nyPartsFormatter = new Intl.DateTimeFormat('en-US', {
  timeZone: BUSINESS_TIMEZONE,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
});

function localParts(date) {
  const parts = Object.fromEntries(nyPartsFormatter.formatToParts(date).map((p) => [p.type, p.value]));
  return { year: parts.year, month: parts.month, day: parts.day };
}

function localMonthKey(date) {
  const p = localParts(date);
  return `${p.year}-${p.month}`;
}

function isToday(dateStr) {
  const a = localParts(new Date(dateStr));
  const b = localParts(new Date());
  return a.year === b.year && a.month === b.month && a.day === b.day;
}

// ── API routes ─────────────────────────────────────────────────────────────────

app.get('/api/status', async (req, res) => {
  const token = await getAccessToken(req, res);
  res.json({ connected: !!token });
});

app.get('/api/stats', async (req, res) => {
  const token = await getAccessToken(req, res);
  if (!token) return res.status(401).json({ error: 'Not connected to Jobber' });

  try {
    const quotes = await fetchAllQuotes(token);

    // Jobs power the "completed jobs" monthly goal. If the connected Jobber
    // app doesn't have permission to read Job records, don't let that take
    // down the whole dashboard — fall back to the previous won-quotes basis
    // for the goal and keep everything else working.
    let jobs = [];
    let jobsAvailable = true;
    try {
      jobs = await fetchAllJobs(token);
    } catch (jobsErr) {
      jobsAvailable = false;
      console.error('Jobs fetch failed — goal will fall back to won-quotes revenue:', jobsErr.message);
    }

    const assignments = readAssignments();
    const leadSourceMap = readLeadSources();
    const reps = readReps();
    const repMap = Object.fromEntries(reps.map((r) => [r.id, r.name]));

    const enriched = quotes.map((q) => ({
      ...q,
      repId: assignments[q.id] || null,
      repName: assignments[q.id] ? (repMap[assignments[q.id]] || null) : null,
      // Manual tag (set from the dashboard) wins if present; otherwise fall back
      // to the "Lead source" field pulled straight from the client's Jobber record.
      leadSource: leadSourceMap[q.id] || q.client?.leadSource || null,
    }));

    // Filters
    let filtered = enriched;
    const { from, to, repId } = req.query;
    if (from) filtered = filtered.filter((q) => new Date(q.createdAt) >= new Date(from));
    if (to) filtered = filtered.filter((q) => new Date(q.createdAt) <= new Date(to + 'T23:59:59'));
    if (repId) filtered = filtered.filter((q) => q.repId === repId);

    const won = filtered.filter((q) => ['approved', 'converted'].includes(q.quoteStatus));
    const lost = filtered.filter((q) => q.quoteStatus === 'archived');
    const sent = filtered.filter((q) => q.quoteStatus !== 'draft');
    const draft = filtered.filter((q) => q.quoteStatus === 'draft');
    const pending = filtered.filter((q) => q.quoteStatus === 'awaiting_response');

    const totalRevenue = won.reduce((s, q) => s + (q.amounts?.total || 0), 0);
    const avgTicket = won.length > 0 ? totalRevenue / won.length : 0;
    const winRate = sent.length > 0 ? (won.length / sent.length) * 100 : 0;

    // Daily metrics (always from full dataset, no date filter applied) —
    // "today" is evaluated in the business's local timezone, not server UTC.
    const todayQuotes = enriched.filter((q) => isToday(q.createdAt));
    const todaySent = todayQuotes.filter((q) => q.quoteStatus !== 'draft');
    const todayPending = todayQuotes.filter((q) => q.quoteStatus === 'awaiting_response');

    // "Won today" is based on when the quote's status actually flipped to
    // approved/converted (transitionedAt), not when it was created. A quote
    // created last week that gets approved today should count toward today's
    // revenue; a quote created today but approved next week should not.
    const todayWon = enriched.filter(
      (q) => ['approved', 'converted'].includes(q.quoteStatus) && q.transitionedAt && isToday(q.transitionedAt)
    );
    const todayRevenue = todayWon.reduce((s, q) => s + (q.amounts?.total || 0), 0);

    // Monthly breakdown (last 6 months, anchored to local "now") — based on quotes,
    // used for the Revenue tab's won-quotes chart.
    const nowP = localParts(new Date());
    const refDate = new Date(Date.UTC(Number(nowP.year), Number(nowP.month) - 1, 15));
    const monthly = {};
    for (let i = 5; i >= 0; i--) {
      const d = new Date(refDate);
      d.setUTCMonth(d.getUTCMonth() - i);
      const key = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
      monthly[key] = { sent: 0, won: 0, revenue: 0 };
    }
    for (const q of enriched) {
      const key = localMonthKey(new Date(q.createdAt));
      if (monthly[key]) {
        if (q.quoteStatus !== 'draft') monthly[key].sent++;
        if (['approved', 'converted'].includes(q.quoteStatus)) {
          monthly[key].won++;
          monthly[key].revenue += q.amounts?.total || 0;
        }
      }
    }

    // Completed-jobs monthly revenue — this is what the Monthly Goal tracks,
    // when the Jobs API is available. A job only counts once it has a real
    // completedAt date (work actually finished on site).
    const completedJobs = jobs.filter((j) => !!j.completedAt);
    const jobsMonthly = {};
    for (let i = 5; i >= 0; i--) {
      const d = new Date(refDate);
      d.setUTCMonth(d.getUTCMonth() - i);
      const key = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
      jobsMonthly[key] = { completed: 0, revenue: 0 };
    }
    for (const j of completedJobs) {
      const key = localMonthKey(new Date(j.completedAt));
      if (jobsMonthly[key]) {
        jobsMonthly[key].completed++;
        jobsMonthly[key].revenue += j.total || 0;
      }
    }

    // Jobs completed *today* — closer to "cash-generating work actually
    // finished today" than quote activity is, since a quote can be won weeks
    // before the crew shows up and does the job.
    const jobsCompletedToday = jobsAvailable ? completedJobs.filter((j) => isToday(j.completedAt)) : [];
    const jobsCompletedTodayRevenue = jobsCompletedToday.reduce((s, j) => s + (j.total || 0), 0);

    // Per-rep stats
    const repStats = {};
    for (const rep of reps) {
      const repQuotes = enriched.filter((q) => q.repId === rep.id);
      const repSent = repQuotes.filter((q) => q.quoteStatus !== 'draft');
      const repWon = repQuotes.filter((q) => ['approved', 'converted'].includes(q.quoteStatus));
      const repRevenue = repWon.reduce((s, q) => s + (q.amounts?.total || 0), 0);
      repStats[rep.id] = {
        name: rep.name,
        sent: repSent.length,
        won: repWon.length,
        winRate: repSent.length > 0 ? (repWon.length / repSent.length) * 100 : 0,
        revenue: repRevenue,
        avgTicket: repWon.length > 0 ? repRevenue / repWon.length : 0,
      };
    }

    const recentQuotes = [...filtered]
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 50)
      .map((q) => ({
        id: q.id,
        number: q.quoteNumber,
        client: q.client?.name || 'Unknown',
        title: q.title || '—',
        status: q.quoteStatus,
        total: q.amounts?.total || 0,
        date: q.createdAt,
        repId: q.repId,
        repName: q.repName,
        leadSource: q.leadSource,
      }));

    // Lead source breakdown
    const leadSourceStats = {};
    for (const src of LEAD_SOURCE_OPTIONS) leadSourceStats[src] = { count: 0, won: 0, revenue: 0 };
    leadSourceStats['Untagged'] = { count: 0, won: 0, revenue: 0 };
    for (const q of enriched) {
      const src = q.leadSource || 'Untagged';
      if (!leadSourceStats[src]) leadSourceStats[src] = { count: 0, won: 0, revenue: 0 };
      if (q.quoteStatus !== 'draft') leadSourceStats[src].count++;
      if (['approved', 'converted'].includes(q.quoteStatus)) {
        leadSourceStats[src].won++;
        leadSourceStats[src].revenue += q.amounts?.total || 0;
      }
    }

    // Current month revenue for goal tracking. Prefer completed-jobs revenue;
    // if the Jobs API isn't accessible, fall back to won-quotes revenue so the
    // goal bar still shows something useful instead of breaking.
    const thisMonthKey = localMonthKey(new Date());
    const thisMonthRevenue = jobsAvailable
      ? (jobsMonthly[thisMonthKey] || {}).revenue || 0
      : (monthly[thisMonthKey] || {}).revenue || 0;

    // Invoices paid today — closest thing to "money actually in the bank" out
    // of the three revenue signals. Tries real payment timestamps first; if
    // the connected Jobber app can't read payment records, falls back to
    // "invoice marked paid + issued today" as a best-effort estimate rather
    // than breaking this section entirely.
    let invoicesPaidToday = { amount: 0, count: 0, basis: 'unavailable' };
    try {
      const invoicesWithPayments = await fetchAllInvoicesWithPayments(token);
      let amount = 0, count = 0;
      for (const inv of invoicesWithPayments) {
        const records = inv.paymentRecords?.nodes || [];
        for (const p of records) {
          if (p.paidAt && isToday(p.paidAt)) {
            amount += p.amount || 0;
            count++;
          }
        }
      }
      invoicesPaidToday = { amount, count, basis: 'payment_records' };
    } catch (payErr) {
      console.error('Payment-records query unavailable, falling back to issued-date estimate:', payErr.message);
      try {
        const invoicesFallback = await fetchAllInvoices(token);
        const paidToday = invoicesFallback.filter(
          (i) => i.invoiceStatus === 'paid' && isToday(i.issuedDate || i.createdAt)
        );
        invoicesPaidToday = {
          amount: paidToday.reduce((s, i) => s + (i.amounts?.total || 0), 0),
          count: paidToday.length,
          basis: 'issued_date_estimate',
        };
      } catch (invErr) {
        console.error('Invoice fallback fetch also failed:', invErr.message);
      }
    }

    res.json({
      summary: {
        totalQuotes: filtered.length,
        sentQuotes: sent.length,
        wonQuotes: won.length,
        lostQuotes: lost.length,
        pendingQuotes: pending.length,
        draftQuotes: draft.length,
        avgTicket,
        totalRevenue,
        winRate,
      },
      daily: {
        sent: todaySent.length,
        won: todayWon.length,
        revenue: todayRevenue,
        pending: todayPending.length,
        revenueBreakdown: {
          quotesWon: { amount: todayRevenue, count: todayWon.length },
          jobsCompleted: { amount: jobsCompletedTodayRevenue, count: jobsCompletedToday.length, available: jobsAvailable },
          invoicesPaid: invoicesPaidToday,
        },
      },
      monthly,
      jobsMonthly,
      repStats,
      recentQuotes,
      leadSourceStats,
      goal: {
        monthly: MONTHLY_GOAL,
        thisMonthRevenue,
        percent: Math.min((thisMonthRevenue / MONTHLY_GOAL) * 100, 100),
        basis: jobsAvailable ? 'completed_jobs' : 'won_quotes_fallback',
      },
      leadSourceOptions: LEAD_SOURCE_OPTIONS,
    });
  } catch (err) {
    console.error('Stats error:', err.message, err.response?.status, JSON.stringify(err.response?.data));
    res.status(500).json({ error: 'Failed to fetch data', detail: err.message });
  }
});

// ── Invoice stats ──────────────────────────────────────────────────────────────

app.get('/api/invoice-stats', async (req, res) => {
  const token = await getAccessToken(req, res);
  if (!token) return res.status(401).json({ error: 'Not connected to Jobber' });

  try {
    const invoices = await fetchAllInvoices(token);

    const paid = invoices.filter((i) => i.invoiceStatus === 'paid');
    const outstanding = invoices.filter((i) => ['sent', 'overdue', 'awaiting_payment'].includes(i.invoiceStatus));
    const draft = invoices.filter((i) => i.invoiceStatus === 'draft');

    const paidRevenue = paid.reduce((s, i) => s + (i.amounts?.total || 0), 0);
    const outstandingRevenue = outstanding.reduce((s, i) => s + (i.amounts?.total || 0), 0);
    const avgInvoice = paid.length > 0 ? paidRevenue / paid.length : 0;

    // Monthly invoice revenue (last 6 months, anchored to local "now")
    const nowP = localParts(new Date());
    const refDate = new Date(Date.UTC(Number(nowP.year), Number(nowP.month) - 1, 15));
    const monthly = {};
    for (let i = 5; i >= 0; i--) {
      const d = new Date(refDate);
      d.setUTCMonth(d.getUTCMonth() - i);
      const key = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
      monthly[key] = { paid: 0, revenue: 0 };
    }
    for (const inv of paid) {
      const key = localMonthKey(new Date(inv.createdAt));
      if (monthly[key]) {
        monthly[key].paid++;
        monthly[key].revenue += inv.amounts?.total || 0;
      }
    }

    const recentInvoices = [...invoices]
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 30)
      .map((i) => ({
        id: i.id,
        number: i.invoiceNumber,
        client: i.client?.name || 'Unknown',
        subject: i.subject || '—',
        status: i.invoiceStatus,
        total: i.amounts?.total || 0,
        date: i.createdAt,
      }));

    res.json({
      summary: {
        total: invoices.length,
        paid: paid.length,
        outstanding: outstanding.length,
        draft: draft.length,
        paidRevenue,
        outstandingRevenue,
        avgInvoice,
      },
      monthly,
      recentInvoices,
    });
  } catch (err) {
    console.error('Invoice stats error:', err.message);
    res.status(500).json({ error: 'Failed to fetch invoices', detail: err.message });
  }
});

// ── Recurring service tracking ───────────────────────────────────────────────
// Flags clients who are due/overdue for their next service, based on how long
// it's been since their last completed job vs. a configurable per-client
// interval (defaults to DEFAULT_RECURRING_INTERVAL_DAYS). Depends on the same
// Jobs data as the completed-jobs goal, so it degrades gracefully the same way
// if the connected Jobber app doesn't have Jobs read access yet.

app.get('/api/recurring', async (req, res) => {
  const token = await getAccessToken(req, res);
  if (!token) return res.status(401).json({ error: 'Not connected to Jobber' });

  try {
    let jobs = [];
    let jobsAvailable = true;
    try {
      jobs = await fetchAllJobs(token);
    } catch (jobsErr) {
      jobsAvailable = false;
      console.error('Recurring: jobs fetch failed:', jobsErr.message);
    }

    if (!jobsAvailable) {
      return res.json({ jobsAvailable: false, clients: [], counts: { overdue: 0, dueSoon: 0, ok: 0 } });
    }

    const settings = readRecurringSettings();
    const completedJobs = jobs.filter((j) => !!j.completedAt);

    const byClient = {};
    for (const j of completedJobs) {
      const name = j.client?.name || 'Unknown';
      if (!byClient[name]) byClient[name] = [];
      byClient[name].push(j);
    }

    const now = Date.now();
    const clients = Object.keys(byClient).map((name) => {
      const jobsForClient = byClient[name].sort((a, b) => new Date(b.completedAt) - new Date(a.completedAt));
      const last = jobsForClient[0];
      const lastDate = new Date(last.completedAt).getTime();
      const daysSince = Math.floor((now - lastDate) / 86400000);
      const intervalDays = settings[name] || DEFAULT_RECURRING_INTERVAL_DAYS;
      const daysUntilDue = intervalDays - daysSince;
      let status = 'ok';
      if (daysUntilDue < 0) status = 'overdue';
      else if (daysUntilDue <= DUE_SOON_WINDOW_DAYS) status = 'due_soon';

      return {
        client: name,
        lastServiceDate: last.completedAt,
        lastServiceTitle: last.title || '—',
        lastServiceTotal: last.total || 0,
        completedCount: jobsForClient.length,
        intervalDays,
        daysSince,
        daysUntilDue,
        status,
      };
    });

    clients.sort((a, b) => a.daysUntilDue - b.daysUntilDue);

    const counts = {
      overdue: clients.filter((c) => c.status === 'overdue').length,
      dueSoon: clients.filter((c) => c.status === 'due_soon').length,
      ok: clients.filter((c) => c.status === 'ok').length,
    };

    res.json({ jobsAvailable: true, clients, counts, defaultIntervalDays: DEFAULT_RECURRING_INTERVAL_DAYS });
  } catch (err) {
    console.error('Recurring error:', err.message);
    res.status(500).json({ error: 'Failed to compute recurring status', detail: err.message });
  }
});

app.post('/api/recurring-settings', (req, res) => {
  const { client, intervalDays } = req.body;
  if (!client) return res.status(400).json({ error: 'client required' });
  const settings = readRecurringSettings();
  if (intervalDays) settings[client] = Number(intervalDays);
  else delete settings[client];
  writeRecurringSettings(settings);
  res.json({ ok: true });
});

// ── Sales reps CRUD ────────────────────────────────────────────────────────────

app.get('/api/reps', (req, res) => res.json(readReps()));

app.post('/api/reps', (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const reps = readReps();
  const rep = { id: crypto.randomBytes(8).toString('hex'), name: name.trim() };
  reps.push(rep);
  writeReps(reps);
  res.json(rep);
});

app.delete('/api/reps/:id', (req, res) => {
  const reps = readReps().filter((r) => r.id !== req.params.id);
  writeReps(reps);
  const assignments = readAssignments();
  for (const key of Object.keys(assignments)) {
    if (assignments[key] === req.params.id) delete assignments[key];
  }
  writeAssignments(assignments);
  res.json({ ok: true });
});

app.get('/api/lead-source-options', (req, res) => res.json(LEAD_SOURCE_OPTIONS));

app.post('/api/lead-sources', (req, res) => {
  const { quoteId, source } = req.body;
  if (!quoteId) return res.status(400).json({ error: 'quoteId required' });
  const sources = readLeadSources();
  if (source) sources[quoteId] = source;
  else delete sources[quoteId];
  writeLeadSources(sources);
  res.json({ ok: true });
});

app.post('/api/assignments', (req, res) => {
  const { quoteId, repId } = req.body;
  if (!quoteId) return res.status(400).json({ error: 'quoteId required' });
  const assignments = readAssignments();
  if (repId) assignments[quoteId] = repId;
  else delete assignments[quoteId];
  writeAssignments(assignments);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`\n🚀 JD Sales Dashboard running at http://localhost:${PORT}\n`);
});
