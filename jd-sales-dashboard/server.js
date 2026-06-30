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
const MONTHLY_GOAL = 50000;

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
        client { name }
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

// ── Helpers ────────────────────────────────────────────────────────────────────

function isToday(dateStr) {
  const d = new Date(dateStr);
  const now = new Date();
  return d.getFullYear() === now.getFullYear() &&
         d.getMonth() === now.getMonth() &&
         d.getDate() === now.getDate();
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
    const assignments = readAssignments();
    const leadSourceMap = readLeadSources();
    const reps = readReps();
    const repMap = Object.fromEntries(reps.map((r) => [r.id, r.name]));

    const enriched = quotes.map((q) => ({
      ...q,
      repId: assignments[q.id] || null,
      repName: assignments[q.id] ? (repMap[assignments[q.id]] || null) : null,
      leadSource: leadSourceMap[q.id] || null,
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

    // Daily metrics (always from full dataset, no date filter applied)
    const todayQuotes = enriched.filter((q) => isToday(q.createdAt));
    const todayWon = todayQuotes.filter((q) => ['approved', 'converted'].includes(q.quoteStatus));
    const todaySent = todayQuotes.filter((q) => q.quoteStatus !== 'draft');
    const todayRevenue = todayWon.reduce((s, q) => s + (q.amounts?.total || 0), 0);
    const todayPending = todayQuotes.filter((q) => q.quoteStatus === 'awaiting_response');

    // Monthly breakdown (last 6 months)
    const monthly = {};
    for (let i = 5; i >= 0; i--) {
      const d = new Date();
      d.setMonth(d.getMonth() - i);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      monthly[key] = { sent: 0, won: 0, revenue: 0 };
    }
    for (const q of enriched) {
      const d = new Date(q.createdAt);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      if (monthly[key]) {
        if (q.quoteStatus !== 'draft') monthly[key].sent++;
        if (['approved', 'converted'].includes(q.quoteStatus)) {
          monthly[key].won++;
          monthly[key].revenue += q.amounts?.total || 0;
        }
      }
    }

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

    // Current month revenue for goal tracking
    const now = new Date();
    const thisMonthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    const thisMonthRevenue = (monthly[thisMonthKey] || {}).revenue || 0;

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
      },
      monthly,
      repStats,
      recentQuotes,
      leadSourceStats,
      goal: {
        monthly: MONTHLY_GOAL,
        thisMonthRevenue,
        percent: Math.min((thisMonthRevenue / MONTHLY_GOAL) * 100, 100),
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

    // Monthly invoice revenue (last 6 months)
    const monthly = {};
    for (let i = 5; i >= 0; i--) {
      const d = new Date();
      d.setMonth(d.getMonth() - i);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      monthly[key] = { paid: 0, revenue: 0 };
    }
    for (const inv of paid) {
      const d = new Date(inv.createdAt);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
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
