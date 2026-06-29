const express = require('express');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const JOBBER_CLIENT_ID = process.env.JOBBER_CLIENT_ID;
const JOBBER_CLIENT_SECRET = process.env.JOBBER_CLIENT_SECRET;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const CALLBACK_URL = `${APP_URL}/auth/callback`;
const TOKEN_FILE = path.join(__dirname, '.token.json');
const REPS_FILE = path.join(__dirname, '.reps.json');
const ASSIGNMENTS_FILE = path.join(__dirname, '.assignments.json');
const JOBBER_API_VERSION = '2025-04-16';

app.use(express.static('public'));
app.use(express.json());

let pendingStates = {};

// ── Token helpers ──────────────────────────────────────────────────────────────

function readToken() {
  try {
    if (fs.existsSync(TOKEN_FILE)) return JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
  } catch (_) {}
  return null;
}

function writeToken(data) {
  fs.writeFileSync(TOKEN_FILE, JSON.stringify({ ...data, obtained_at: Date.now() }));
}

async function getAccessToken() {
  let token = readToken();
  if (!token) return null;

  const age = Date.now() - token.obtained_at;
  if (age > 55 * 60 * 1000) {
    // Refresh
    try {
      const res = await axios.post('https://api.getjobber.com/api/oauth/token', {
        client_id: JOBBER_CLIENT_ID,
        client_secret: JOBBER_CLIENT_SECRET,
        refresh_token: token.refresh_token,
        grant_type: 'refresh_token',
      });
      writeToken(res.data);
      return res.data.access_token;
    } catch (err) {
      console.error('Token refresh failed:', err.response?.data || err.message);
      if (fs.existsSync(TOKEN_FILE)) fs.unlinkSync(TOKEN_FILE);
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
    writeToken(response.data);
    res.redirect('/');
  } catch (err) {
    console.error('OAuth callback error:', err.response?.data || err.message);
    res.status(500).send('Authentication failed. Please go back and try again.');
  }
});

app.get('/auth/logout', (req, res) => {
  if (fs.existsSync(TOKEN_FILE)) fs.unlinkSync(TOKEN_FILE);
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

const QUOTES_QUERY = `
  query GetQuotes($cursor: String) {
    quotes(first: 100, after: $cursor) {
      nodes {
        id
        quoteNumber
        quoteStatus
        title
        amounts {
          subtotal
          total
          taxAmount
        }
        client {
          name
        }
        createdAt
        transitionedAt
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
`;

async function fetchAllQuotes(token) {
  let all = [];
  let cursor = null;

  do {
    const data = await jobberQuery(token, QUOTES_QUERY, { cursor });
    all = all.concat(data.quotes.nodes);
    cursor = data.quotes.pageInfo.hasNextPage ? data.quotes.pageInfo.endCursor : null;
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

// ── API routes ─────────────────────────────────────────────────────────────────

app.get('/api/status', async (req, res) => {
  const token = await getAccessToken();
  res.json({ connected: !!token });
});

app.get('/api/stats', async (req, res) => {
  const token = await getAccessToken();
  if (!token) return res.status(401).json({ error: 'Not connected to Jobber' });

  try {
    const quotes = await fetchAllQuotes(token);
    const assignments = readAssignments();
    const reps = readReps();
    const repMap = Object.fromEntries(reps.map((r) => [r.id, r.name]));

    // Attach rep to each quote
    const enriched = quotes.map((q) => ({
      ...q,
      repId: assignments[q.id] || null,
      repName: assignments[q.id] ? (repMap[assignments[q.id]] || null) : null,
    }));

    // Filter by date range / rep
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

    // Per-rep breakdown
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

    // Build recent quote list
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
      }));

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
      repStats,
      recentQuotes,
    });
  } catch (err) {
    console.error('Stats error:', err.message, err.response?.status, JSON.stringify(err.response?.data));
    res.status(500).json({ error: 'Failed to fetch data from Jobber', detail: err.response?.status + ' ' + JSON.stringify(err.response?.data) });
  }
});

// Sales reps CRUD
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
  // Also remove assignments for this rep
  const assignments = readAssignments();
  for (const key of Object.keys(assignments)) {
    if (assignments[key] === req.params.id) delete assignments[key];
  }
  writeAssignments(assignments);
  res.json({ ok: true });
});

// Quote → rep assignment
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
