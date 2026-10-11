const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const sessions = new Map();
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-5.6-luna';
const MAX_JSON_BYTES = Number(process.env.MAX_JSON_BYTES || 25000000);
const MAX_NOTE_FILES = 5;
const MAX_NOTE_FILE_BYTES = Number(process.env.MAX_NOTE_FILE_BYTES || 5000000);
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 7);

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is required. Configure it in Render/local environment before starting MedRise.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
  max: Number(process.env.DB_POOL_MAX || 5),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      trial_ends_at TIMESTAMPTZ,
      premium BOOLEAN NOT NULL DEFAULT FALSE,
      plan TEXT NOT NULL DEFAULT '',
      progress JSONB NOT NULL DEFAULT '{}'::jsonb
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id BIGSERIAL PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE INDEX IF NOT EXISTS sessions_token_hash_idx ON sessions(token_hash);
    CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);

    CREATE TABLE IF NOT EXISTS ai_usage (
      id BIGSERIAL PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS ai_usage_user_time_idx ON ai_usage(user_id, used_at);
  `);
  await pool.query(`DELETE FROM sessions WHERE expires_at <= NOW()`);
}

function rowToUser(r) {
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    email: r.email,
    passwordHash: r.password_hash,
    passwordSalt: r.password_salt,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at,
    updatedAt: r.updated_at instanceof Date ? r.updated_at.toISOString() : r.updated_at,
    trialEndsAt: r.trial_ends_at ? (r.trial_ends_at instanceof Date ? r.trial_ends_at.toISOString() : r.trial_ends_at) : null,
    premium: !!r.premium,
    plan: r.plan || '',
    progress: r.progress && typeof r.progress === 'object' ? r.progress : {}
  };
}

async function getUserById(id) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return rowToUser(rows[0]);
}

async function getUserByEmail(email) {
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return rowToUser(rows[0]);
}

function tokenHash(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await pool.query(
    'INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
    [userId, tokenHash(token), expiresAt]
  );
  return token;
}

async function authUser(req) {
  const token = bearer(req);
  if (!token) return null;
  const { rows } = await pool.query(`
    SELECT u.*
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = $1 AND s.expires_at > NOW()
    LIMIT 1
  `, [tokenHash(token)]);
  if (!rows[0]) {
    await pool.query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash(token)]).catch(() => {});
    return null;
  }
  return rowToUser(rows[0]);
}

async function allowAI(userId) {
  const { rows } = await pool.query(
    'SELECT COUNT(*)::int AS count FROM ai_usage WHERE user_id = $1 AND used_at > NOW() - INTERVAL \'1 hour\'',
    [userId]
  );
  if (Number(rows[0]?.count || 0) >= 30) return false;
  await pool.query('INSERT INTO ai_usage (user_id) VALUES ($1)', [userId]);
  return true;
}

function progressOf(u) { return u.progress || {}; }
function publicProgress(u) { return { progress: progressOf(u) }; }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function validPassword(password, salt, expectedHash) {
  const actual = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expectedHash, 'hex'));
}
function send(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS'
  });
  res.end(body);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > MAX_JSON_BYTES) { req.destroy(); reject(new Error('Payload too large')); }
    });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}
function publicUser(u) { return { id: u.id, name: u.name, email: u.email, createdAt: u.createdAt, premium: !!u.premium, plan: u.plan || '', trialEndsAt: u.trialEndsAt || null }; }
function bearer(req) { const auth = String(req.headers.authorization || ''); return auth.startsWith('Bearer ') ? auth.slice(7) : ''; }
async function openAIResponse(input, instructions, maxOutputTokens=1200){
  if(!process.env.OPENAI_API_KEY) throw new Error('AI is not configured on the MedRise server. Add OPENAI_API_KEY on the server.');
  const r=await fetch('https://api.openai.com/v1/responses',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+process.env.OPENAI_API_KEY},body:JSON.stringify({model:OPENAI_MODEL,instructions,input,max_output_tokens:maxOutputTokens})});
  const data=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(data?.error?.message||'OpenAI request failed.');
  return data.output_text||((data.output||[]).flatMap(x=>x.content||[]).map(x=>x.text||'').filter(Boolean).join(''))||'';
}
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {});

  if (req.method === 'GET' && req.url === '/api/health') {
    return send(res, 200, { ok: true, service: 'MedRise API' });
  }

  if (req.method === 'POST' && req.url === '/api/signup') {
    try {
      const { name, email, password } = await readJson(req);
      const cleanName = String(name || '').trim();
      const cleanEmail = String(email || '').trim().toLowerCase();
      const cleanPassword = String(password || '');

      if (cleanName.length < 2) return send(res, 400, { error: 'Please enter a valid name.' });
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) return send(res, 400, { error: 'Please enter a valid email address.' });
      if (cleanPassword.length < 8 || !/[A-Za-z]/.test(cleanPassword) || !/\d/.test(cleanPassword) || !/[^A-Za-z0-9]/.test(cleanPassword)) {
        return send(res, 400, { error: 'Password does not meet the required strength.' });
      }

      const existing = await getUserByEmail(cleanEmail);
      if (existing) return send(res, 409, { error: 'An account with that email already exists.' });

      const { salt, hash } = hashPassword(cleanPassword);
      const id = crypto.randomUUID();
      const trialEndsAt = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);
      const result = await pool.query(`
        INSERT INTO users (id, name, email, password_hash, password_salt, trial_ends_at, premium, plan, progress)
        VALUES ($1, $2, $3, $4, $5, $6, FALSE, '', '{}'::jsonb)
        RETURNING *
      `, [id, cleanName, cleanEmail, hash, salt, trialEndsAt]);
      const user = rowToUser(result.rows[0]);
      const token = await createSession(user.id);
      return send(res, 201, { ok: true, user: publicUser(user), progress: progressOf(user), token });
    } catch (err) {
      if (err.code === '23505') return send(res, 409, { error: 'An account with that email already exists.' });
      return send(res, 400, { error: err.message || 'Unable to create account.' });
    }
  }

  if (req.method === 'POST' && req.url === '/api/login') {
    try {
      const { email, password } = await readJson(req);
      const cleanEmail = String(email || '').trim().toLowerCase();
      const cleanPassword = String(password || '');
      if (!cleanEmail || !cleanPassword) return send(res, 400, { error: 'Email and password are required.' });

      const user = await getUserByEmail(cleanEmail);
      if (!user || !validPassword(cleanPassword, user.passwordSalt, user.passwordHash)) {
        return send(res, 401, { error: 'Invalid email or password.' });
      }
      const token = await createSession(user.id);
      return send(res, 200, { ok: true, user: publicUser(user), progress: progressOf(user), token });
    } catch (err) {
      return send(res, 400, { error: err.message || 'Unable to log in.' });
    }
  }

  if (req.method === 'GET' && req.url === '/api/me') {
    try {
      const user = await authUser(req);
      if (!user) return send(res, 401, { error: 'Not authenticated.' });
      return send(res, 200, { ok: true, user: publicUser(user) });
    } catch (err) { return send(res, 500, { error: 'Unable to load account.' }); }
  }

  if (req.method === 'GET' && req.url === '/api/progress') {
    try {
      const user = await authUser(req);
      if (!user) return send(res, 401, { error: 'Not authenticated.' });
      return send(res, 200, { ok: true, progress: progressOf(user) });
    } catch (err) { return send(res, 500, { error: 'Unable to load progress.' }); }
  }

  if (req.method === 'PUT' && req.url === '/api/progress') {
    try {
      const user = await authUser(req);
      if (!user) return send(res, 401, { error: 'Not authenticated.' });
      const body = await readJson(req);
      const progress = body && typeof body.progress === 'object' ? body.progress : {};
      await pool.query('UPDATE users SET progress = $1::jsonb, updated_at = NOW() WHERE id = $2', [JSON.stringify(progress), user.id]);
      return send(res, 200, { ok: true });
    } catch (err) { return send(res, 400, { error: err.message || 'Unable to save progress.' }); }
  }

  if (req.method === 'POST' && req.url === '/api/ai/ask') {
    try {
      const user = await authUser(req);
      if (!user) return send(res, 401, { error: 'Log in to use the AI tutor.' });
      if (!await allowAI(user.id)) return send(res, 429, { error: 'AI usage limit reached for this account. Try again later.' });
      const body = await readJson(req);
      const question = String(body.question || '').trim();
      if (!question || question.length > 4000) return send(res, 400, { error: 'Question must be between 1 and 4000 characters.' });
      const subject = String(body.subject || 'all');
      const topic = String(body.topic || 'all');
      const instructions = 'You are MedRise AI, an educational tutor for preclinical medical students. Explain Anatomy, Physiology and Biochemistry clearly at university level. Prefer structured explanations, mechanisms, clinically relevant correlations and short examples. Do not diagnose a real person or give individualized treatment instructions. If a question is outside study scope, say so briefly. Current study context: subject='+subject+', topic='+topic+'.';
      const answer = await openAIResponse([{role:'user',content:question}], instructions);
      return send(res, 200, { ok: true, answer });
    } catch (err) { return send(res, 500, { error: err.message || 'AI tutor is unavailable.' }); }
  }

  if (req.method === 'POST' && req.url === '/api/ai/generate') {
    try {
      const user = await authUser(req);
      if (!user) return send(res, 401, { error: 'Log in to use AI generation.' });
      if (!await allowAI(user.id)) return send(res, 429, { error: 'AI usage limit reached for this account. Try again later.' });
      const body = await readJson(req);
      const topic = String(body.topic || '').trim();
      const subject = String(body.subject || 'all');
      if (!topic || topic.length > 160) return send(res, 400, { error: 'Please provide a valid topic.' });
      const instructions = 'Create exactly 5 difficult university-level preclinical medical MCQs. Return ONLY valid JSON as an array. Each item must have q (string), o (array of exactly 4 strings), c (integer 0-3), e (short explanation string), s (one of A/P/B). Do not use markdown. Subject context='+subject+'; topic='+topic+'.';
      const raw = await openAIResponse([{role:'user',content:'Generate difficult MCQs on '+topic}], instructions);
      let cleaned=raw.trim().replace(/^```json\s*/i,'').replace(/```$/,'').trim();
      let questions=JSON.parse(cleaned);
      if(!Array.isArray(questions)) throw new Error('AI returned an invalid question set.');
      questions=questions.slice(0,5).filter(x=>x&&typeof x.q==='string'&&Array.isArray(x.o)&&x.o.length===4&&Number.isInteger(x.c)&&x.c>=0&&x.c<4).map(x=>({q:x.q,o:x.o,c:x.c,e:String(x.e||''),s:['A','P','B'].includes(x.s)?x.s:subject}));
      return send(res, 200, { ok:true, questions });
    } catch (err) { return send(res, 500, { error: err.message || 'AI generation is unavailable.' }); }
  }

  if (req.method === 'POST' && req.url === '/api/ai/generate-notes') {
    try {
      const user = await authUser(req);
      if (!user) return send(res, 401, { error: 'Log in to generate study material.' });
      if (!await allowAI(user.id)) return send(res, 429, { error: 'AI usage limit reached for this account. Try again later.' });
      const body = await readJson(req);
      const kind = body.kind === 'card' ? 'card' : body.kind === 'mcq' ? 'mcq' : '';
      const subject = ['A','P','B'].includes(body.subject) ? body.subject : 'A';
      const topic = String(body.topic || 'General').trim().slice(0,160) || 'General';
      const files = Array.isArray(body.files) ? body.files.slice(0, MAX_NOTE_FILES) : [];
      if (!kind) return send(res, 400, { error: 'Choose flashcards or MCQs.' });
      if (!files.length) return send(res, 400, { error: 'Attach at least one note.' });
      const content = [{ type:'input_text', text:
        kind === 'mcq'
          ? `Use the attached lecture notes to create exactly 5 difficult university-level preclinical medical MCQs. Subject=${subject}; topic=${topic}. Return ONLY valid JSON array. Each item: {"q":string,"o":[4 strings],"c":integer 0-3,"e":string,"s":"A"|"P"|"B","t":string}. Do not invent facts not supported by the notes unless needed to clarify standard terminology.`
          : `Use the attached lecture notes to create exactly 5 university-level medical flashcards. Subject=${subject}; topic=${topic}. Return ONLY valid JSON array. Each item: {"q":string,"a":string,"e":string,"s":"A"|"P"|"B","t":string}. Keep answers accurate, concise and explanatory.`
      }];
      for (const f of files) {
        if (!f || typeof f.data !== 'string') continue;
        const name = String(f.name || 'note').slice(0,120);
        const type = String(f.type || 'application/octet-stream').toLowerCase();
        const comma = f.data.indexOf(',');
        const b64 = comma >= 0 ? f.data.slice(comma + 1) : f.data;
        const approxBytes = Math.floor(b64.length * 3 / 4);
        if (approxBytes > MAX_NOTE_FILE_BYTES) return send(res, 413, { error: `${name} is too large. Keep each note file under ${Math.round(MAX_NOTE_FILE_BYTES/1000000)} MB.` });
        if (type.startsWith('image/')) content.push({type:'input_image', image_url:f.data, detail:'high'});
        else content.push({type:'input_file', filename:name, file_data:f.data});
      }
      if (content.length === 1) return send(res, 400, { error: 'No supported note files were attached.' });
      const instructions = 'You are MedRise AI, an educational medical study-content generator. Use the supplied notes as the primary source. Produce accurate university-level preclinical material. Never diagnose or provide individualized treatment. Return JSON only when requested.';
      const raw = await openAIResponse([{role:'user',content}], instructions, 2600);
      const cleaned = raw.trim().replace(/^```(?:json)?\s*/i,'').replace(/```$/,'').trim();
      const parsed = JSON.parse(cleaned);
      if (!Array.isArray(parsed)) throw new Error('AI returned an invalid study set.');
      if (kind === 'mcq') {
        const questions = parsed.slice(0,5).filter(x => x && typeof x.q === 'string' && Array.isArray(x.o) && x.o.length === 4 && Number.isInteger(x.c) && x.c >= 0 && x.c < 4)
          .map(x => ({q:x.q, o:x.o.map(String), c:x.c, e:String(x.e||''), s:['A','P','B'].includes(x.s)?x.s:subject, t:String(x.t||topic)}));
        if (questions.length !== 5) throw new Error('AI did not return exactly 5 valid MCQs.');
        return send(res, 200, {ok:true, questions});
      }
      const cards = parsed.slice(0,5).filter(x => x && typeof x.q === 'string' && typeof x.a === 'string')
        .map(x => ({q:x.q, a:x.a, e:String(x.e||''), s:['A','P','B'].includes(x.s)?x.s:subject, t:String(x.t||topic)}));
      if (cards.length !== 5) throw new Error('AI did not return exactly 5 valid flashcards.');
      return send(res, 200, {ok:true, cards});
    } catch (err) { return send(res, 500, { error: err.message || 'Note generation is unavailable.' }); }
  }

  if (req.method === 'POST' && req.url === '/api/logout') {
    const token = bearer(req);
    if (token) await pool.query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash(token)]);
    return send(res, 200, { ok: true });
  }

  // Simple static hosting so MedRise.html and its background image can run from the same origin.
  let pathname = req.url.split('?')[0];
  if (pathname === '/') pathname = '/MedRise.html';
  const safePath = path.normalize(pathname).replace(/^([.][.][/\\])+/, '');
  const filePath = path.join(__dirname, safePath.replace(/^[/\\]/, ''));
  if (req.method === 'GET' && filePath.startsWith(__dirname) && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext = path.extname(filePath).toLowerCase();
    const types = { '.html':'text/html; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.jpeg':'image/jpeg', '.jpg':'image/jpeg', '.png':'image/png', '.webp':'image/webp', '.css':'text/css; charset=utf-8' };
    res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    return fs.createReadStream(filePath).pipe(res);
  }
  send(res, 404, { error: 'Not found' });
});

initDb().then(() => {
  server.listen(PORT, HOST, () => console.log(`MedRise server running at http://${HOST}:${PORT}`));
}).catch(err => {
  console.error('MedRise database initialization failed:', err);
  process.exit(1);
});

process.on('SIGTERM', async () => {
  await pool.end().catch(() => {});
  process.exit(0);
});
process.on('SIGINT', async () => {
  await pool.end().catch(() => {});
  process.exit(0);
});
