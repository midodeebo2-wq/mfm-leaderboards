// Cloudflare Worker — mfm-leaderboards
// Env vars needed: FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY, LB_SECRET

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        // POST /check-user — check if user exists (read-only, no write)
        if (request.method === 'POST' && url.pathname === '/check-user') {
            try {
                const body = await request.json();
                const { uid } = body;
                if (!uid) {
                    return new Response(JSON.stringify({ found: false }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
                }
                const existing = await firebaseGet(uid, env);
                if (existing) {
                    return new Response(JSON.stringify({ found: true, ...existing }), {
                        status: 200,
                        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                    });
                }
                return new Response(JSON.stringify({ found: false }), {
                    status: 200,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });
            } catch (e) {
                return new Response(JSON.stringify({ found: false }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
        }

        // POST /submit — verify HMAC + write score
        if (request.method === 'POST' && url.pathname === '/submit') {
            try {
                const body = await request.json();
                const { uid, p, name } = body;

                if (!uid || !p || !name) {
                    return new Response(JSON.stringify({ error: 'Missing fields' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
                }
                if (uid.length > 30 || name.length > 20) {
                    return new Response(JSON.stringify({ error: 'Too long' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
                }

                // Verify HMAC
                const payload = await verifyPayload(p, env.LB_SECRET);
                if (!payload) {
                    return new Response(JSON.stringify({ error: 'Invalid signature' }), { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
                }

                // Check if user already exists
                const existing = await firebaseGet(uid, env);

                // New user: check name uniqueness
                if (!existing) {
                    const nameTaken = await firebaseQueryByName(name, env);
                    if (nameTaken) {
                        return new Response(JSON.stringify({ error: 'name_taken' }), { status: 409, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
                    }
                }

                // Only update if score is higher or new user
                if (existing) {
                    if (payload.score <= existing.score) {
                        return new Response(JSON.stringify({ error: 'score_not_higher', currentBest: existing.score }), { status: 409, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
                    }
                }

                // Write to Firebase
                await firebaseSet(uid, {
                    name: name,
                    score: payload.score,
                    chapter: payload.ch,
                    stage: payload.st,
                }, env);

                // Get rank
                const rank = await firebaseGetRank(payload.score, env);

                return new Response(JSON.stringify({ ok: true, rank }), {
                    status: 200,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });

            } catch (e) {
                return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
        }

        // POST /check-name — check if name is taken
        if (request.method === 'POST' && url.pathname === '/check-name') {
            try {
                const body = await request.json();
                const { name } = body;
                if (!name) {
                    return new Response(JSON.stringify({ error: 'Missing name' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
                }
                const taken = await firebaseQueryByName(name, env);
                return new Response(JSON.stringify({ taken }), {
                    status: 200,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });
            } catch (e) {
                return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
        }

        // GET /leaderboard — read-only (public)
        if (request.method === 'GET' && url.pathname === '/leaderboard') {
            try {
                const players = await firebaseGetLeaderboard(env);
                return new Response(JSON.stringify({ players }), {
                    status: 200,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });
            } catch (e) {
                return new Response(JSON.stringify({ players: [] }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
        }

        return new Response('Not found', { status: 404, headers: corsHeaders });
    }
};

// ============================================
// HMAC verification (server-side)
// ============================================
async function verifyPayload(p, secret) {
    const dot = p.lastIndexOf('.');
    if (dot === -1) return null;
    const dataB64 = p.substring(0, dot);
    const sig = p.substring(dot + 1);
    const data = base64Decode(dataB64);

    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sigBytes = await crypto.subtle.sign('HMAC', key, enc.encode(data));
    const expected = b64EncodeUrl(new Uint8Array(sigBytes));

    if (sig !== expected) return null;
    const parts = data.split('|');
    if (parts.length !== 3) return null;
    return { score: parseInt(parts[0]), ch: parseInt(parts[1]), st: parseInt(parts[2]) };
}

function base64Decode(b64) {
    const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
    let s = '';
    for (let i = 0; i < bin.length; i++) s += bin[i];
    return s;
}

function b64EncodeUrl(bytes) {
    let s = ''; bytes.forEach(b => s += String.fromCharCode(b));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ============================================
// Firebase REST API helpers
// ============================================
async function getAccessToken(clientEmail, privateKey) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iss: clientEmail,
        scope: 'https://www.googleapis.com/auth/datastore',
        aud: 'https://oauth2.googleapis.com/token',
        iat: now,
        exp: now + 3600,
    };

    const header = { alg: 'RS256', typ: 'JWT' };
    const enc = s => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const jwtPayload = enc(JSON.stringify(payload));
    const jwtHeader = enc(JSON.stringify(header));
    const toSign = `${jwtHeader}.${jwtPayload}`;

    const key = await crypto.subtle.importKey(
        'pkcs8',
        pemToArrayBuffer(privateKey),
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(toSign));
    const jwt = `${toSign}.${enc(String.fromCharCode(...new Uint8Array(sig)))}`;

    const res = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
    });

    const data = await res.json();
    return data.access_token;
}

function pemToArrayBuffer(pem) {
    const b64 = pem.replace(/-----BEGIN PRIVATE KEY-----/, '')
                    .replace(/-----END PRIVATE KEY-----/, '')
                    .replace(/\s/g, '');
    const binary = atob(b64);
    const buffer = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) buffer[i] = binary.charCodeAt(i);
    return buffer.buffer;
}

async function getAuthHeader(env) {
    const token = await getAccessToken(env.FIREBASE_CLIENT_EMAIL, env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'));
    return `Bearer ${token}`;
}

// Read a document by ID
async function firebaseGet(uid, env) {
    const auth = await getAuthHeader(env);
    const docUrl = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/scores/${uid}`;
    const res = await fetch(docUrl, { headers: { 'Authorization': auth } });
    if (!res.ok) return null;
    const data = await res.json();
    if (!data.fields) return null;
    return {
        name: data.fields.name?.stringValue || '',
        score: parseInt(data.fields.score?.integerValue || '0'),
        chapter: parseInt(data.fields.chapter?.integerValue || '1'),
        stage: parseInt(data.fields.stage?.integerValue || '1'),
    };
}

// Write a document
async function firebaseSet(uid, data, env) {
    const auth = await getAuthHeader(env);
    const docUrl = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/scores/${uid}`;
    const body = {
        fields: {
            name: { stringValue: data.name },
            score: { integerValue: data.score.toString() },
            chapter: { integerValue: (data.chapter || 1).toString() },
            stage: { integerValue: (data.stage || 1).toString() },
        }
    };
    await fetch(docUrl, {
        method: 'PATCH',
        headers: { 'Authorization': auth, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
}

// Check if name is taken
async function firebaseQueryByName(name, env) {
    const auth = await getAuthHeader(env);
    const queryUrl = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/scores`;
    const res = await fetch(queryUrl, { headers: { 'Authorization': auth } });
    if (!res.ok) return false;
    const data = await res.json();
    const docs = data.documents || [];
    return docs.some(doc => {
        const f = doc.fields || {};
        return f.name?.stringValue === name;
    });
}

// Get rank for a score
async function firebaseGetRank(score, env) {
    const auth = await getAuthHeader(env);
    const queryUrl = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/scores`;
    const res = await fetch(queryUrl, { headers: { 'Authorization': auth } });
    if (!res.ok) return 0;
    const data = await res.json();
    const docs = data.documents || [];
    return docs.filter(doc => {
        const f = doc.fields || {};
        return parseInt(f.score?.integerValue || '0') > score;
    }).length;
}

// Get top 100 leaderboard
async function firebaseGetLeaderboard(env) {
    const auth = await getAuthHeader(env);
    const queryUrl = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/scores`;
    const res = await fetch(queryUrl, { headers: { 'Authorization': auth } });
    if (!res.ok) return [];
    const data = await res.json();
    const docs = data.documents || [];
    const players = docs.map(doc => {
        const f = doc.fields || {};
        const docId = doc.name ? doc.name.split('/').pop() : '';
        return {
            uid: docId,
            name: f.name?.stringValue || '???',
            score: parseInt(f.score?.integerValue || '0'),
            chapter: parseInt(f.chapter?.integerValue || '1'),
            stage: parseInt(f.stage?.integerValue || '1'),
        };
    });
    players.sort((a, b) => b.score - a.score);
    return players.slice(0, 100);
}
