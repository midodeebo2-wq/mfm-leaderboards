// Cloudflare Worker — mfm-leaderboards
// Paste this into Cloudflare Dashboard → Workers → your worker → Edit code

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        // CORS headers
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        // POST /submit — game submits score
        if (request.method === 'POST' && url.pathname === '/submit') {
            try {
                const body = await request.json();
                const { user_id, name, score, chapter, stage } = body;

                // Validate
                if (!user_id || !name || typeof score !== 'number' || score < 0 || score > 9999999) {
                    return new Response('Invalid', { status: 400, headers: corsHeaders });
                }
                if (name.length > 20 || user_id.length > 30) {
                    return new Response('Too long', { status: 400, headers: corsHeaders });
                }

                // Write to Firebase using REST API with service account
                const projectId = env.FIREBASE_PROJECT_ID;
                const clientEmail = env.FIREBASE_CLIENT_EMAIL;
                const privateKey = env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');

                // Get access token
                const token = await getAccessToken(clientEmail, privateKey);

                // Write document
                const docUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/scores/${user_id}`;
                const docBody = {
                    fields: {
                        name: { stringValue: name },
                        score: { integerValue: score.toString() },
                        chapter: { integerValue: (chapter || 1).toString() },
                        stage: { integerValue: (stage || 1).toString() },
                    }
                };

                const firestoreRes = await fetch(docUrl, {
                    method: 'PATCH',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(docBody),
                });

                if (!firestoreRes.ok) {
                    const err = await firestoreRes.text();
                    return new Response(`Firestore error: ${err}`, { status: 500, headers: corsHeaders });
                }

                return new Response(JSON.stringify({ ok: true }), {
                    status: 200,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });

            } catch (e) {
                return new Response(`Error: ${e.message}`, { status: 500, headers: corsHeaders });
            }
        }

        // GET /leaderboard — return top 100 scores
        if (request.method === 'GET' && url.pathname === '/leaderboard') {
            try {
                const projectId = env.FIREBASE_PROJECT_ID;
                const clientEmail = env.FIREBASE_CLIENT_EMAIL;
                const privateKey = env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');

                const token = await getAccessToken(clientEmail, privateKey);

                // Query Firestore, ordered by score descending
                const queryUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/scores`;
                const queryBody = {
                    structuredQuery: {
                        from: [{ collectionId: 'scores' }],
                        orderBy: [{ field: { fieldPath: 'score' }, direction: 'DESCENDING' }],
                        limit: 100,
                    }
                };

                const res = await fetch(queryUrl, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(queryBody),
                });

                if (!res.ok) {
                    return new Response('[]', { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
                }

                const data = await res.json();
                const players = (data.document || []).map(doc => {
                    const f = doc.fields || {};
                    return {
                        name: f.name?.stringValue || '???',
                        score: parseInt(f.score?.integerValue || '0'),
                        chapter: parseInt(f.chapter?.integerValue || '1'),
                        stage: parseInt(f.stage?.integerValue || '1'),
                    };
                });

                return new Response(JSON.stringify({ players }), {
                    status: 200,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });

            } catch (e) {
                return new Response('[]', { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
        }

        return new Response('Not found', { status: 404, headers: corsHeaders });
    }
};

// JWT sign for Firebase service account
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
