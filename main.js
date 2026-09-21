require('dotenv').config();

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const app = express();
const PORT = 3000;

for (const name of ['WELL_KNOWN_URL', 'CLIENT_ID', 'CLIENT_SECRET', 'SESSION_SECRET']) {
    if (!process.env[name]) {
        console.error(`Variable manquante dans .env : ${name}`);
        process.exit(1);
    }
}

const { WELL_KNOWN_URL, CLIENT_ID, CLIENT_SECRET, SESSION_SECRET } = process.env;
const REDIRECT_URI = `http://localhost:${PORT}/redirect`;

let issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri;

async function getInfo() {
    let data = await (await fetch(WELL_KNOWN_URL)).json();
    issuer = data.issuer;
    authorization_endpoint = data.authorization_endpoint;
    token_endpoint = data.token_endpoint;
    userinfo_endpoint = data.userinfo_endpoint;
    jwks_uri = data.jwks_uri;
}

// Un JWT = header.payload.signature, les deux premières parties sont du JSON en base64url
function decodeJwt(token) {
    const [header, payload] = token.split('.');
    return {
        header: JSON.parse(Buffer.from(header, 'base64url').toString()),
        payload: JSON.parse(Buffer.from(payload, 'base64url').toString()),
    };
}

// Vérifie la signature avec la clé publique de Keycloak (JWKS)
function verifySignature(token, keys) {
    const [header, payload, signature] = token.split('.');
    const { kid, alg } = decodeJwt(token).header;
    if (alg !== 'RS256') return false;

    const jwk = keys.find(k => k.kid === kid);
    if (!jwk) return false;

    const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    return crypto.verify(
        'RSA-SHA256',
        Buffer.from(`${header}.${payload}`),
        publicKey,
        Buffer.from(signature, 'base64url'),
    );
}

// Renvoie la liste des erreurs de validation (vide si le token est valide)
function validateToken(token, keys, expected) {
    const errors = [];
    const { payload } = decodeJwt(token);

    if (!verifySignature(token, keys)) errors.push('signature invalide');
    if (payload.iss !== issuer) errors.push('iss invalide');
    if (!payload.exp || payload.exp * 1000 <= Date.now()) errors.push('token expiré');

    if (expected.aud) {
        const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        if (!aud.includes(expected.aud)) errors.push('aud invalide');
    }
    if (expected.azp && payload.azp !== expected.azp) errors.push('azp invalide');
    if (expected.nonce && payload.nonce !== expected.nonce) errors.push('nonce invalide');

    return errors;
}

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax' },
}));

// Étape 1 : redirection vers la page de login Keycloak
app.get('/', (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    req.session.state = state;
    req.session.nonce = nonce;

    const params = new URLSearchParams({
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        response_type: 'code',
        scope: 'openid',
        state,
        nonce,
    });

    res.redirect(`${authorization_endpoint}?${params.toString()}`);
});

// Étape 2 : Keycloak redirige ici après le login
app.get('/redirect', async (req, res) => {
    const { state, session_state, code, error, error_description } = req.query;
    const { state: expectedState, nonce } = req.session;
    delete req.session.state;
    delete req.session.nonce;

    if (error) return res.status(400).json({ error, error_description });
    if (!state || !expectedState || state !== expectedState) return res.status(400).send('State invalide');

    // Étape 3 : échange du code contre les tokens (en backend)
    const tokenResponse = await fetch(token_endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            redirect_uri: REDIRECT_URI,
            state,
            session_state: session_state ?? '',
            code,
        }),
    });

    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok) return res.status(400).json(tokenData);

    // Étape 4 : validation des tokens (signature, iss, exp, aud/azp, nonce) puis décodage
    const { keys } = await (await fetch(jwks_uri)).json();
    const errors = {
        id_token: validateToken(tokenData.id_token, keys, { aud: CLIENT_ID, nonce }),
        access_token: validateToken(tokenData.access_token, keys, { azp: CLIENT_ID }),
    };
    if (errors.id_token.length || errors.access_token.length) {
        return res.status(401).json({ error: 'Token invalide', details: errors });
    }

    // Étape 5 : appel du endpoint userinfo avec le token d'accès
    const userInfoResponse = await fetch(userinfo_endpoint, {
        headers: {
            'Authorization': `Bearer ${tokenData.access_token}`,
        },
    });
    const userInfo = await userInfoResponse.json();

    res.json({
        id_token: decodeJwt(tokenData.id_token),
        access_token: decodeJwt(tokenData.access_token),
        userInfo,
    });
});

getInfo().then(() => {
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
});
