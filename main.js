const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const app = express();
const PORT = 3000;

const WELL_KNOWN_URL = 'http://localhost:8080/realms/Test/.well-known/openid-configuration';
const REDIRECT_URI = 'http://localhost:3000/callback';
const CLIENT_ID = process.env.CLIENT_ID || 'node-app';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'CLIENT_SECRET';

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

// Optionnel : vérifie la signature avec la clé publique de Keycloak (JWKS)
async function verifyJwt(token) {
    const [header, payload, signature] = token.split('.');
    const { kid, alg } = decodeJwt(token).header;
    if (alg !== 'RS256') return false;

    const { keys } = await (await fetch(jwks_uri)).json();
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

app.use(session({ secret: crypto.randomBytes(32).toString('hex'), resave: false, saveUninitialized: false }));

// Étape 1 : redirection vers la page de login Keycloak
app.get('/', (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    req.session.state = state;

    const params = new URLSearchParams({
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        response_type: 'code',
        scope: 'openid',
        state,
    });

    res.redirect(`${authorization_endpoint}?${params.toString()}`);
});

// Étape 2 : Keycloak redirige ici après le login
app.get('/callback', async (req, res) => {
    const { state, session_state, code, error, error_description } = req.query;
    console.log('Paramètres reçus :', req.query);

    if (error) return res.status(400).json({ error, error_description });
    if (!state || state !== req.session.state) return res.status(400).send('State invalide');
    delete req.session.state;

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

    // Étape 4 : décodage des tokens (+ vérification de signature)
    const accessToken = decodeJwt(tokenData.access_token);
    const idToken = decodeJwt(tokenData.id_token);
    const signatures = {
        access_token: await verifyJwt(tokenData.access_token),
        id_token: await verifyJwt(tokenData.id_token),
    };

    // Étape 5 : appel du endpoint userinfo avec le token d'accès
    const userInfoResponse = await fetch(userinfo_endpoint, {
        headers: {
            'Authorization': `Bearer ${tokenData.access_token}`,
        },
    });
    const userInfo = await userInfoResponse.json();

    res.json({ access_token: accessToken, id_token: idToken, signatures, userInfo });
});

getInfo().then(() => {
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
});
