require('dotenv').config();

const session = require('express-session');
const crypto = require('node:crypto');
const express = require('express');

const well_known_url = process.env.WELL_KNOWN_URL;


const client_id =  process.env.CLIENT_ID;
const client_secret = process.env.CLIENT_SECRET;

const port = 3000;
const redirect_uri = `http://localhost:${port}/redirect`;

let issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri;

const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }, 
}));

async function getInfo() {
  const data = await (await fetch(well_known_url)).json();
  issuer = data.issuer;
  authorization_endpoint = data.authorization_endpoint;
  token_endpoint = data.token_endpoint;
  userinfo_endpoint = data.userinfo_endpoint;
  jwks_uri = data.jwks_uri;
  console.log({ issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri });
}

function decodeJwt(token) {
  const [header, payload, signature] = token.split('.');
  return {
    header: JSON.parse(Buffer.from(header, 'base64url').toString('utf8')),
    payload: JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')),
    signature,
  };
}

async function verifyJwt(token) {
  const [headerB64, payloadB64, signatureB64] = token.split('.');
  const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));

  if (header.alg !== 'RS256') {
    throw new Error(`Algorithme non supporté : ${header.alg}`);
  }

  const { keys } = await (await fetch(jwks_uri)).json();
  const jwk = keys.find((k) => k.kid === header.kid && k.use === 'sig');
  if (!jwk) throw new Error(`Aucune clé trouvée pour kid=${header.kid}`);

  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });

  const valid = crypto.verify(
    'sha256',
    Buffer.from(`${headerB64}.${payloadB64}`),
    publicKey,
    Buffer.from(signatureB64, 'base64url'),
  );

  if (!valid) throw new Error('Signature invalide');

  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== issuer) throw new Error(`Issuer inattendu : ${payload.iss}`);
  if (payload.exp < now) throw new Error('Token expiré');

  return true;
}

app.get('/', (req, res) => {
  res.send('<h1>TP OIDC</h1><a href="/login">Se connecter avec Keycloak</a>');
});

app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.state = state;

  const params = new URLSearchParams({
    redirect_uri,
    client_id,
    response_type: 'code',
    scope: 'openid',
    state,
  });

  res.redirect(`${authorization_endpoint}?${params.toString()}`);
});

app.get('/redirect', async (req, res) => {
  const { code, state, session_state, error, error_description } = req.query;
  console.log('Paramètres reçus :', req.query);

  if (error) {
    return res.status(400).send(`Erreur IdP : ${error} - ${error_description}`);
  }

  if (!state || state !== req.session.state) {
    return res.status(400).send('State invalide');
  }
  delete req.session.state;

  try {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id,
      client_secret,
      redirect_uri,
      state,
      session_state: session_state || '',
      code,
    });

    const tokenRes = await fetch(token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    const tokens = await tokenRes.json();

    if (!tokenRes.ok) {
      return res.status(400).send(`<pre>Erreur token : ${JSON.stringify(tokens, null, 2)}</pre>`);
    }

    const idToken = decodeJwt(tokens.id_token);
    const accessToken = decodeJwt(tokens.access_token);

    let signatureStatus;
    try {
      await verifyJwt(tokens.id_token);
      await verifyJwt(tokens.access_token);
      signatureStatus = 'Signatures valides';
    } catch (e) {
      signatureStatus = `${e.message}`;
    }

    const userinfoRes = await fetch(userinfo_endpoint, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const userinfo = await userinfoRes.json();

    req.session.tokens = tokens;

    res.send(`
      <h1>Authentifié</h1>
      <p>${signatureStatus}</p>
      <h2>ID token</h2>
      <pre>${JSON.stringify({ header: idToken.header, payload: idToken.payload }, null, 2)}</pre>
      <h2>Access token</h2>
      <pre>${JSON.stringify({ header: accessToken.header, payload: accessToken.payload }, null, 2)}</pre>
      <h2>UserInfo</h2>
      <pre>${JSON.stringify(userinfo, null, 2)}</pre>
      <a href="/">Accueil</a>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send(`Erreur : ${e.message}`);
  }
});


getInfo()
  .then(() => {
    app.listen(port, () => {
      console.log(`Serveur en écoute sur http://localhost:${port}`);
    });
  })
  .catch((e) => {
    console.error('Impossible de charger la configuration OIDC :', e);
    process.exit(1);
  });