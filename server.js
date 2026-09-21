const session = require('express-session');
const crypto = require('node:crypto');
const express = require('express');

const well_known_url = process.env.WELL_KNOWN_URL;
let issuer, authorization_endpoint, token_endpoint, userinfo_endpoint;

const app = express();
const port = 3000;

async function getInfo() {
    let data = await (await fetch(well_known_url)).json();
    issuer = data.issuer;
    authorization_endpoint = data.authorization_endpoint;
    token_endpoint = data.token_endpoint;
    userinfo_endpoint = data.userinfo_endpoint;

    console.log(userinfo_endpoint);
}

// getInfo();

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Serveur en écoute sur http://localhost:${port}`);
});










