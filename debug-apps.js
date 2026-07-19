const fs = require('fs');
const path = require('path');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const privateKey = fs.readFileSync(path.join(process.cwd(), 'private.pem'), 'utf8');
const tenant = process.env.QLIK_TENANT_URL.replace(/\/$/, '');
const payload = {
  jti: 'debug-apps',
  iss: process.env.QLIK_JWT_ISSUER,
  sub: 'thiagomsimoes@poli.ufrj.br',
  subType: 'user',
  aud: 'qlik.api/login-jwt',
  nbf: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 300,
  name: 'Thiago M. Simões',
  email: 'thiagomsimoes@poli.ufrj.br',
  email_verified: true,
  groups: []
};
const token = jwt.sign(payload, privateKey, { algorithm: 'RS256', keyid: process.env.QLIK_JWT_KEY_ID });
(async () => {
  const res = await fetch(`${tenant}/api/v1/items?resourceType=app&limit=5`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  const text = await res.text();
  console.log('status', res.status);
  console.log(text);
})();
