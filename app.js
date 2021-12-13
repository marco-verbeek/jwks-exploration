const express = require('express');
const createError = require('http-errors');
const morgan = require('morgan');
const jose = require('jose');
const fs = require('fs');
const { createPrivateKey, createPublicKey } = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(morgan('dev'));

const JWKS = jose.createRemoteJWKSet(new URL('http://localhost:3000/jwks'));

let privateKey, publicKey;
(async () => {
  privateKey = createPrivateKey({
    key: fs.readFileSync('./certs/private.pem'),
    format: 'pem',
    encoding: 'utf8'
  });

  publicKey = createPublicKey({
    key: fs.readFileSync('./certs/public.pem'),
    format: 'pem',
    encoding: 'utf8'
  });
})();

app.get('/get-jwt', async (req, res, next) => {
  const jwt = await new jose.SignJWT({ 'name': 'token' })
  .setProtectedHeader({ alg: 'ES256' })
  .setIssuedAt()
  .setIssuer('example:issuer')
  .setAudience('example:audience')
  .setExpirationTime('10m')
  .sign(privateKey)

  res.send({ token: jwt });
});

app.get('/check/:jwt', async (req, res, next) => {
  try {
    await jose.jwtVerify(req.params.jwt, JWKS, {
      issuer: 'example:issuer',
      audience: 'example:audience'
    });

    res.send({token: req.params.jwt, correct: true});
  } catch (err) {
    res.send({token: req.params.jwt, correct: false});
  }
});

app.get('/jwks', async (req, res, next) => {
  const jwk = await jose.exportJWK(publicKey);

  res.send({ keys: [jwk]});
});

app.use((req, res, next) => {
  next(createError.NotFound());
});

app.use((err, req, res, next) => {
  res.status(err.status || 500);
  res.send({
    status: err.status || 500,
    message: err.message,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 @ http://localhost:${PORT}`));
