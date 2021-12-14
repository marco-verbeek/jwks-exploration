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

const JWKS = jose.createRemoteJWKSet(new URL('http://localhost:3000/.well-known/jwks.json'));

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
  .setProtectedHeader({ alg: 'ES256', kid: 'example:kid' })
  .setIssuedAt()
  .setIssuer('example:issuer')
  .setAudience('example:audience')
  .setExpirationTime('10m')
  .sign(privateKey)

  res.send({ token: jwt });
});

/**
 * This endpoint is weird: it tries to simulate the LMS.
 * First, it will get all the JWK Sets,
 * Then, it will find the correct one using the provided kid,
 * Finally, it will try to JwtVerify it using that JWK.
 */
app.get('/check/:jwt', async (req, res, next) => {
  try {
    const protectedHeader = jose.decodeProtectedHeader(req.params.jwt);

    await jose.jwtVerify(req.params.jwt, await JWKS({alg: protectedHeader.alg, kid: protectedHeader.kid}, {}), {
      issuer: 'example:issuer',
      audience: 'example:audience'
    });

    res.send({token: req.params.jwt, correct: true});
  } catch (err) {
    console.log(err);
    res.send({token: req.params.jwt, correct: false});
  }
});

app.get('/.well-known/jwks.json', async (req, res, next) => {
  const jwk = await jose.exportJWK(publicKey);
  jwk.kid = "example:kid";

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
