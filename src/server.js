const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const express = require('express');
const handlebars = require('express-handlebars');
const path = require('path');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const passport = require('passport');
const Auth0Strategy = require('passport-auth0');
const request = require('request-promise');
const session = require('express-session');
require('cors');
// loading env vars from .env file
require('dotenv').config();

const nonceCookie = 'auth0rization-nonce';
let oidcProviderInfo;

const PORT = process.env.PORT || 3000;

const app = express();

// Configure Passport to use Auth0
const auth0Strategy = new Auth0Strategy(
  {
    domain: process.env.OIDC_PROVIDER,
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/callback'
  },
  (accessToken, refreshToken, extraParams, profile, done) => {
    profile.idToken = extraParams.id_token;
    return done(null, profile);
  }
);
passport.use(auth0Strategy);
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser(crypto.randomBytes(16).toString('hex')));
app.use(
  session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false
  })
);
app.engine('handlebars', handlebars());
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/spruitjes', (req, res) => {
  const { idToken, decodedIdToken } = req.session;
  res.render('spruitjes', {
    idToken,
    decodedIdToken
  });
});

// app.get('/login', (req, res) => {
//
//   // define constants for the authorization request
//   const authorizationEndpoint = oidcProviderInfo['authorization_endpoint'];
//   const responseType = 'id_token';
//   const scope = 'openid';
//   const clientID = process.env.CLIENT_ID;
//   const redirectUri = 'http://localhost:3000/callback';
//   const responseMode = 'form_post';
//   const nonce = crypto.randomBytes(16).toString('hex');
//
//   // define a signed cookie containing the nonce value
//   const options = {
//     maxAge: 1000 * 60 * 15,
//     httpOnly: true, // The cookie only accessible by the web server
//     signed: true // Indicates if the cookie should be signed
//   };
//
//   // add cookie to the response and set custom header to point front-end cell to auth URL
//   res
//     .cookie(nonceCookie, nonce, options)
//     .redirect(
//       authorizationEndpoint +
//       '?response_mode=' + responseMode +
//       '&response_type=' + responseType +
//       '&scope=' + scope +
//       '&client_id=' + clientID +
//       '&redirect_uri=' + redirectUri +
//       '&nonce=' + nonce
//     );
// });

app.get(
  '/login',
  passport.authenticate('auth0', {
    scope: 'openid email profile'
  })
);
// app.post('/callback', async (req, res) => {
//   // take nonce from cookie
//   const nonce = req.signedCookies[nonceCookie];
//   // delete nonce
//   delete req.signedCookies[nonceCookie];
//   // take ID Token posted by the user
//   const { id_token } = req.body;
//   // decode token
//   const decodedToken = jwt.decode(id_token, { complete: true });
//   // get key id
//   const kid = decodedToken.header.kid;
//   // get public key
//   const client = jwksClient({
//     jwksUri: oidcProviderInfo['jwks_uri']
//   });
//   client.getSigningKey(kid, (err, key) => {
//     const signingKey = key.publicKey || key.rsaPublicKey;
//     // verify signature & decode token
//     const verifiedToken = jwt.verify(id_token, signingKey);
//     // check audience, nonce, and expiration time
//     const {
//       nonce: decodedNonce,
//       aud: audience,
//       exp: expirationDate,
//       iss: issuer
//     } = verifiedToken;
//     const currentTime = Math.floor(Date.now() / 1000);
//     const expectedAudience = process.env.CLIENT_ID;
//     if (audience !== expectedAudience ||
//       decodedNonce !== nonce ||
//       expirationDate < currentTime ||
//       issuer !== oidcProviderInfo['issuer']) {
//       // send an unauthorized http status
//       return res.status(401).send();
//     }
//     req.session.decodedIdToken = verifiedToken;
//     req.session.idToken = id_token;
//     // send the decoded version of the ID Token
//     res.redirect('/spruitjes');
//   });
// });

app.get('/callback', async (req, res, next) => {
  passport.authenticate('auth0', (err, user) => {
    if (err) return next(err);
    if (!user) return res.redirect('/login');

    req.logIn(user, function(err) {
      if (err) return next(err);
      res.redirect('/spruitjes');
    });
  })(req, res, next);
});

app.get('/to-dos', async (req, res) => {
  res.status(501).send();
});

app.get('/remove-to-do/:id', async (req, res) => {
  res.status(501).send();
});


const { OIDC_PROVIDER } = process.env;
console.log({ OIDC_PROVIDER });
const discEnd = `https://${OIDC_PROVIDER}/.well-known/openid-configuration`;
request(discEnd).then((res) => {
  oidcProviderInfo = JSON.parse(res);
  app.listen(PORT, () => {
    console.log(`Server running on ${PORT}`);
  });
}).catch((error) => {
  console.error(error);
  console.error('Unable to get OIDC endpoints for ${OIDC_PROVIDER}');
  process.exit(1);
});

