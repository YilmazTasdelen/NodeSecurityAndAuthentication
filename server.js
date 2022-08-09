const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const pasport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const passport = require('passport');

require('dotenv').config();

const PORT = 3001;

const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
};

const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback',
    clientId: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshToken, profile, done) {
    console.log('Google profile', profile);
    done(null, profile);
}

app.use(verifyCallback);

const app = express();
/***
 * for securing some information on response headers like this api developed by express
 * x-powered-by header for example
 * additionall this library 
 * set scritct-tansport-security tue which means turn all http req into https
last but not least sets the content-security-policy header  
which is provide protection from cross side scripting attack.
cross-side-scripting is like sql injection. user send script to db which is running on ever user screen!!. that script can steal user tokens and session or cookies etc.

By default, Helmet sets the following headers:

Content-Security-Policy: default-src 'self';base-uri 'self';block-all-mixed-content;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Expect-CT: max-age=0
Origin-Agent-Cluster: ?1
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-DNS-Prefetch-Control: off
X-Download-Options: noopen
X-Frame-Options: SAMEORIGIN
X-Permitted-Cross-Domain-Policies: none
X-XSS-Protection: 0
 */
app.use(helmet());
app.use(passport.initialize());

app.use(new Strategy({

}))

// app.use((req, res, next) => {
//     const isLoggedIn = true; //TODO
//     if (!isLoggedIn) {
//         return res.status(401).json({ error: 'u must login' });
//     }
// })



function checkLoggedIn(req, res, next) {
    const isLoggedIn = true; //TODO
    if (!isLoggedIn) {
        return res.status(401).json({ error: 'u must login' });
    }
}


app.get('/auth/google', (req, res) => { });

app.get('/auth/google/callback', (req, res) => { });

app.get('/auth/logut', (req, res) => { });


app.get('/secret', checkLoggedIn, (req, res) => {
    res.sendFile(`some secret value: 48`);
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// to create ssl certificate: openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365
//-x509 means self signed certificate
//4036 is size of the key
//nodes just for development that alows us the acces password(pass isnt necessary for development) without doing anthing
//cert.pen is public  which is browser will check who is owner of server
//cert.pem is private
//-days 365 how many days this certificate will be valid 
https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
}, app).listen(PORT, () => {
    console.log(`Listening on port ${PORT}...`);
});