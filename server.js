const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const { Strategy } = require('passport-google-oauth20');
const passport = require('passport');
const cookieSession = require('cookie-session');

require('dotenv').config();

const PORT = 3000;

const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshToken, profile, done) {
    console.log('Google profile', profile);
    done(null, profile); // error=null and user data
}


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
// cookie needs to be set up before passport use it so we will ad middleware here before password midw.
app.use(cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,          // life time in ms 
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2], // for sign and verify cookies. Have at least 2 key for dont logut active users while updatin one of the keys                
}));


app.use(passport.initialize());
app.use(passport.session()); //its authenticate to session that sended to server

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// app.use((req, res, next) => {
//     const isLoggedIn = true; //TODO
//     if (!isLoggedIn) {
//         return res.status(401).json({ error: 'u must login' });
//     }
// })

// Save the session to the cookie
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Read the session from the cookie
passport.deserializeUser((id, done) => {
    // User.findById(id).then(user => {
    //   done(null, user);
    // });
    done(null, id);
});

function checkLoggedIn(req, res, next) { //req.user
    console.log('current user is: ', req.user);
    const isLoggedIn = req.isAuthenticated() && req.user;
    if (!isLoggedIn) {
        return res.status(401).json({ error: 'u must login' });
    }
}


app.get('/auth/google',
    passport.authenticate('google', {
        //scope:['email','profile'] //scopes we need
        scope: ['email']
    }));

app.get('/auth/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/failure',
        successRedirect: '/',
        //session: true, // default true
    }),
    (req, res) => {
        // res.redirect();
        console.log('google callback');
    });

app.get('/failure', (req, res) => {
    return res.send('Failed to log in!');
});


app.get('/auth/logut', (req, res) => {
    req.logout(); //Removes req.user and clears any logged in session
    return res.redirect('/');
});


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