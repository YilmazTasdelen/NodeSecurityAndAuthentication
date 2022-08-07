const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');

const PORT = 3001;

const app = express();

app.get('/secret', (req, res) => {
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