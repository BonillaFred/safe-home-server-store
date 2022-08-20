const openpgp = require('openpgp');

const express = require('express');
var cors = require('cors')

const corsOptions = {
  "origin": "*",
  "methods": "GET,POST",
  "preflightContinue": false,
  "optionsSuccessStatus": 204

}
//https://stackoverflow.com/questions/11744975/enabling-https-on-express-js
// Following from: 
let fs = require('fs')
let https = require('https')




const app = express();
app.use(express.json())
app.use(cors(corsOptions))



//TODO:: make this an env varible later on. Make it STD
const PORT = 8080;

function writeLog(ip) {
  let fs = require('fs')
  let time = new Date(Date.now())
  fs.appendFile("logs.log", ip.toString() + "\t" + time.toString() + "\n", function (err) {  fs.close });
  fs.close
}


// ONLY REALLY NEEDS TO BE CALLED ONCE IN A WHILE
async function makeKeyPair() {
  const keyEnv = require('./env/key_env.json');

  const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
    type: keyEnv['type'],
    curve: keyEnv['curve'],
    userIDs: [{ name: 'HomeServerMainId' }],
    passphrase: keyEnv["passphrase"],
    format: keyEnv['format']
  });
  x = { "privateKey": privateKey, "publicKey": publicKey, "revocationCertificate": revocationCertificate };
  x = JSON.stringify(x);

  fs = require('fs')
  fs.writeFile("env.json", x, function (err) { console.log("running" + x) });
  fs.close
  console.log({ "privateKey": privateKey, "publicKey": publicKey, "revocationCertificate": revocationCertificate });
}


async function encryptMessages(pubKey, message) {
  const publicKey = await openpgp.readKey({ armoredKey: pubKey });

  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: message }),
    encryptionKeys: publicKey,
  });
  return encrypted;
}

async function decryptMessage(encMessage) {
  let env = require('./env/env.json');
  let key_env = require('./env/key_env.json')

  let priKey = env["privateKey"];

  const passphrase = key_env['passphrase'];

  const privateKey = await openpgp.decryptKey({
    privateKey: await openpgp.readPrivateKey({ armoredKey: priKey }),
    passphrase
  });

  let msg = await openpgp.readMessage({ armoredMessage: encMessage })

  const { data: decrypted } = await openpgp.decrypt({
    message: msg,
    decryptionKeys: privateKey
  });

  return decrypted;
}

async function getPublicKey() {
  let env = require('./env/env.json');
  return {
    "publickey":
      env['publicKey']
  };
}

app.get("/", (req, res) => {
  writeLog(req.ip);
  res.status(200).send("<h1>SYSTEM RUNNING... READY TO ACCEPT REQUESTS</h1>");

});

app.get("/publickey", (req, res) => {

  writeLog(req.ip);
  Promise.resolve(getPublicKey()).then((result) => {
    res.status(200).send(
      JSON.stringify(result));
  }
  ).catch((_) => res.status(400).send({ "ERROR": "COULD NOT SEND PUBLIC KEY" }));

}
);

//TODO:: Find a better logging strat 
app.post("/encrypt", (req, res) => {

  writeLog(req.ip);
  const sentData = JSON.parse(JSON.stringify(req.body));
  const arPublicKey = sentData['publickey'];
  const message = sentData['message'];


  Promise.resolve(encryptMessages(arPublicKey, message)).then((result) => {
    res.status(200).send(
      JSON.stringify(result));
  }
  ).catch((_) => res.status(400).send({ "ERROR": "COULD NOT ENCRYPT DATA" }));

});

//TODO:: Find a better logging strat 
app.post("/decrypt", (req, res) => {
  writeLog(req.ip);
  const message = JSON.parse(JSON.stringify(req.body))['message'];

  Promise.resolve(decryptMessage(message)).then((result) => {
    res.status(200).send(
      JSON.stringify(result));
  }).catch((_) => res.status(400).send({ "ERROR": "COULD NOT DE-CRYPT DATA" }));

});

//Following from: https://stackoverflow.com/questions/11744975/enabling-https-on-express-js
let options = {
  key: fs.readFileSync('./env/crts/internal.pem', 'utf-8'),
  cert: fs.readFileSync('./env/crts/serverCert.crt', 'utf-8'),
  passphrase: require('./env/key_env.json')['CRT_PASS']
}

let httpsServer = https.createServer(options, app);
httpsServer.listen(PORT);

/*
PSUDO DOCS FOR NOW --- NEEDS TESTING AND WORDS
ENCRYPT MESSAGE


GET PUBLIC KEY

const pubKey = {"publickey": "", "message": "something something"};


fetch('http://localhost:8080/publickey', {
  method: 'get', 
})
  .then((response) => response.json())
  .then((data) => { 
    pubKey["publickey"] = data["publickey"]
    console.log('Success:', data);
  })
  .catch((error) => {
    console.error('Error:', error);
  })

fetch('http://localhost:8080/encrypt', {
  method: 'POST', // or 'PUT'
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify(pubKey),
})
  .then((response) => response.json())
  .then((data) => { encMesg = {message:data};
    console.log('Success:', data);
  })
  .catch((error) => {
    console.error('Error:', error);
  });


encMesg = {message: "-----BEGIN PGP MESSAGE-----\n\nwV4DB+OSOUKzh/wSAQdA/eqvn2T3ebX9jbPGPitsVzpausSLRZVgv4KJ6j7L\nFUQwPOV8thQVr/q/OwSzDwzTB36mTp9WixtrAOV/UVZcJx6TIh5EnJtfGBUw\n9MhhvjG40nkBHKDU6I8D/w1hVJFOUNlJVr9IDQE41LPm16Foe7RXfycZ7cR4\nbrb71ZK1EMiMD6iRWL2PzRe2I9edEFVzgVJNYNFG0JTGgVdE8dupD/B/ScN+\n0stovnCmuTYRZbCNI++/rLFHz3cFJ4aS/1aJpT4amcUGPTXkQs6W\n=Nihl\n-----END PGP MESSAGE-----\n"}

fetch('http://localhost:8080/decrypt', {
  method: 'POST', // or 'PUT'
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify(encMesg),
})
  .then((response) => response.json())
  .then((data) => {
    msg = data; //THIS IS THE ENCRYPTED MESSAGE 
    console.log('Success:', data);
  })
  .catch((error) => {
    console.error('Error:', error);
  });

  MAKE CRT:
  openssl req -newkey rsa:4096 -new -keyout internal.pem -out csr.pem
  SIGN CRT: 
  openssl x509 -req -in csr.pem -signkey internal.pem -out serverCert.crt -extfile serverSubjectName.ext
  Have a file containing the following called serverSubjectName.ext:
  subjectAltName = DNS:localhost

  NOTE: to run on lower level ports i.e 443 use the following 
  sudo "$(which node)" .
  PATH VARS to known using sudo
*/
