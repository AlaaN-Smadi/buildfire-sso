const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

const {
  AUTH0_DOMAIN,
  AUTH0_CLIENT_ID,
  AUTH0_CLIENT_SECRET,
  AUTH0_CONNECTION,
  AUTH0_AUDIENCE
} = process.env;

// ----------------------
// LOGIN
// ----------------------
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const response = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, {
      grant_type: 'password',
      username,
      password,
      audience: AUTH0_AUDIENCE,
      client_id: AUTH0_CLIENT_ID,
      client_secret: AUTH0_CLIENT_SECRET,
      scope: 'openid profile email',
      "realm": "Username-Password-Authentication"
    });

    res.json({
      access_token: response.data.access_token,
      id_token: response.data.id_token,
      expires_in: response.data.expires_in
    });
  } catch (err) {
    res.status(401).json({ error: err.response?.data || 'Login failed' });
  }
});

// ----------------------
// REGISTER
// ----------------------
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const response = await axios.post(`https://${AUTH0_DOMAIN}/dbconnections/signup`, {
      client_id: AUTH0_CLIENT_ID,
      username,
      email,
      password,
      connection: AUTH0_CONNECTION
    });
    
    axios.post('https://buildfire-sso.onrender.com/login', {
      username: email,
      password
    }).then(loginResponse => {
      res.json({
        message: 'User registered and logged in',
        access_token: loginResponse.data.access_token,
        id_token: loginResponse.data.id_token,
        expires_in: loginResponse.data.expires_in
      });
    }).catch(loginError => {
      res.status(400).json({ error: loginError.response?.data || 'Login after registration failed' });
    })
  } catch (err) {
    res.status(400).json({ error: err.response?.data || 'Registration failed' });
  }
});

app.get('/register', (req, res) => {
  res.render('register', { title: 'Register Form' });
});

// ----------------------
// RESET PASSWORD
// ----------------------
app.post('/reset-password', async (req, res) => {
  const { email } = req.body;

  try {
    await axios.post(`https://${AUTH0_DOMAIN}/dbconnections/change_password`, {
      client_id: AUTH0_CLIENT_ID,
      email,
      connection: AUTH0_CONNECTION
    });

    res.json({ message: 'Password reset email sent' });
  } catch (err) {
    res.status(400).json({ error: err.response?.data || 'Reset failed' });
  }
});

// ----------------------
// VALIDATE TOKEN
// ----------------------
const client = jwksRsa({
  jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

app.get('/validate-token', (req, res) => {
  const authHeader = req.headers.authorization;

  // Check if header is present and formatted correctly
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ valid: false, error: 'Missing or malformed Authorization header' });
  }

  // Extract token from header
  const token = authHeader.split(' ')[1];

  jwt.verify(
    token,
    getKey,
    {
      audience: AUTH0_AUDIENCE,
      issuer: `https://${AUTH0_DOMAIN}/`,
      algorithms: ['RS256']
    },
    (err, decoded) => {
      if (err) return res.status(401).json({ valid: false, error: err.message });
      res.json({ valid: true, decoded });
    }
  );
});

// ----------------------
app.listen(PORT, () => {
  console.log(`Auth server running at http://localhost:${PORT}`);
});
