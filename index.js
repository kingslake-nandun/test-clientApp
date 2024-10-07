const express = require('express');
const axios = require('axios');
const crypto = require('crypto'); // Import crypto module for PKCE
const e = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');


const app = express();
app.use(express.json()); // Middleware to parse JSON requests

//initialize cookie parser
app.use(cookieParser());

//initialize session
app.use(session({
  name: 'code_verifier',
  secret: 'secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production',
            maxAge: 60000  //1 minute
          },  
  
}));

// Logger middleware
const logger = (req, res, next) => {
  console.log('Request:', req.method, req.url);
  next();
};
app.use(logger);

// Function to generate a random code verifier (a URL-safe string)
function generateCodeVerifier() {
  return base64UrlEncode(crypto.randomBytes(32));
}

// Function to generate a code challenge from the code verifier
function generateCodeChallenge(codeVerifier) {
  const hash = crypto.createHash('sha256').update(codeVerifier).digest();
  return base64UrlEncode(hash);
}

// Helper function to convert a buffer to URL-safe Base64 encoding
function base64UrlEncode(buffer) {
  return buffer
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

//Function to generate a random state
function generateState() {
  return crypto.randomBytes(16).toString('hex');
}

// Use OAuth server for login
app.get('/oauth/login', async (req, res) => {
  codeVerifier = generateCodeVerifier(); // Generate a new code verifier
  const codeChallenge = await generateCodeChallenge(codeVerifier); // Generate code challenge
  const state = generateState(); // Generate a new state
  req.session.code_verifier = codeVerifier; // Store code verifier in session
  req.session.state = state; // Store state in session

  const authUrl = `http://localhost:4000/oauth/authorize?response_type=code&client_id=client1234&redirect_uri=http://localhost:5000/callback&scope=read:user_profile&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`;
  
  res.redirect(authUrl);
});

// Callback route for OAuth server
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  const codeVerifier = req.session.code_verifier; // Retrieve code verifier from session
  const storedState = req.session.state; // Retrieve state from session

  if (state !== storedState) {
    return res.status(403).json({ error: 'Invalid state parameter' });
  }else{
    try {
      const tokenResponse = await axios.post('http://localhost:4000/oauth/token', {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost:5000/callback',
        client_id: 'client1234',
        code_verifier: codeVerifier, // Send code verifier
      }, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });

      //delete code verifier and state from session
      delete req.session.code_verifier;
  
      // Store access token securely (e.g., in a cookie or local storage)
      res.json({
        message: 'Access token obtained successfully',
        accessToken: tokenResponse.data.accessToken,
        refreshToken: tokenResponse.data.refreshToken,
      });
    } catch (err) {
       res.status(err.response.status).json({ error: err.response.data.error });
      
    }

  }
   
});

// Refresh token route
app.post('/refresh-token', async (req, res) => {

 const {refreshToken} = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  // Call the refresh token endpoint of the OAuth server
  try {
    const tokenResponse = await axios.post('http://localhost:4000/oauth/token', {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: 'client1234',
      scope: 'read:user_profile',
    }, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    res.json({
      message: 'Access token obtained successfully',
      accessToken: tokenResponse.data.accessToken,
      refreshToken: tokenResponse.data.refreshToken,
    });
  } catch (err) {
    res.status(err.response.status).json({ error: err.response.data.error });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
