const express = require('express');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const Replicate = require('replicate');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const replicate = new Replicate({
  auth: process.env.REPLICATE_API_TOKEN,
});

const app = express();
app.use(express.json());
app.use(cookieParser());

// Set up rate limiting
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 1 minute'
});

app.use(limiter);

const replicateApiToken = process.env.REPLICATE_API_TOKEN;

// Simulated user data
const users = [
  { id: 1, username: 'john_doe', password: 'password123' },
  { id: 2, username: 'jane_smith', password: 'secretpassword' },
];

// Generate a CSRF token
function generateCSRFToken() {
  return crypto.randomBytes(16).toString('hex');
}

// Middleware to verify CSRF token
function verifyCSRFToken(req, res, next) {
  if (req.method !== 'GET') {
    const csrfToken = req.cookies['csrf-token'];
    const requestToken = req.headers['x-csrf-token'];

    if (!csrfToken || !requestToken || csrfToken !== requestToken) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }

  next();
}

// Middleware to verify user token
function verifyUserToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const user = users.find((u) => u.token === token);

  if (!user) {
    return res.status(403).json({ error: 'Invalid token' });
  }

  req.user = user;
  next();
}

// Generate a user token
function generateUserToken(user) {
  return crypto.randomBytes(32).toString('hex');
}

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username && u.password === password);

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  user.token = generateUserToken(user);
  res.json({ token: user.token });
});

// Protected endpoint
app.get('/api/stablevision', verifyUserToken, verifyCSRFToken, async (req, res) => {
  try {
    const input = {
      auth: replicateApiToken,
      cfg: 3.5,
      steps: 28,
      prompt: "a photo of  a supermodel in the beach wearing a swimsuit thick",
      aspect_ratio: "3:2",
      output_format: "webp",
      output_quality: 90,
      negative_prompt: "",
      prompt_strength: 0.85
    };

    const output = await replicate.run("stability-ai/stable-diffusion-3", { input });
    console.log(output);
    res.json(output);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while generating the waveform' });
  }
});

// Protected endpoint
app.get('/api/video', verifyUserToken, verifyCSRFToken, async (req, res) => {
  try {
    const input = {
      auth: replicateApiToken,
    };

    const output = await replicate.run("cjwbw/damo-text-to-video:1e205ea73084bd17a0a3b43396e49ba0d6bc2e754e9283b2df49fad2dcf95755", { input });
    console.log(output);
    res.json(output);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while generating the waveform' });
  }
});

app.get('/api/video-caption', verifyUserToken, verifyCSRFToken, async (req, res) => {
  try {
    const input = {
      auth: replicateApiToken,
      video_file_input: "https://replicate.delivery/pbxt/K5zuJ6HCdsffhegX0JZwDl10qm7fYAh5txe0FZc7XFccpdtm/kingnobelbig.mp4"
    };

    const output = await replicate.run("fictions-ai/autocaption:18a45ff0d95feb4449d192bbdc06b4a6df168fa33def76dfc51b78ae224b599b", { input });
    console.log(output);
    res.json(output);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while generating the waveform' });
  }
});

// CSRF token endpoint
app.get('/csrf-token', (req, res) => {
  const csrfToken = generateCSRFToken();
  res.cookie('csrf-token', csrfToken, { httpOnly: true });
  res.json({ csrfToken });
});

app.listen(3000, () => {
  console.log('Server is running on port 80');
});