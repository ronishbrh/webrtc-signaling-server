// serverHttps.js - Metered Correct Version
import fs from "fs";
import http from "http";
import https from "https";
import { WebSocketServer } from "ws";

// ---------- CONFIGURATION ----------
const PORT = process.env.PORT || 8080;
const USE_SSL = process.env.USE_SSL === "true";

// ⭐ Your Metered App Details (from Metered dashboard)
const METERED_APP_DOMAIN = 'webrtc-calling-app.metered.live';
const METERED_SECRET_KEY = process.env.METERED_SECRET_KEY || 'b5b262211c66cdca4bd375a9bd7180a906c7';

let server;
if (USE_SSL) {
  server = https.createServer({
    key: fs.readFileSync(process.env.SSL_KEY_PATH || "/etc/letsencrypt/live/yourdomain.com/privkey.pem"),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH || "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"),
  });
  console.log("Starting HTTPS server (VPS / custom SSL)");
} else {
  server = http.createServer();
  console.log("Starting HTTP server (Render or LAN)");
}

// ---------- HTTP ROUTES FOR TURN CREDENTIALS ----------
server.on('request', async (req, res) => {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // TURN Credentials Endpoint
  if (req.url === '/api/turn-credentials' && req.method === 'GET') {
    try {
      console.log('Fetching TURN credentials from Metered...');

      const metered_url = `https://${METERED_APP_DOMAIN}/api/v1/turn/credentials?apiKey=${METERED_SECRET_KEY}`;

      const response = await fetch(metered_url);

      if (!response.ok) {
        console.error(`Metered API returned status: ${response.status}`);
        res.writeHead(response.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Metered API returned status ${response.status}` }));
        return;
      }

      const data = await response.json();
      console.log('✅ Got TURN credentials from Metered');

      // Metered returns an array directly, wrap it in iceServers object
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        iceServers: data  // Wrap the array in iceServers
      }));
    } catch (error) {
      console.error('Error fetching TURN credentials:', error);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: 'Failed to fetch TURN credentials',
        details: error.message
      }));
    }
    return;
  }

  // Health check endpoint
  if (req.url === '/api/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', message: 'Server is running' }));
    return;
  }

  // Root endpoint
  if (req.url === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      message: 'WebRTC Signaling Server',
      endpoints: {
        websocket: `ws${USE_SSL ? 's' : ''}://localhost:${PORT}`,
        turnCredentials: '/api/turn-credentials',
        health: '/api/health'
      }
    }));
    return;
  }
});

// ---------- WEBSOCKET SERVER ----------
const wss = new WebSocketServer({ server, clientTracking: true });

// ---------- CLIENT MANAGEMENT ----------
const clients = {};

wss.on("connection", (ws) => {
  ws.isAlive = true;

  ws.on("pong", () => {
    ws.isAlive = true;
  });

  let username = null;

  ws.on("message", (msg) => {
    let data;
    try {
      data = JSON.parse(msg);
    } catch {
      return;
    }

    if (data.type === "register") {
      username = data.userName;
      if (clients[username]) clients[username].close();
      clients[username] = ws;
      console.log(`User registered: ${username}`);
      return;
    }

    const target = clients[data.to];
    if (!target) return;

    const types = [
      "call-request",
      "call-accepted",
      "call-declined",
      "call-cancelled",
      "join",
      "challenge1",
      "challenge2",
      "offer",
      "answer",
      "ice",
      "end-call",
    ];

    if (types.includes(data.type)) {
      target.send(JSON.stringify(data));
      console.log(`Forwarded ${data.type} from ${data.from} to ${data.to}`);
    }
  });

  ws.on("close", () => {
    if (username && clients[username] === ws) {
      delete clients[username];
      console.log(`User disconnected: ${username}`);
    }
  });
});

// ---------- HEARTBEAT / PING ----------
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

// ---------- START SERVER ----------
server.listen(PORT, "0.0.0.0", () => {
  console.log(`WebSocket server running on port ${PORT}`);
  console.log(`📍 TURN credentials endpoint: http${USE_SSL ? 's' : ''}://localhost:${PORT}/api/turn-credentials`);
  console.log(`📍 Using Metered App: ${METERED_APP_DOMAIN}`);
  if (METERED_SECRET_KEY === 'YOUR_SECRET_KEY_HERE') {
    console.warn('⚠️  WARNING: METERED_SECRET_KEY not set! Update serverHttps.js or set environment variable.');
  }
});