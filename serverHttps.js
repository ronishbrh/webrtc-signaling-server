// serverHttps.js
import fs from "fs";
import http from "http";
import https from "https";
import { WebSocketServer } from "ws";

// ---------- CONFIGURATION ----------
const PORT = process.env.PORT || 8080;
const USE_SSL = process.env.USE_SSL === "true"; 
// true only for VPS where you have cert files
// false for Render free or local LAN without certs

let server;

if (USE_SSL) {
  // VPS / Let’s Encrypt
  server = https.createServer({
    key: fs.readFileSync(process.env.SSL_KEY_PATH || "/etc/letsencrypt/live/yourdomain.com/privkey.pem"),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH || "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"),
  });
  console.log("Starting HTTPS server (VPS / custom SSL)");
} else {
  // Render free / local LAN: HTTP only, Render handles HTTPS automatically
  server = http.createServer();
  console.log("Starting HTTP server (Render or LAN)");
}

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
});