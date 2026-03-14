
import fs from "fs";
import https from "https";
import { WebSocketServer } from "ws";

// ---------- CONFIGURATION ----------
const PORT = process.env.PORT || 8080;
const USE_SELF_SIGNED = true; // set false if using Let’s Encrypt or cloud HTTPS

let server;

if (USE_SELF_SIGNED) {
  // Local LAN / testing: self-signed certificate
  server = https.createServer({
    key: fs.readFileSync("./certs/key.pem"),
    cert: fs.readFileSync("./certs/cert.pem"),
  });
} else {
  // VPS / Let’s Encrypt: replace domain.com with your domain
  server = https.createServer({
    key: fs.readFileSync("/etc/letsencrypt/live/yourdomain.com/privkey.pem"),
    cert: fs.readFileSync("/etc/letsencrypt/live/yourdomain.com/fullchain.pem"),
  });
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

    // Forward messages privately
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
const interval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

// ---------- START SERVER ----------
server.listen(PORT, "0.0.0.0", () => {
  console.log(`Secure WebSocket server running on port ${PORT}`);
});