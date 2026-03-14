# WebRTC Signaling Server

A simple secure WebSocket-based signaling server for WebRTC applications. This server allows users to exchange messages like call requests, offers, answers, ICE candidates, and more. It supports automatic heartbeat ping to detect disconnected clients and private message forwarding between users.

---

## Features

* Secure WebSocket (WSS) server
* User registration and private message forwarding
* Automatic heartbeat ping to detect disconnected clients
* Works on LAN, VPS, or cloud platforms like Render
* Active server selection for clients
* Optional self-signed certificate for local testing

---

## Quick Start

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd <repo-folder>
```

### 2. Install dependencies

```bash
npm install
```

### 3. Certificates

For local testing, generate self-signed certificates in a `certs` folder:

```bash
mkdir certs
openssl req -nodes -new -x509 -keyout certs/key.pem -out certs/cert.pem
```

For production, you can use Let’s Encrypt or cloud HTTPS.

### 4. Run the server locally

```bash
node serverHttps.js
```

The server will start on `https://localhost:8080` or your local LAN IP.

---

## Deployment Instructions

### A. Deploy on Render (free)

1. Create a new **Web Service** on Render.
2. Connect your GitHub repository.
3. Set the **Build Command**:

```bash
npm install
```

4. Set the **Start Command**:

```bash
node serverHttps.js
```

5. Ensure `USE_SELF_SIGNED` is `true` in `serverHttps.js` for Render deployment.
6. Render will provide a public URL like `https://your-app.onrender.com`. Use this as your signaling server URL in your clients.

---

### B. Deploy on a VPS or any other server

1. Upload your project to the VPS.
2. Install Node.js and dependencies:

```bash
npm install
```

3. Obtain a domain and SSL certificate (e.g., via Let’s Encrypt).
4. Update `serverHttps.js`:

```js
server = https.createServer({
  key: fs.readFileSync("/etc/letsencrypt/live/yourdomain.com/privkey.pem"),
  cert: fs.readFileSync("/etc/letsencrypt/live/yourdomain.com/fullchain.pem"),
});
```

5. Start the server:

```bash
node serverHttps.js
```

6. Access it via `wss://yourdomain.com:PORT`.

> **Note:** Make sure your VPS firewall allows the port (default 8080) and HTTPS traffic.

---

### C. Local LAN usage

1. Use self-signed certificates.
2. Update `server.listen` in `serverHttps.js`:

```js
server.listen(8080, "0.0.0.0");
```

3. Your server will be reachable from LAN via `https://<your-lan-ip>:8080`.

> Example: `https://192.168.1.98:8080`

---

## .gitignore

Make sure to add:

```
node_modules
.env
certs
```

This prevents sensitive info and dependencies from being pushed to GitHub.

---

## Notes

* Clients should handle automatic reconnects if the connection drops.
* The server does **not broadcast online users** — all messaging is private.
* Heartbeat ping ensures disconnected clients are cleaned up automatically.
* You can switch between self-signed certificates for LAN/testing or Let’s Encrypt/cloud certificates for public deployment.

---

