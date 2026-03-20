// serverHttps.js - Metered Correct Version
import fs from "fs";
import http from "http";
import https from "https";
import { WebSocketServer } from "ws";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// ---------- CONFIGURATION ----------
// ⭐ Your Metered App Details (from Metered dashboard)
const METERED_APP_DOMAIN = 'webrtc_calling_app.metered.live';
const METERED_SECRET_KEY = process.env.METERED_SECRET_KEY || 'd534ddd0a0cc115b19aaa0e5a7437231814a';


// true only for VPS where you have cert files
// false for Render free or local LAN without certs
const USE_SSL = process.env.USE_SSL === "true";
const PORT = process.env.PORT || 8080;


const SECRET = "super-secret-key";
let ADMIN_TOKEN = "";
const ADMIN_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE47QPQDeqs83kKYMWvvSdmBfIEMscBlAwvevp2Tauv/qE2Pbf/XRktCrp7nqNs7dARu0kZnNvdkWv4z+/7J2MlA==";

const challenges = new Map();
const approvedUsers = new Map();
const registrationQueue = new Map();

approvedUsers.set(ADMIN_key, true);

async function server_apis(req, res) {

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
	// REGISTER REQUEST

	if (req.method === "POST" && req.url === "/register") {

		let body = "";

		req.on("data", chunk => body += chunk);

		req.on("end", () => {

			const { publicKey, message } = JSON.parse(body);

			if (approvedUsers.has(publicKey) || registrationQueue.has(publicKey)) {
				res.writeHead(400);
				return res.end("Already requested or registered");
			}

			registrationQueue.set(publicKey, {
				publicKey,
				message,
				time: Date.now()
			});

			res.writeHead(200);
			res.end("Registration request submitted");

		});

	}

	/* ------------ OWNER: LIST REQUESTS ------------ */

	else if (req.method === "GET" && req.url === "/admin/requests") {

		if (req.headers.authorization !== ADMIN_TOKEN) {
			res.writeHead(403);
			return res.end("Forbidden");
		}

		const list = Array.from(registrationQueue.values());

		res.writeHead(200, { "Content-Type": "application/json" });
		res.end(JSON.stringify(list));

	}

	/* ------------ OWNER: APPROVE USER ------------ */

	else if (req.method === "POST" && req.url === "/admin/approve") {

		if (req.headers.authorization !== ADMIN_TOKEN) {
			res.writeHead(403);
			return res.end("Forbidden");
		}

		let body = "";

		req.on("data", chunk => body += chunk);

		req.on("end", () => {

			const { publicKey } = JSON.parse(body);

			const request = registrationQueue.get(publicKey);

			if (!request) {
				res.writeHead(404);
				return res.end("Request not found");
			}

			registrationQueue.delete(publicKey);
			approvedUsers.set(publicKey, true);

			res.writeHead(200);
			res.end("User approved");

		});

	}

	/* ------------ OWNER: REJECT USER ------------ */

	else if (req.method === "POST" && req.url === "/admin/reject") {

		if (req.headers.authorization !== ADMIN_TOKEN) {
			res.writeHead(403);
			return res.end("Forbidden");
		}

		let body = "";

		req.on("data", chunk => body += chunk);

		req.on("end", () => {

			const { publicKey } = JSON.parse(body);

			registrationQueue.delete(publicKey);

			res.writeHead(200);
			res.end("User rejected");

		});

	}

	/* ------------ OWNER: LIST APPROVED USERS ------------ */
	else if (req.method === "GET" && req.url === "/admin/approved") {

		// Only admin can list approved users
		if (req.headers.authorization !== ADMIN_TOKEN) {
			res.writeHead(403);
			return res.end("Forbidden");
		}

		// Convert Map keys to array
		const list = Array.from(approvedUsers.keys());

		res.writeHead(200, { "Content-Type": "application/json" });
		res.end(JSON.stringify(list));
	}

	/* ------------ OWNER: REMOVE APPROVED USER ------------ */
	else if (req.method === "POST" && req.url === "/admin/remove") {

		// Only admin can remove users
		if (req.headers.authorization !== ADMIN_TOKEN) {
			res.writeHead(403);
			return res.end("Forbidden");
		}

		let body = "";

		req.on("data", chunk => body += chunk);

		req.on("end", () => {

			const { publicKey } = JSON.parse(body);

			if (!approvedUsers.has(publicKey)) {
				res.writeHead(404);
				return res.end("User not found in approved list");
			}

			approvedUsers.delete(publicKey);

			// Optional: also remove any active WebSocket connections
			for (const [username, ws] of clients.entries()) {
				if (username === publicKey) { // assuming username = publicKey
					ws.close(4000, "User removed by admin");
					clients.delete(username);
				}
			}

			res.writeHead(200);
			res.end("User removed successfully");

		});
	}

	/* ------------ AUTH CHALLENGE ------------ */

	else if (req.method === "POST" && req.url === "/auth/challenge") {

		let body = "";

		req.on("data", chunk => body += chunk);

		req.on("end", () => {

			const { publicKey } = JSON.parse(body);

			if (!approvedUsers.has(publicKey)) {
				res.writeHead(403);
				return res.end("User not approved");
			}

			const nonce = crypto.randomBytes(32).toString("hex");

			challenges.set(publicKey, nonce);

			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ nonce }));

		});

	}

	/* ------------ VERIFY SIGNATURE ------------ */

	else if (req.method === "POST" && req.url === "/auth/verify") {

		let body = "";

		req.on("data", chunk => body += chunk);

		req.on("end", () => {

			const { publicKey, signature } = JSON.parse(body);

			if (!approvedUsers.has(publicKey)) {
				res.writeHead(403);
				return res.end("User not approved");
			}

			const nonce = challenges.get(publicKey);

			if (!nonce) {
				res.writeHead(401);
				return res.end("No challenge was given");
			}

			const verify = crypto.createVerify("SHA256");

			verify.update(nonce);
			verify.end();

			try {
				const valid = verify.verify(publicKey, signature, "hex");

				if (!valid) {
					res.writeHead(401);
					return res.end("Invalid signature");
				}

			} catch (error) {
				res.writeHead(401);
				return res.end("Error while creating token");
			}

			const token = jwt.sign(
				{ user: publicKey },
				SECRET,
				{ expiresIn: "1h" }
			);

			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ token }));

			if (publicKey == ADMIN_key) {
				ADMIN_TOKEN = token;
			}

		});

	}

	else {

		res.writeHead(404);
		res.end();

	}

}

let server;

if (USE_SSL) {
	// VPS / Let’s Encrypt
	server = https.createServer({
		key: fs.readFileSync(process.env.SSL_KEY_PATH || "/etc/letsencrypt/live/yourdomain.com/privkey.pem"),
		cert: fs.readFileSync(process.env.SSL_CERT_PATH || "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"),
	}, server_apis);
	console.log("Starting HTTPS server (VPS / custom SSL)");
} else {
	// Render free / local LAN: HTTP only, Render handles HTTPS automatically
	server = http.createServer(server_apis); // mathi ko esari server_apis pass garera vayo locally
	console.log("Starting HTTP server (Render or LAN)");
}

// ---------- HTTP ROUTES FOR TURN CREDENTIALS ----------
//server.on('request', async (req, res) => {
//  // Enable CORS
//  res.setHeader('Access-Control-Allow-Origin', '*');
//  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
//  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
//
//  // Handle CORS preflight
//  if (req.method === 'OPTIONS') {
//    res.writeHead(200);
//    res.end();
//    return;
//  }
//
//  // TURN Credentials Endpoint
//  if (req.url === '/api/turn-credentials' && req.method === 'GET') {
//    try {
//      console.log('Fetching TURN credentials from Metered...');
//
//      const metered_url = `https://${METERED_APP_DOMAIN}/api/v1/turn/credentials?apiKey=${METERED_SECRET_KEY}`;
//
//      const response = await fetch(metered_url);
//
//      if (!response.ok) {
//        console.error(`Metered API returned status: ${response.status}`);
//        res.writeHead(response.status, { 'Content-Type': 'application/json' });
//        res.end(JSON.stringify({ error: `Metered API returned status ${response.status}` }));
//        return;
//      }
//
//      const data = await response.json();
//      console.log('✅ Got TURN credentials from Metered');
//
//      // Metered returns an array directly, wrap it in iceServers object
//      res.writeHead(200, { 'Content-Type': 'application/json' });
//      res.end(JSON.stringify({
//        iceServers: data  // Wrap the array in iceServers
//      }));
//    } catch (error) {
//      console.error('Error fetching TURN credentials:', error);
//      res.writeHead(500, { 'Content-Type': 'application/json' });
//      res.end(JSON.stringify({
//        error: 'Failed to fetch TURN credentials',
//        details: error.message
//      }));
//    }
//    return;
//  }
//
//  // Health check endpoint
//  if (req.url === '/api/health' && req.method === 'GET') {
//    res.writeHead(200, { 'Content-Type': 'application/json' });
//    res.end(JSON.stringify({ status: 'ok', message: 'Server is running' }));
//    return;
//  }
//
//  // Root endpoint
//  if (req.url === '/' && req.method === 'GET') {
//    res.writeHead(200, { 'Content-Type': 'application/json' });
//    res.end(JSON.stringify({
//      message: 'WebRTC Signaling Server',
//      endpoints: {
//        websocket: `ws${USE_SSL ? 's' : ''}://localhost:${PORT}`,
//        turnCredentials: '/api/turn-credentials',
//        health: '/api/health'
//      }
//    }));
//    return;
//  }
//});

// ---------- WEBSOCKET SERVER ----------
const wss = new WebSocketServer({ server, clientTracking: true });

// ---------- CLIENT MANAGEMENT ----------
const clients = new Map()

wss.on("connection", (ws, req) => {
	ws.isAlive = true;

	const url = new URL(req.url, "https://localhost");
	const token = url.searchParams.get("token");

	if (!token) {
		ws.close(1008, "Token required")
		return;
	}

	try {
		const payload = jwt.verify(token, SECRET);
		const userId = payload.user;
		if (!approvedUsers.has(userId)) {
			ws.close(1008, "Invalid or expired token");
			return;
		}
	} catch (err) {
		ws.close(1008, "Invalid or expired token");
		return;
	}


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
			if (clients.get(username)) clients.get(username).close();
			clients.set(username, ws);
			console.log(`User registered: ${username}`);
			return;
		}

		const target = clients.get(data.to);
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
		if (username && clients.get(username) === ws) {
			clients.delete(username);
			console.log(`User disconnected: ${username}`);
		}
	});
	console.log("A client connected");
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
	const serverUrl = process.env.RENDER_EXTERNAL_URL || `http${USE_SSL ? 's' : ''}://localhost:${PORT}`;
	console.log(`📍 TURN credentials endpoint: ${serverUrl}/api/turn-credentials`);
	console.log(`📍 Using Metered App: ${METERED_APP_DOMAIN}`);
	if (METERED_SECRET_KEY === 'YOUR_SECRET_KEY_HERE') {
		console.warn('⚠️  WARNING: METERED_SECRET_KEY not set! Update serverHttps.js or set environment variable.');
	}
});
