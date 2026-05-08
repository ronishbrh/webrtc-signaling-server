import fs from "fs";
import http from "http";
import https from "https";
import { WebSocketServer } from "ws";


import jwt from "jsonwebtoken";
import crypto from "crypto";

// ---------- CONFIGURATION ----------
const PORT = process.env.PORT || 8080;
const USE_SSL = process.env.USE_SSL === "true";


const METERED_APP_DOMAIN = 'webrtc_calling_app.metered.live';
const METERED_SECRET_KEY = process.env.METERED_SECRET_KEY || 'd534ddd0a0cc115b19aaa0e5a7437231814a';

const SECRET = "super-secret-key";
let ADMIN_TOKEN = "";
const ADMIN_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElcQEtZdf80JRmmQK0rZmzMGLaNy+alxm9/VOu/UC7mHSVBQB5Le+2OjqPvcKgTLwUSBYY6iDEwIjWuB4mkkoXw==";

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

const challenges = new Map();
const approvedUsers = new Map();
const registrationQueue = new Map();

approvedUsers.set(ADMIN_key, true);

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

	const url = req.url.replace(/\/$/, "");
	// Enable CORS
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
	res.setHeader('Access-Control-Allow-Headers', 'Content-Type');


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

			res.writeHead(200, { 'Content-Type': 'application/json' });
			res.end(JSON.stringify({
				iceServers: data
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

	/* ------------ ADMIN LOGIN (PASSWORD BASED) ------------ */

	if (req.method === "POST" && url === "/auth/admin-login") {

		let body = "";

		req.on("data", chunk => body += chunk);

		req.on("end", () => {

			try {
				const { password } = JSON.parse(body);

				const ADMIN_PASSWORD = "admin123";

				if (password !== ADMIN_PASSWORD) {
					res.writeHead(401, { "Content-Type": "application/json" });
					return res.end(JSON.stringify({ error: "Invalid password" }));
				}

				const token = jwt.sign(
					{ user: ADMIN_key, isAdmin: true },
					SECRET,
					{ expiresIn: "1h" }
				);

				ADMIN_TOKEN = token;

				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ token, isAdmin: true }));

			} catch (e) {
				res.writeHead(500, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ error: "Server error" }));
			}
		});

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

		try {
			const decoded = jwt.verify(req.headers.authorization, SECRET);
			if (decoded.role !== "admin") throw new Error();
		} catch {
			res.writeHead(403);
			return res.end("Forbidden");
		}

		const list = Array.from(registrationQueue.values());

		res.writeHead(200, { "Content-Type": "application/json" });
		res.end(JSON.stringify(list));

	}

	/* ------------ OWNER: APPROVE USER ------------ */

	else if (req.method === "POST" && req.url === "/admin/approve") {

		try {
			const decoded = jwt.verify(req.headers.authorization, SECRET);
			if (decoded.role !== "admin") throw new Error();
		} catch {
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

		try {
			const decoded = jwt.verify(req.headers.authorization, SECRET);
			if (decoded.role !== "admin") throw new Error();
		} catch {
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

		try {
			const decoded = jwt.verify(req.headers.authorization, SECRET);
			if (decoded.role !== "admin") throw new Error();
		} catch {
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

		try {
			const decoded = jwt.verify(req.headers.authorization, SECRET);
			if (decoded.role !== "admin") throw new Error();
		} catch {
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

		req.on("end", async () => {
			try {
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

				// IMPORTANT FIX: verify using WebCrypto-style key
				const verify = crypto.createVerify("SHA256");
				verify.update(nonce);
				verify.end();

				// publicKey must be PEM format
				const valid = verify.verify(publicKey, Buffer.from(signature, "base64"));

				if (!valid) {
					res.writeHead(401);
					return res.end("Invalid signature");
				}

				const token = jwt.sign(
					{ user: publicKey },
					SECRET,
					{ expiresIn: "1h" }
				);

				if (publicKey === ADMIN_key) {
					ADMIN_TOKEN = token;
				}

				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({
					token,
					isAdmin: publicKey === ADMIN_key
				}));

			} catch (err) {
				console.error(err);
				res.writeHead(500);
				res.end("Error while creating token");
			}
		});
	}

	else {

		res.writeHead(404);
		res.end();

	}
});

// ---------- WEBSOCKET SERVER ----------
const wss = new WebSocketServer({ server, clientTracking: true });

// ---------- CLIENT MANAGEMENT ----------
const clients = {};

wss.on("connection", (ws, req) => {

	ws.isAlive = true;

	// ================= AUTH TOKEN =================
	// const url = new URL(req.url, `http://${req.headers.host}`);
	// const token = url.searchParams.get("token");

	// if (!token) {
	// 	ws.close(1008, "Token required");
	// 	return;
	// }

	// let payload;

	// try {
	// 	payload = jwt.verify(token, SECRET);
	// } catch (err) {
	// 	ws.close(1008, "Invalid or expired token");
	// 	return;
	// }

	// const userId = payload.user;

	// if (!approvedUsers.has(userId)) {
	// 	ws.close(1008, "User not approved");
	// 	return;
	// }

	let username = null;

	ws.on("message", (msg) => {
		let data;

		try {
			data = JSON.parse(msg);
		} catch {
			return;
		}

		// register identity
		if (data.type === "register") {
			username = userId; // bind token identity (IMPORTANT FIX)
			if (clients[username]) clients[username].close();
			clients[username] = ws;

			console.log(`User connected: ${username}`);
			return;
		}

		// forward signaling messages
		const target = clients[data.to];
		if (!target) return;

		const allowed = [
			"call-request",
			"call-accepted",
			"call-declined",
			"call-cancelled",
			"join",
			"offer",
			"answer",
			"ice",
			"end-call"
		];

		if (allowed.includes(data.type)) {
			target.send(JSON.stringify(data));
		}
	});

	ws.on("close", () => {
		if (username && clients[username] === ws) {
			delete clients[username];
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
	const serverUrl = process.env.RENDER_EXTERNAL_URL || `http${USE_SSL ? 's' : ''}://localhost:${PORT}`;
	console.log(`📍 TURN credentials endpoint: ${serverUrl}/api/turn-credentials`);
	console.log(`📍 Using Metered App: ${METERED_APP_DOMAIN}`);
	if (METERED_SECRET_KEY === 'YOUR_SECRET_KEY_HERE') {
		console.warn('⚠️  WARNING: METERED_SECRET_KEY not set! Update serverHttps.js or set environment variable.');
	}
});