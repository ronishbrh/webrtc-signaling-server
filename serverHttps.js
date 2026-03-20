// serverHttps.js
import fs from "fs";
import http from "http";
import https from "https";
import { WebSocketServer } from "ws";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// ---------- CONFIGURATION ----------
const PORT = process.env.PORT || 8080;
const USE_SSL = process.env.USE_SSL === "true";
// true only for VPS where you have cert files
// false for Render free or local LAN without certs

let server;

const SECRET = "super-secret-key";
let ADMIN_TOKEN = "";
const ADMIN_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE47QPQDeqs83kKYMWvvSdmBfIEMscBlAwvevp2Tauv/qE2Pbf/XRktCrp7nqNs7dARu0kZnNvdkWv4z+/7J2MlA==";

const challenges = new Map();
const approvedUsers = new Map();
const registrationQueue = new Map();

approvedUsers.set(ADMIN_key, true);

function server_apis(req, res) {

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

			const valid = verify.verify(publicKey, signature, "hex");

			if (!valid) {
				res.writeHead(401);
				return res.end("Invalid signature");
			}

			const token = jwt.sign(
				{ user: publicKey },
				SECRET,
				{ expiresIn: "1h" }
			);

			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ token }));

			if (publicKey == ADMIN_key ){
				ADMIN_TOKEN = token;
			}

		});

	}

	else {

		res.writeHead(404);
		res.end();

	}

}

if (USE_SSL) {
	// VPS / Let’s Encrypt
	server = https.createServer({
		key: fs.readFileSync(process.env.SSL_KEY_PATH || "/etc/letsencrypt/live/yourdomain.com/privkey.pem"),
		cert: fs.readFileSync(process.env.SSL_CERT_PATH || "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"),
	}, server_apis);
	console.log("Starting HTTPS server (VPS / custom SSL)");
} else {
	// Render free / local LAN: HTTP only, Render handles HTTPS automatically
	server = http.createServer();
	console.log("Starting HTTP server (Render or LAN)");
}

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
		if(!approvedUsers.has(userId)){
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
});
