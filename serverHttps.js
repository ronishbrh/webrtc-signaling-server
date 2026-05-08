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

// IMPORTANT FIX: declare before usage
const clients = {};

approvedUsers.set(ADMIN_key, true);

let server;

if (USE_SSL) {
	server = https.createServer({
		key: fs.readFileSync(process.env.SSL_KEY_PATH),
		cert: fs.readFileSync(process.env.SSL_CERT_PATH),
	});
} else {
	server = http.createServer();
}

// ---------- REQUEST HANDLER ----------
server.on("request", async (req, res) => {

	// IMPORTANT FIX: normalize URL
	const url = req.url.replace(/\/$/, "");

	// CORS
	res.setHeader("Access-Control-Allow-Origin", "*");
	res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
	res.setHeader("Access-Control-Allow-Headers", "Content-Type");

	if (req.method === "OPTIONS") {
		res.writeHead(200);
		return res.end();
	}

	// ---------- ADMIN LOGIN ----------
	if (req.method === "POST" && url === "/auth/admin-login") {

		let body = "";

		req.on("data", chunk => body += chunk);

		req.on("end", () => {
			try {
				const { password } = JSON.parse(body);

				if (password !== ADMIN_PASSWORD) {
					res.writeHead(401, { "Content-Type": "application/json" });
					return res.end(JSON.stringify({ error: "Invalid password" }));
				}

				const token = jwt.sign(
					{ user: ADMIN_key, role: "admin" },
					SECRET,
					{ expiresIn: "1h" }
				);

				ADMIN_TOKEN = token;

				res.writeHead(200, { "Content-Type": "application/json" });
				return res.end(JSON.stringify({ token, isAdmin: true }));

			} catch (e) {
				res.writeHead(500, { "Content-Type": "application/json" });
				return res.end(JSON.stringify({ error: "Server error" }));
			}
		});

		return;
	}

	// ---------- TURN ----------
	if (url === "/api/turn-credentials" && req.method === "GET") {
		try {
			const metered_url = `https://${METERED_APP_DOMAIN}/api/v1/turn/credentials?apiKey=${METERED_SECRET_KEY}`;
			const response = await fetch(metered_url);

			const data = await response.json();

			res.writeHead(200, { "Content-Type": "application/json" });
			return res.end(JSON.stringify({ iceServers: data }));

		} catch (e) {
			res.writeHead(500);
			return res.end(JSON.stringify({ error: "TURN error" }));
		}
	}

	// ---------- REGISTER ----------
	if (req.method === "POST" && url === "/register") {

		let body = "";

		req.on("data", c => body += c);

		req.on("end", () => {
			const { publicKey, message } = JSON.parse(body);

			if (approvedUsers.has(publicKey) || registrationQueue.has(publicKey)) {
				res.writeHead(400);
				return res.end("Already exists");
			}

			registrationQueue.set(publicKey, {
				publicKey,
				message,
				time: Date.now()
			});

			res.writeHead(200);
			return res.end("OK");
		});
	}

	// ---------- ADMIN REQUESTS ----------
	if (url === "/admin/requests" && req.method === "GET") {
		try {
			jwt.verify(req.headers.authorization, SECRET);
		} catch {
			res.writeHead(403);
			return res.end("Forbidden");
		}

		res.writeHead(200, { "Content-Type": "application/json" });
		return res.end(JSON.stringify([...registrationQueue.values()]));
	}

	// ---------- APPROVE ----------
	if (url === "/admin/approve" && req.method === "POST") {

		let body = "";
		req.on("data", c => body += c);

		req.on("end", () => {
			const { publicKey } = JSON.parse(body);

			if (!registrationQueue.has(publicKey)) {
				res.writeHead(404);
				return res.end("Not found");
			}

			registrationQueue.delete(publicKey);
			approvedUsers.set(publicKey, true);

			res.writeHead(200);
			return res.end("Approved");
		});
	}

	// ---------- REJECT ----------
	if (url === "/admin/reject" && req.method === "POST") {

		let body = "";
		req.on("data", c => body += c);

		req.on("end", () => {
			const { publicKey } = JSON.parse(body);
			registrationQueue.delete(publicKey);

			res.writeHead(200);
			return res.end("Rejected");
		});
	}

	// ---------- APPROVED LIST ----------
	if (url === "/admin/approved" && req.method === "GET") {
		res.writeHead(200, { "Content-Type": "application/json" });
		return res.end(JSON.stringify([...approvedUsers.keys()]));
	}

	// ---------- REMOVE ----------
	if (url === "/admin/remove" && req.method === "POST") {

		let body = "";
		req.on("data", c => body += c);

		req.on("end", () => {
			const { publicKey } = JSON.parse(body);

			approvedUsers.delete(publicKey);

			res.writeHead(200);
			return res.end("Removed");
		});
	}

	// ---------- CHALLENGE ----------
	if (url === "/auth/challenge" && req.method === "POST") {

		let body = "";
		req.on("data", c => body += c);

		req.on("end", () => {
			const { publicKey } = JSON.parse(body);

			const nonce = crypto.randomBytes(32).toString("hex");
			challenges.set(publicKey, nonce);

			res.writeHead(200, { "Content-Type": "application/json" });
			return res.end(JSON.stringify({ nonce }));
		});
	}

	// ---------- VERIFY ----------
	if (url === "/auth/verify" && req.method === "POST") {

		let body = "";
		req.on("data", c => body += c);

		req.on("end", () => {

			try {
				const { publicKey, signature } = JSON.parse(body);

				const nonce = challenges.get(publicKey);
				if (!nonce) {
					res.writeHead(401);
					return res.end("No nonce");
				}

				const verify = crypto.createVerify("SHA256");
				verify.update(nonce);
				verify.end();

				// FIX: consistent format (base64)
				const valid = verify.verify(publicKey, Buffer.from(signature, "base64"));

				if (!valid) {
					res.writeHead(401);
					return res.end("Invalid signature");
				}

				const token = jwt.sign(
					{ user: publicKey, role: "user" },
					SECRET,
					{ expiresIn: "1h" }
				);

				if (publicKey === ADMIN_key) ADMIN_TOKEN = token;

				res.writeHead(200, { "Content-Type": "application/json" });
				return res.end(JSON.stringify({
					token,
					isAdmin: publicKey === ADMIN_key
				}));

			} catch (e) {
				res.writeHead(500);
				return res.end("Error while creating token");
			}
		});
	}

	// fallback
	res.writeHead(404);
	res.end();
});

// ---------- WS ----------
const wss = new WebSocketServer({ server });

wss.on("connection", (ws, req) => {

	ws.isAlive = true;

	const url = new URL(req.url, `http://${req.headers.host}`);
	const token = url.searchParams.get("token");

	if (!token) return ws.close();

	let payload;

	try {
		payload = jwt.verify(token, SECRET);
	} catch {
		return ws.close();
	}

	const userId = payload.user;

	if (!approvedUsers.has(userId)) return ws.close();

	let username = null;

	ws.on("message", msg => {

		let data;
		try { data = JSON.parse(msg); } catch { return; }

		if (data.type === "register") {
			username = userId;
			clients[username] = ws;
			return;
		}

		const target = clients[data.to];
		if (target) target.send(JSON.stringify(data));
	});

	ws.on("close", () => {
		if (username) delete clients[username];
	});
});

// ---------- START ----------
server.listen(PORT, () => {
	console.log("Server running on", PORT);
});