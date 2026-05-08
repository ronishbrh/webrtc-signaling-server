import fs from "fs";
import http from "http";
import https from "https";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { WebSocketServer } from "ws";

// ---------------- CONFIG ----------------
const PORT = process.env.PORT || 8080;
const USE_SSL = process.env.USE_SSL === "true";

const SECRET = "super-secret-key";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

const METERED_APP_DOMAIN = "webrtc_calling_app.metered.live";
const METERED_SECRET_KEY =
	process.env.METERED_SECRET_KEY || "d534ddd0a0cc115b19aaa0e5a7437231814a";

const ADMIN_KEY =
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElcQEtZdf80JRmmQK0rZmzMGLaNy+alxm9/VOu/UC7mHSVBQB5Le+2OjqPvcKgTLwUSBYY6iDEwIjWuB4mkkoXw=="; // keep yours

// ---------------- STATE ----------------
const registrationQueue = new Map();
const approvedUsers = new Map();
const challenges = new Map();
const clients = {};

approvedUsers.set(ADMIN_KEY, true);

// ---------------- SERVER ----------------
let server;

if (USE_SSL) {
	server = https.createServer({
		key: fs.readFileSync(process.env.SSL_KEY_PATH),
		cert: fs.readFileSync(process.env.SSL_CERT_PATH),
	});
} else {
	server = http.createServer();
}

// ---------------- HELPERS ----------------
function verifyAdmin(req, res) {
	try {
		const auth = req.headers.authorization;
		if (!auth) throw new Error();

		const token = auth.startsWith("Bearer ")
			? auth.split(" ")[1]
			: auth;

		const decoded = jwt.verify(token, SECRET);
		if (decoded.role !== "admin") throw new Error();

		return true;
	} catch {
		res.writeHead(403);
		res.end("Forbidden");
		return false;
	}
}

// ---------------- HTTP ROUTES ----------------
server.on("request", async (req, res) => {
	res.setHeader("Access-Control-Allow-Origin", "*");
	res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
	res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

	if (req.method === "OPTIONS") {
		res.writeHead(200);
		return res.end();
	}

	const url = req.url.replace(/\/$/, "");

	// ---------- HEALTH ----------
	if (url === "/api/health") {
		res.writeHead(200);
		return res.end(JSON.stringify({ status: "ok" }));
	}

	// ---------- TURN ----------
	if (url === "/api/turn-credentials") {
		try {
			const response = await fetch(
				`https://${METERED_APP_DOMAIN}/api/v1/turn/credentials?apiKey=${METERED_SECRET_KEY}`
			);

			const data = await response.json();

			res.writeHead(200, { "Content-Type": "application/json" });
			return res.end(JSON.stringify({ iceServers: data }));
		} catch (err) {
			res.writeHead(500);
			return res.end(JSON.stringify({ error: err.message }));
		}
	}

	// ---------- ADMIN LOGIN ----------
	if (url === "/auth/admin-login" && req.method === "POST") {
		let body = "";

		req.on("data", c => (body += c));

		req.on("end", () => {
			const { password } = JSON.parse(body);

			if (password !== ADMIN_PASSWORD) {
				res.writeHead(401);
				return res.end("Invalid password");
			}

			const token = jwt.sign(
				{ user: ADMIN_KEY, role: "admin" },
				SECRET,
				{ expiresIn: "1h" }
			);

			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ token, isAdmin: true }));
		});

		return;
	}

	// ---------- REGISTER ----------
	if (url === "/register" && req.method === "POST") {
		let body = "";

		req.on("data", c => (body += c));

		req.on("end", () => {
			const { publicKey, message } = JSON.parse(body);

			registrationQueue.set(publicKey, {
				publicKey,
				message,
				time: Date.now(),
			});

			res.writeHead(200);
			res.end("registered");
		});

		return;
	}

	// ---------- ADMIN ROUTES ----------
	if (url.startsWith("/admin")) {
		if (!verifyAdmin(req, res)) return;

		// requests
		if (url === "/admin/requests") {
			res.writeHead(200);
			return res.end(JSON.stringify([...registrationQueue.values()]));
		}

		// approve
		if (url === "/admin/approve") {
			let body = "";
			req.on("data", c => (body += c));

			req.on("end", () => {
				const { publicKey } = JSON.parse(body);

				registrationQueue.delete(publicKey);
				approvedUsers.set(publicKey, true);

				res.writeHead(200);
				res.end("approved");
			});
			return;
		}

		// reject
		if (url === "/admin/reject") {
			let body = "";
			req.on("data", c => (body += c));

			req.on("end", () => {
				const { publicKey } = JSON.parse(body);

				registrationQueue.delete(publicKey);

				res.writeHead(200);
				res.end("rejected");
			});
			return;
		}

		// approved list
		if (url === "/admin/approved") {
			res.writeHead(200);
			return res.end(JSON.stringify([...approvedUsers.keys()]));
		}

		// remove user
		if (url === "/admin/remove") {
			let body = "";
			req.on("data", c => (body += c));

			req.on("end", () => {
				const { publicKey } = JSON.parse(body);

				approvedUsers.delete(publicKey);

				if (clients[publicKey]) {
					clients[publicKey].close();
					delete clients[publicKey];
				}

				res.writeHead(200);
				res.end("removed");
			});
			return;
		}
	}

	// ---------- AUTH CHALLENGE ----------
	if (url === "/auth/challenge" && req.method === "POST") {
		let body = "";

		req.on("data", c => (body += c));

		req.on("end", () => {
			const { publicKey } = JSON.parse(body);

			const nonce = crypto.randomBytes(32).toString("hex");
			challenges.set(publicKey, nonce);

			res.writeHead(200);
			res.end(JSON.stringify({ nonce }));
		});

		return;
	}

	// ---------- AUTH STATUS ----------
	if (url === "/auth/status" && req.method === "GET") {
		try {
			const auth = req.headers.authorization;
			if (!auth) {
				res.writeHead(401);
				return res.end("No token");
			}

			const token = auth.startsWith("Bearer ")
				? auth.split(" ")[1]
				: auth;

			const decoded = jwt.verify(token, SECRET);

			const publicKey = decoded.user;

			const isApproved = approvedUsers.has(publicKey);

			res.writeHead(200, { "Content-Type": "application/json" });
			return res.end(JSON.stringify({
				approved: isApproved
			}));

		} catch (err) {
			res.writeHead(401);
			return res.end(JSON.stringify({
				approved: false,
				error: "invalid token"
			}));
		}
	}

	// ---------- AUTH VERIFY ----------
	// ---------- AUTH VERIFY ----------
	if (url === "/auth/verify" && req.method === "POST") {
		let body = "";
		req.on("data", c => (body += c));

		req.on("end", async () => {
			try {
				const { publicKey, signature } = JSON.parse(body);

				if (!approvedUsers.has(publicKey)) {
					res.writeHead(403);
					return res.end("not approved");
				}

				const nonce = challenges.get(publicKey);
				if (!nonce) {
					res.writeHead(400);
					return res.end("no challenge");
				}

				// ── FIX: use Web Crypto-compatible ECDSA verification ──
				const keyBuffer = Buffer.from(publicKey, "base64");

				const cryptoKey = await crypto.subtle.importKey(
					"spki",
					keyBuffer,
					{ name: "ECDSA", namedCurve: "P-256" },
					false,
					["verify"]
				);

				const signatureBuffer = Buffer.from(signature, "base64");
				const nonceBuffer = new TextEncoder().encode(nonce);

				const valid = await crypto.subtle.verify(
					{ name: "ECDSA", hash: { name: "SHA-256" } },
					cryptoKey,
					signatureBuffer,
					nonceBuffer
				);

				if (!valid) {
					res.writeHead(401);
					return res.end("invalid signature");
				}

				challenges.delete(publicKey);

				const token = jwt.sign(
					{
						user: publicKey,
						role: publicKey === ADMIN_KEY ? "admin" : "user",
					},
					SECRET,
					{ expiresIn: "1h" }
				);

				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({
					token,
					isAdmin: publicKey === ADMIN_KEY,
				}));

			} catch (err) {
				console.error("Verify error:", err);
				res.writeHead(500);
				res.end("Server error");
			}
		});

		return;
	}

	res.writeHead(404);
	res.end("Not found");
});

// ---------------- WEBSOCKET ----------------
const wss = new WebSocketServer({ server });

wss.on("connection", (ws, req) => {
	let username = null;

	ws.on("message", (msg) => {
		let data;


		try {
			data = JSON.parse(msg);
		} catch {
			return;
		}

		// ---------- REGISTER ----------
		if (data.type === "register") {
			// ── FIX: require a valid token ──
			if (!data.token) {
				ws.send(JSON.stringify({ type: "error", message: "No token provided" }));
				ws.close();
				return;
			}

			try {
				const decoded = jwt.verify(data.token, SECRET);

				// Ensure the token's user matches the claimed userName
				if (decoded.user !== data.userName) {
					ws.send(JSON.stringify({ type: "error", message: "Token mismatch" }));
					ws.close();
					return;
				}

				// Ensure the user is still approved
				if (!approvedUsers.has(decoded.user)) {
					ws.send(JSON.stringify({ type: "error", message: "Not approved" }));
					ws.close();
					return;
				}

			} catch (err) {
				ws.send(JSON.stringify({ type: "error", message: "Invalid token" }));
				ws.close();
				return;
			}

			username = data.userName;
			if (clients[username]) clients[username].close();
			clients[username] = ws;
			console.log(`User registered: ${username}`);
			return;
		}


		// ---------- SIGNAL TYPES ----------
		const allowedTypes = [
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

		if (!allowedTypes.includes(data.type)) return;

		const target = clients[data.to];
		if (!target) return;

		target.send(JSON.stringify(data));

		console.log(`Forwarded ${data.type} from ${data.from} to ${data.to}`);
	});

	ws.on("close", () => {
		if (username && clients[username] === ws) {
			delete clients[username];
			console.log(`User disconnected: ${username}`);
		}
	});
});

// ---------------- START ----------------
server.listen(PORT, "0.0.0.0", () => {
	console.log(`Server running on port ${PORT}`);
});