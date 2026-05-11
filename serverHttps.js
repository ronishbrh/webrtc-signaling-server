/**
 * WebRTC Signaling Server
 *
 * Auth model:
 *  - Every user (including the admin) is identified by their ECDSA P-256 public key.
 *  - The admin key is set via ADMIN_KEY env var (base64 SPKI). On first boot with no
 *    approved_users.json the admin key is seeded automatically.
 *  - There is NO password-based login. Admin authenticates with the same
 *    challenge-response flow as any other approved user, then gets role:"admin" in
 *    their JWT because their public key matches ADMIN_KEY.
 *  - JWT_SECRET must be set in the environment; the server refuses to start without it.
 */

import fs from "fs";
import http from "http";
import https from "https";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { WebSocketServer } from "ws";

// ─── Config ──────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 8080;
const USE_SSL = process.env.USE_SSL === "true";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
	console.error("FATAL: JWT_SECRET environment variable is required.");
	process.exit(1);
}

const ADMIN_KEY = process.env.ADMIN_KEY;
if (!ADMIN_KEY) {
	console.error("FATAL: ADMIN_KEY environment variable is required (base64 SPKI of admin's public key).");
	process.exit(1);
}

const TOKEN_TTL = process.env.TOKEN_TTL || "1h";
const REFRESH_TTL = process.env.REFRESH_TTL || "7d"; // refresh tokens live longer

const METERED_APP_DOMAIN = process.env.METERED_APP_DOMAIN || "webrtc_calling_app.metered.live";
const METERED_SECRET_KEY = process.env.METERED_SECRET_KEY;

const APPROVED_USERS_FILE = process.env.APPROVED_USERS_FILE || "./approved_users.json";

// ─── Persistence ─────────────────────────────────────────────────────────────

function loadApprovedUsers() {
	try {
		if (fs.existsSync(APPROVED_USERS_FILE)) {
			const data = JSON.parse(fs.readFileSync(APPROVED_USERS_FILE, "utf8"));
			const map = new Set(data);
			map.add(ADMIN_KEY); // admin always present
			console.log(`Loaded ${map.size} approved users from disk.`);
			return map;
		}
	} catch (err) {
		console.error("Failed to load approved_users.json:", err.message);
	}
	console.log("Starting fresh — seeding admin key.");
	return new Set([ADMIN_KEY]);
}

function saveApprovedUsers() {
	try {
		fs.writeFileSync(
			APPROVED_USERS_FILE,
			JSON.stringify([...approvedUsers]),
			"utf8"
		);
	} catch (err) {
		console.error("Failed to save approved_users.json:", err.message);
	}
}

// ─── State ───────────────────────────────────────────────────────────────────

const registrationQueue = new Map(); // publicKey → { publicKey, message, time }
const approvedUsers = loadApprovedUsers();
const challenges = new Map();        // publicKey → nonce (short-lived, in-memory only)
const wsClients = {};                // publicKey → WebSocket

// ─── Server ──────────────────────────────────────────────────────────────────

const server = USE_SSL
	? https.createServer({
		key: fs.readFileSync(process.env.SSL_KEY_PATH),
		cert: fs.readFileSync(process.env.SSL_CERT_PATH),
	})
	: http.createServer();

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Read request body as parsed JSON, reject on malformed input. */
function readBody(req) {
	return new Promise((resolve, reject) => {
		let raw = "";
		req.on("data", c => (raw += c));
		req.on("end", () => {
			try { resolve(JSON.parse(raw)); }
			catch { reject(new Error("Invalid JSON")); }
		});
	});
}

/** Send a JSON response. */
function json(res, status, data) {
	res.writeHead(status, { "Content-Type": "application/json" });
	res.end(JSON.stringify(data));
}

/** Verify a JWT and return its payload, or null on failure. */
function verifyToken(req) {
	try {
		const auth = req.headers.authorization || "";
		const token = auth.startsWith("Bearer ") ? auth.slice(7) : auth;
		return jwt.verify(token, JWT_SECRET);
	} catch {
		return null;
	}
}

/** Middleware: require a valid token with role:"admin". Returns decoded payload or ends the response. */
function requireAdmin(req, res) {
	const decoded = verifyToken(req);
	if (!decoded || decoded.role !== "admin") {
		res.writeHead(403);
		res.end("Forbidden");
		return null;
	}
	return decoded;
}

/** Issue an access token (short-lived) and a refresh token (long-lived). */
function issueTokens(publicKey) {
	const role = publicKey.trim() === ADMIN_KEY.trim() ? "admin" : "user";
	const accessToken = jwt.sign({ user: publicKey, role }, JWT_SECRET, { expiresIn: TOKEN_TTL });
	const refreshToken = jwt.sign({ user: publicKey, role, type: "refresh" }, JWT_SECRET, { expiresIn: REFRESH_TTL });
	return { accessToken, refreshToken, role };
}

// ─── HTTP Routes ─────────────────────────────────────────────────────────────

server.on("request", async (req, res) => {
	res.setHeader("Access-Control-Allow-Origin", "*");
	res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
	res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

	if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

	const url = req.url.split("?")[0].replace(/\/$/, "");

	try {
		await route(req, res, url);
	} catch (err) {
		console.error("Unhandled route error:", err);
		if (!res.headersSent) { res.writeHead(500); res.end("Internal Server Error"); }
	}
});

async function route(req, res, url) {

	// ── Health ────────────────────────────────────────────────────────────────

	if (url === "/api/health") {
		return json(res, 200, { status: "ok", time: Date.now() });
	}

	// ── TURN credentials ─────────────────────────────────────────────────────

	if (url === "/api/turn-credentials") {
		if (!METERED_SECRET_KEY) {
			return json(res, 503, { error: "TURN not configured on this server" });
		}
		const r = await fetch(`https://${METERED_APP_DOMAIN}/api/v1/turn/credentials?apiKey=${METERED_SECRET_KEY}`);
		return json(res, 200, { iceServers: await r.json() });
	}

	// ── Registration (unauthenticated) ────────────────────────────────────────
	// Client submits their public key and an optional human-readable message.
	// Adds to the pending queue; admin must approve before a token can be issued.

	if (url === "/auth/register" && req.method === "POST") {
		const { publicKey, message } = await readBody(req);
		if (!publicKey) { res.writeHead(400); return res.end("publicKey required"); }
		if (approvedUsers.has(publicKey)) {
			// Already approved — nothing to queue; client can go straight to auth/challenge
			res.writeHead(200);
			return res.end(JSON.stringify({ status: "already_approved" }));
		}
		registrationQueue.set(publicKey, { publicKey, message: message || "", time: Date.now() });
		res.writeHead(200);
		return res.end(JSON.stringify({ status: "pending" }));
	}

	// ── Challenge (step 1 of auth) ────────────────────────────────────────────

	if (url === "/auth/challenge" && req.method === "POST") {
		const { publicKey } = await readBody(req);

		if (!publicKey) { res.writeHead(400); return res.end("publicKey required"); }

		if (!approvedUsers.has(publicKey)) {
			// Check if they're in the queue so the client knows the difference
			const status = registrationQueue.has(publicKey) ? "pending" : "not_registered";
			res.writeHead(403);
			return res.end(JSON.stringify({ error: status }));
		}

		const nonce = crypto.randomBytes(32).toString("hex");
		challenges.set(publicKey, { nonce, createdAt: Date.now() });
		// Expire challenges after 2 minutes
		setTimeout(() => challenges.delete(publicKey), 2 * 60 * 1000);
		return json(res, 200, { nonce });
	}

	// ── Verify (step 2 of auth) → issues tokens ───────────────────────────────

	if (url === "/auth/verify" && req.method === "POST") {
		const { publicKey, signature } = await readBody(req);

		if (!approvedUsers.has(publicKey)) {
			// Check if they're in the queue so the client knows the difference
			const status = registrationQueue.has(publicKey) ? "pending" : "not_registered";
			res.writeHead(403);
			return res.end(JSON.stringify({ error: status }));
		}

		const entry = challenges.get(publicKey);
		if (!entry) { res.writeHead(400); return res.end("No active challenge — request one first"); }

		const keyBuffer = Buffer.from(publicKey, "base64");
		const cryptoKey = await crypto.subtle.importKey(
			"spki", keyBuffer,
			{ name: "ECDSA", namedCurve: "P-256" },
			false, ["verify"]
		);

		const valid = await crypto.subtle.verify(
			{ name: "ECDSA", hash: { name: "SHA-256" } },
			cryptoKey,
			Buffer.from(signature, "base64"),
			new TextEncoder().encode(entry.nonce)
		);

		if (!valid) { res.writeHead(401); return res.end("Invalid signature"); }

		challenges.delete(publicKey);
		const { accessToken, refreshToken, role } = issueTokens(publicKey);
		return json(res, 200, { accessToken, refreshToken, isAdmin: role === "admin" });
	}

	// ── Token refresh ─────────────────────────────────────────────────────────
	// Client sends a long-lived refresh token; server issues a new access token.

	if (url === "/auth/refresh" && req.method === "POST") {
		const { refreshToken } = await readBody(req);
		let decoded;
		try {
			decoded = jwt.verify(refreshToken, JWT_SECRET);
		} catch {
			res.writeHead(401);
			return res.end("Invalid or expired refresh token");
		}

		if (decoded.type !== "refresh") { res.writeHead(400); return res.end("Not a refresh token"); }
		if (!approvedUsers.has(decoded.user)) { res.writeHead(403); return res.end("User no longer approved"); }

		const { accessToken, refreshToken: newRefresh, role } = issueTokens(decoded.user);
		return json(res, 200, { accessToken, refreshToken: newRefresh, isAdmin: role === "admin" });
	}

	// ── Auth status ───────────────────────────────────────────────────────────

	if (url === "/auth/status" && req.method === "GET") {
		const decoded = verifyToken(req);
		if (!decoded) return json(res, 401, { approved: false, error: "invalid_token" });
		return json(res, 200, {
			approved: approvedUsers.has(decoded.user),
			isAdmin: decoded.role === "admin",
		});
	}

	// ── Admin: list pending requests ──────────────────────────────────────────

	if (url === "/admin/requests" && req.method === "GET") {
		if (!requireAdmin(req, res)) return;
		return json(res, 200, [...registrationQueue.values()]);
	}

	// ── Admin: list approved users ────────────────────────────────────────────

	if (url === "/admin/approved" && req.method === "GET") {
		if (!requireAdmin(req, res)) return;
		return json(res, 200, [...approvedUsers]);
	}

	// ── Admin: approve ────────────────────────────────────────────────────────

	if (url === "/admin/approve" && req.method === "POST") {
		if (!requireAdmin(req, res)) return;
		const { publicKey } = await readBody(req);
		registrationQueue.delete(publicKey);
		approvedUsers.add(publicKey);
		saveApprovedUsers();
		return json(res, 200, { ok: true });
	}

	// ── Admin: reject ─────────────────────────────────────────────────────────

	if (url === "/admin/reject" && req.method === "POST") {
		if (!requireAdmin(req, res)) return;
		const { publicKey } = await readBody(req);
		registrationQueue.delete(publicKey);
		return json(res, 200, { ok: true });
	}

	// ── Admin/self: remove user ───────────────────────────────────────────────
	// Admins can remove anyone. Approved users can remove themselves (self-revoke).

	if (url === "/admin/remove" && req.method === "POST") {
		const decoded = verifyToken(req);
		if (!decoded) { res.writeHead(401); return res.end("Unauthorized"); }

		const { publicKey } = await readBody(req);
		const isSelf = decoded.user === publicKey;
		const isAdmin = decoded.role === "admin";

		if (!isSelf && !isAdmin) { res.writeHead(403); return res.end("Forbidden"); if (isAdmin) {console.log("Admin was tried to be removed")}}
		if (publicKey === ADMIN_KEY) { res.writeHead(403); return res.end("Cannot remove the admin key"); }

		approvedUsers.delete(publicKey);
		registrationQueue.delete(publicKey);
		saveApprovedUsers();

		if (wsClients[publicKey]) {
			wsClients[publicKey].close(1008, "Removed by admin");
			delete wsClients[publicKey];
		}

		return json(res, 200, { ok: true });
	}

	res.writeHead(404);
	res.end("Not found");
}

// ─── WebSocket ───────────────────────────────────────────────────────────────

const wss = new WebSocketServer({ server });

const ALLOWED_RELAY_TYPES = new Set([
	"call-request", "call-accepted", "call-declined", "call-cancelled",
	"join", "challenge1", "challenge2", "offer", "answer", "ice", "end-call",
]);

wss.on("connection", (ws) => {
	let publicKey = null;

	ws.on("message", (raw) => {
		let msg;
		try { msg = JSON.parse(raw); } catch { return; }

		// ── Registration handshake ──────────────────────────────────────────────
		if (msg.type === "register") {
			const { token, publicKey: pk } = msg;
			if (!token || !pk) {
				ws.send(JSON.stringify({ type: "error", message: "Missing token or publicKey" }));
				return ws.close(1008, "Bad register");
			}

			let decoded;
			try { decoded = jwt.verify(token, JWT_SECRET); }
			catch { ws.send(JSON.stringify({ type: "error", message: "Invalid token" })); return ws.close(1008, "Bad token"); }

			if (decoded.user !== pk) {
				ws.send(JSON.stringify({ type: "error", message: "Token/key mismatch" }));
				return ws.close(1008, "Mismatch");
			}
			if (!approvedUsers.has(pk)) {
				ws.send(JSON.stringify({ type: "error", message: "Not approved" }));
				return ws.close(1008, "Not approved");
			}

			// Replace any stale connection for this key
			if (wsClients[pk]) wsClients[pk].close(1000, "Replaced by new connection");
			publicKey = pk;
			wsClients[publicKey] = ws;
			ws.send(JSON.stringify({ type: "registered" }));
			console.log(`WS registered: ${publicKey}…`);
			return;
		}

		// ── Relay ───────────────────────────────────────────────────────────────
		if (!publicKey) return; // not yet registered
		if (!ALLOWED_RELAY_TYPES.has(msg.type)) return;

		const target = wsClients[msg.to];
		if (!target || target.readyState !== target.OPEN) return;
		target.send(JSON.stringify({ ...msg, from: publicKey })); // always stamp from
		console.log(`Sent from ${publicKey} to ${msg.to}: ${msg}`);
	});

	ws.on("close", () => {
		if (publicKey && wsClients[publicKey] === ws) {
			delete wsClients[publicKey];
			console.log(`WS disconnected: ${publicKey.slice(0, 20)}…`);
		}
	});
});

// ─── Start ───────────────────────────────────────────────────────────────────

server.listen(PORT, "0.0.0.0", () => {
	const base = process.env.RENDER_EXTERNAL_URL || `http${USE_SSL ? "s" : ""}://localhost:${PORT}`;
	console.log(`Signaling server listening on port ${PORT}`);
	console.log(`  Health:  ${base}/api/health`);
	console.log(`  TURN:    ${base}/api/turn-credentials`);
	if (!METERED_SECRET_KEY) console.warn("  ⚠  METERED_SECRET_KEY not set — TURN disabled");
});
