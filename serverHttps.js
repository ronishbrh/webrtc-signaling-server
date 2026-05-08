import fs from "fs";
import http from "http";
import https from "https";
import { WebSocketServer } from "ws";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// ---------- CONFIGURATION ----------
const PORT = process.env.PORT || 8080;
const USE_SSL = process.env.USE_SSL === "true";

const METERED_APP_DOMAIN = "webrtc_calling_app.metered.live";
const METERED_SECRET_KEY =
	process.env.METERED_SECRET_KEY || "d534ddd0a0cc115b19aaa0e5a7437231814a";

const SECRET = "super-secret-key";
let ADMIN_TOKEN = "";

const ADMIN_key =
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElcQEtZdf80JRmmQK0rZmzMGLaNy+alxm9/VOu/UC7mHSVBQB5Le+2OjqPvcKgTLwUSBYY6iDEwIjWuB4mkkoXw==";

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

const challenges = new Map();
const approvedUsers = new Map();
const registrationQueue = new Map();

approvedUsers.set(ADMIN_key, true);

// ---------- SERVER ----------
let server;

if (USE_SSL) {
	server = https.createServer({
		key: fs.readFileSync(process.env.SSL_KEY_PATH),
		cert: fs.readFileSync(process.env.SSL_CERT_PATH),
	});
} else {
	server = http.createServer();
}

// ---------- CORS ----------
server.on("request", async (req, res) => {


	res.setHeader("Access-Control-Allow-Origin", "*");
	res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
	res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

	if (req.method === "OPTIONS") {
		res.writeHead(200);
		return res.end();
	}

	const url = req.url.replace(/\/$/, "");

	// ---------- ADMIN LOGIN (FIXED) ----------
	if (req.method === "POST" && url === "/auth/admin-login") {
		let body = "";

		req.on("data", (c) => (body += c));

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
			} catch {
				res.writeHead(500);
				return res.end("Server error");
			}
		});

		return;
	}

	// ---------- HEALTH ----------
	if (req.url === "/api/health") {
		res.writeHead(200);
		return res.end(JSON.stringify({ status: "ok" }));
	}

	// ---------- REGISTER ----------
	if (req.method === "POST" && url === "/register") {
		let body = "";

		req.on("data", (c) => (body += c));

		req.on("end", () => {
			const { publicKey, message } = JSON.parse(body);

			const key = String(publicKey).trim();

			registrationQueue.set(key, {
				publicKey: key,
				message: String(message),
				time: Date.now(),
			});

			res.writeHead(200);
			res.end("OK");
		});
		return;
	}

	// ---------- ADMIN CHECK HELPER ----------
	function verifyAdmin(req, res) {
		try {
			const authHeader = req.headers.authorization;

			if (!authHeader) throw new Error();

			const token = authHeader.startsWith("Bearer ")
				? authHeader.split(" ")[1]
				: authHeader;

			const decoded = jwt.verify(token, SECRET);

			if (!decoded || decoded.role !== "admin") throw new Error();

			return true;
		} catch {
			res.writeHead(403);
			res.end("Forbidden");
			return false;
		}
	}
	// ---------- REQUESTS ----------
	if (req.method === "GET" && url === "/admin/requests") {
		if (!verifyAdmin(req, res)) return;

		res.writeHead(200, { "Content-Type": "application/json" });
		return res.end(JSON.stringify([...registrationQueue.values()]));
	}

	// ---------- APPROVE ----------
	if (req.method === "POST" && url === "/admin/approve") {
		if (!verifyAdmin(req, res)) return;

		let body = "";
		req.on("data", (c) => (body += c));

		req.on("end", () => {
			const { publicKey } = JSON.parse(body);
			const key = String(publicKey).trim();

			registrationQueue.delete(publicKey);
			approvedUsers.set(publicKey, true);

			res.writeHead(200);
			res.end("approved");
		});

		return;
	}

	// ---------- REJECT ----------
	if (req.method === "POST" && url === "/admin/reject") {
		if (!verifyAdmin(req, res)) return;

		let body = "";
		req.on("data", (c) => (body += c));

		req.on("end", () => {
			const { publicKey } = JSON.parse(body);

			registrationQueue.delete(publicKey);

			res.writeHead(200);
			res.end("rejected");
		});

		return;
	}

	// ---------- APPROVED USERS ----------
	if (req.method === "GET" && url === "/admin/approved") {
		if (!verifyAdmin(req, res)) return;

		res.writeHead(200, { "Content-Type": "application/json" });
		return res.end(JSON.stringify([...approvedUsers.keys()]));
	}

	// ---------- REMOVE USER ----------
	if (req.method === "POST" && url === "/admin/remove") {
		if (!verifyAdmin(req, res)) return;

		let body = "";
		req.on("data", (c) => (body += c));

		req.on("end", () => {
			const { publicKey } = JSON.parse(body);

			approvedUsers.delete(publicKey);

			res.writeHead(200);
			res.end("removed");
		});

		return;
	}

	// ---------- STATUS CHECK ----------
	if (req.method === "GET" && url === "/auth/status") {
		const auth = req.headers.authorization;

		if (!auth) {
			res.writeHead(401);
			return res.end("No token");
		}

		try {
			const token = auth.startsWith("Bearer ")
				? auth.split(" ")[1]
				: auth;

			const decoded = jwt.verify(token, SECRET);

			const user = decoded.user;

			const isApproved = approvedUsers.has(user);

			res.writeHead(200, { "Content-Type": "application/json" });
			return res.end(JSON.stringify({
				approved: isApproved
			}));

		} catch {
			res.writeHead(403);
			return res.end("Forbidden");
		}
	}

	// ---------- AUTH CHALLENGE ----------
	if (req.method === "POST" && url === "/auth/challenge") {
		let body = "";

		req.on("data", (c) => (body += c));

		req.on("end", () => {
			const { publicKey } = JSON.parse(body);

			const nonce = crypto.randomBytes(32).toString("hex");
			challenges.set(publicKey, nonce);

			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ nonce }));
		});

		return;
	}

	// ---------- VERIFY (FIXED SIGNATURE HANDLING) ----------
	if (req.method === "POST" && url === "/auth/verify") {
		let body = "";

		req.on("data", (c) => (body += c));

		req.on("end", () => {
			try {
				const { publicKey, signature } = JSON.parse(body);

				if (!approvedUsers.has(publicKey)) {
					res.writeHead(403);
					return res.end("not approved");
				}

				const nonce = challenges.get(publicKey);

				const verify = crypto.createVerify("SHA256");
				verify.update(nonce);
				verify.end();

				const valid = verify.verify(
					publicKey,
					Buffer.from(signature, "base64")
				);

				if (!valid) {
					res.writeHead(401);
					return res.end("invalid signature");
				}

				const token = jwt.sign(
					{
						user: publicKey,
						role: publicKey === ADMIN_key ? "admin" : "user",
					},
					SECRET,
					{ expiresIn: "1h" }
				);

				if (publicKey === ADMIN_key) {
					ADMIN_TOKEN = token;
				}

				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(
					JSON.stringify({
						token,
						isAdmin: publicKey === ADMIN_key,
					})
				);
			} catch {
				res.writeHead(500);
				res.end("verify error");
			}
		});

		return;
	}

	res.writeHead(404);
	res.end("Not found");
});

// ---------- WEBSOCKET ----------
const wss = new WebSocketServer({ server });
const clients = {};

wss.on("connection", (ws, req) => {
	const url = new URL(req.url, "http://localhost");
	const token = url.searchParams.get("token");

	if (!token) return ws.close();

	let payload;

	try {
		payload = jwt.verify(token, SECRET);
	} catch {
		return ws.close();
	}

	const userId = payload.user;

	ws.on("message", (msg) => {
		const data = JSON.parse(msg);

		if (data.type === "register") {
			clients[userId] = ws;
			return;
		}

		const target = clients[data.to];
		if (target) target.send(JSON.stringify(data));
	});
});

// ---------- START ----------
server.listen(PORT, () => {
	console.log("Server running on", PORT);
});