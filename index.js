const express = require("express");
const pool = require("./db_connect.js");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const authMiddleware = require("./middleware/auth.js");

const {
	upload_chat_doc,
	processChatUploads,
} = require("./middleware/multer.js");


const fs = require("fs");

const upload = require("./upload");

const http = require("http");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8000;

const { Server } = require("socket.io");
const server = http.createServer(app);

const io = new Server(server, {
	cors: {
		origin: process.env.ORIGIN,
		credentials: true,
	},
});

const socketAuth = require("./middleware/socketAuth.js");
io.use(socketAuth);
io.on("connection", (socket) => {
	const userId = socket.user.user_id;
	console.log("🟢 Socket connected:", socket.id, "User:", userId);

	socket.on("join_chat", async (roomId) => {
		const [u1, u2] = roomId.split("_").map(Number);

		if (userId !== u1 && userId !== u2) {
			console.warn("🚫 Unauthorized room join:", userId, roomId);
			return;
		}

		socket.join(roomId);
	});

	socket.on("leave_chat", (roomId) => {
		socket.leave(roomId);
	});

	socket.on("typing", ({ roomId }) => {
		socket.to(roomId).emit("user_typing", userId);
	});

	socket.on("stop_typing", ({ roomId }) => {
		socket.to(roomId).emit("user_stop_typing", userId);
	});

	socket.on("message_delivered", async ({ roomId, messageId }) => {
		try {
			const result = await pool.query(
				`UPDATE message_status
				 SET status = 'delivered'
				 WHERE message_id = $1
				   AND user_id = $2
				   AND status = 'sent'
				 RETURNING message_id`,
				[messageId, userId]
			);

			if (result.rowCount > 0) {
				socket.to(roomId).emit("message_status_update", {
					messageId,
					status: "delivered",
				});
			}
		} catch (err) {
			console.error("Delivered update error:", err);
		}
	});

	socket.on("message_read", async ({ roomId, messageId }) => {
		try {
			const result = await pool.query(
				`UPDATE message_status
				 SET status = 'read'
				 WHERE message_id = $1
				   AND user_id = $2
				   AND status != 'read'
				 RETURNING message_id`,
				[messageId, userId]
			);

			if (result.rowCount > 0) {
				socket.to(roomId).emit("message_status_update", {
					messageId,
					status: "read",
				});
			}
		} catch (err) {
			console.error("Read update error:", err);
		}
	});

	socket.on("disconnect", () => {
		console.log("🔴 Socket disconnected:", socket.id);
	});
});

app.use(cors({
	origin: process.env.ORIGIN,
	credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use("/uploads", express.static(path.join(process.cwd(), "uploads")));

pool.query("SELECT 1")
	.then(() => console.log("✅ DB connected"))
	.catch(err => console.error("❌ DB connection failed", err));

app.post("/api/logout", (req, res) => {
	const isProduction = process.env.NODE_ENV === "production";

	res.clearCookie("token", {
		httpOnly: true,
		sameSite: "strict",
		sameSite: isProduction ? "none" : "lax",
		secure: true,
	});
	res.json({ message: "Logged out", status: true });
});

app.get("/api/profile", authMiddleware, async (req, res) => {
	try {
		// ✅ user_id comes from JWT
		const user_id = req.user.user_id;

		const result = await pool.query(
			"SELECT username, email, mobile, profile_image FROM users WHERE user_id = $1",
			[user_id]
		);

		const user = result.rows[0];

		if (!user) {
			return res.status(404).json({ message: "User not found" });
		}

		return res.status(200).json({
			message: "Profile fetched successfully",
			data: user,
		});
	} catch (e) {
		console.error(e);
		return res.status(500).json({ message: "Server error" });
	}
});

app.post("/api/login", async (req, res) => {
	try {

		const { username, password } = req.body;

		if (!username || !password) {
			return res.json({ status: 400, success: false, message: "All fields are required" });
		}

		const result = await pool.query(
			`SELECT user_id, password FROM users WHERE email = '${username}'`
		);
		if (result.rowCount === 0) {
			return res.json({ status: 401, success: false, message: "Invalid credentials" });
		}

		const user = result.rows[0];

		let verify_password = await bcrypt.compareSync(password, user.password);

		if (!verify_password) {
			return res.json({ status: 401, success: false, message: "Wrong credentials" });
		}

		const token = jwt.sign(
			{ user_id: user.user_id },
			process.env.JWT_SECRET,
			{ expiresIn: "1h" }
		);

		// 🍪 Set cookie
		res.cookie("token", token, {
			httpOnly: true,
			secure: true, // true in production (https)
			sameSite: "None",
			maxAge: 60 * 60 * 1000
		});

		return res.json({ status: 200, success: true, message: "Login successful", user_id: user.user_id });

	} catch (e) {
		console.error(e);
		return res.status(500).json({ message: "Server error" });
	}
});

app.post("/api/users", async (req, res) => {
	try {

		const { name, mobile, email, password } = req.body;

		if (!name || !password || !email || !mobile) {
			return res.status(400).json({ message: "All fields are required" });
		}

		console.log("HEADERS:", req.headers);
		console.log("BODY:", req.body);
		console.log("COOKIES:", req.cookies);

		const salt = await bcrypt.genSalt(10);
		const hash_password = await bcrypt.hash(password, salt);

		const checkUsersExist = await pool.query(`SELECT USER_ID FROM USERS WHERE EMAIL = $1`, [email]);
		console.log("checkUsersExist:", checkUsersExist);
		if (checkUsersExist.rows[0]) {
			return res.status(409).json({ message: "This email already registred." });
		}

		const result = await pool.query(
			`INSERT INTO USERS (username, mobile, email, password) VALUES ($1, $2, $3, $4)`,
			[name, mobile, email, hash_password]
		);

		if (result.rowCount) {
			return res.json({ message: "Data successfully saved", status: 200 });
		}
		else {
			return res.json({ message: "Failed to save data.", status: 500 });
		}
	}
	catch (e) {
		console.log(e);
		return res.json({ message: e.detail });
	}
});

// protected route
app.post("/api/auth/check", authMiddleware, (req, res) => {
	return res.status(200).json({
		authenticated: true,
		user: req.user
	});
});

app.post("/api/add_contact", authMiddleware, async (req, res) => {
	try {
		const { name, email_mobile } = req.body;
		const loggedInUserId = req.user.user_id;

		if (!name || !email_mobile) {
			return res.status(400).json({ message: "All fields are required", status: 400 });
		}

		// 🔎 Find contact user
		const result = await pool.query(
			`SELECT user_id FROM users WHERE email = $1 OR mobile = $1`,
			[email_mobile]
		);

		const contactUser = result.rows[0];

		if (!contactUser) {
			return res.status(404).json({ message: "This contact does not exist", status: 404 });
		}

		if (contactUser.user_id === loggedInUserId) {
			return res.status(400).json({ message: "You cannot add yourself", status: 400 });
		}

		const exists = await pool.query(`SELECT user_id, is_saved FROM contact_list WHERE user_id = $1 AND contact_user_id = $2`,
			[loggedInUserId, contactUser.user_id]
		);

		if (exists.rowCount > 0) {
			if (exists.rows[0].is_saved === 0) {
				await pool.query(`UPDATE contact_list SET is_saved = 1, contact_user_name = $1 WHERE user_id = $2 AND contact_user_id = $3`,
					[name, loggedInUserId, contactUser.user_id]
				);

				return res.status(200).json({
					message: "Contact added successfully",
					status: 200
				});
			}

			return res.status(409).json({ message: "Contact already exists", status: 409 });
		}

		// ✅ Insert contact
		await pool.query(`INSERT INTO contact_list (
				user_id, 
				contact_user_id, 
				contact_user_name, 
				mute, 
				pin,
				is_saved
			) VALUES (
				$1, 
				$2, 
				$3, 
				0, 
				0,
				1
			)`,
			[loggedInUserId, contactUser.user_id, name]
		);

		return res.status(200).json({
			message: "Contact added successfully",
			status: 200
		});

	} catch (e) {
		console.error(e);
		return res.status(500).json({ message: "Server error", status: 500 });
	}
});

app.get("/api/get_contacts", authMiddleware, async (req, res) => {
	try {
		const loggedInUserId = req.user.user_id;

		// 🔎 Find contact user
		const result = await pool.query(
			`SELECT 
				c.contact_list_id,
				c.contact_user_id,
				c.contact_user_name,
				c.mute,
				c.is_saved,
				u.profile_image,
				COALESCE(v.last_message, '') AS last_message,
				v.last_sender_id,
				COALESCE(v.pending, 0) AS pending
			FROM contact_list c
			JOIN users u 
				ON u.user_id = c.contact_user_id
			LEFT JOIN chats ch
				ON ch.user1_id = LEAST($1, c.contact_user_id)
				AND ch.user2_id = GREATEST($1, c.contact_user_id)
			LEFT JOIN (
				SELECT
					M.chat_id,
					(
						SELECT content
						FROM messages m2
						WHERE m2.chat_id = M.chat_id
						ORDER BY m2.created_at DESC
						LIMIT 1
					) AS last_message,
					(
						SELECT sender_id
						FROM messages m2
						WHERE m2.chat_id = M.chat_id
						ORDER BY m2.created_at DESC
						LIMIT 1
					) AS last_sender_id,
					COUNT(*) AS pending
				FROM messages M
				JOIN message_status MS 
					ON MS.message_id = M.message_id
				WHERE
					MS.user_id = $1
					AND MS.status = 'sent'
					AND MS.user_id <> M.sender_id
				GROUP BY
					M.chat_id
			) v ON v.chat_id = ch.chat_id
			WHERE 
				c.user_id = $1
			ORDER BY
				pending DESC;

			`,
			[loggedInUserId]
		);

		const pending_messages_data = await pool.query(`SELECT
				M.chat_id,
				MAX(M.created_at) AS last_message_time,
				(
					SELECT content
					FROM messages m2
					WHERE m2.chat_id = M.chat_id
					ORDER BY m2.created_at DESC
					LIMIT 1
				) AS last_message,
				(
					SELECT sender_id
					FROM messages m2
					WHERE m2.chat_id = M.chat_id
					ORDER BY m2.created_at DESC
					LIMIT 1
				) AS last_sender_id,
				COUNT(*) AS pending
			FROM messages M
			JOIN message_status MS 
				ON MS.message_id = M.message_id
			WHERE
				MS.user_id = $1
				AND MS.user_id <> M.sender_id
				AND MS.status = 'sent'
			GROUP BY
				M.chat_id
			ORDER BY
				last_message_time DESC`,
			[loggedInUserId]
		);

		return res.status(200).json({
			message: "Fetch Contact List Successfully.",
			data: result.rows,
			pending_messages_data: pending_messages_data.rows,
			status: 200
		});

	} catch (e) {
		console.error(e);
		return res.status(500).json({ message: "Server error", status: 500 });
	}
});

app.get("/api/contact_list", authMiddleware, async (req, res) => {
	try {
		const loggedInUserId = req.user.user_id;

		// 🔎 Find contact user
		const result = await pool.query(
			`SELECT 
				c.contact_list_id,
				c.contact_user_id,
				c.contact_user_name,
				c.mute,
				c.is_saved,
				u.mobile,
				u.email,
				u.profile_image
			FROM contact_list c
				JOIN users u ON u.user_id = c.contact_user_id
			WHERE 
				c.user_id = $1
				AND c.is_saved = 1
			ORDER BY
				c.contact_list_id ASC;

			`,
			[loggedInUserId]
		);

		return res.status(200).json({
			message: "Fetch Contact List Successfully.",
			data: result.rows,
			status: 200
		});

	} catch (e) {
		console.error(e);
		return res.status(500).json({ message: "Server error", status: 500 });
	}
});

app.post(
	"/api/send_message",
	authMiddleware,
	upload_chat_doc.array("attachments", 5),
	processChatUploads,
	async (req, res) => {
		const senderId = req.user.user_id;
		const { contactId, message } = req.body;
		const receiverId = parseInt(contactId, 10);

		if (Number.isNaN(receiverId)) {
			return res.status(400).json({ message: "Invalid contactId" });
		}

		const attachments = req.attachments || [];

		const hasText = typeof message === "string" && message.trim().length > 0;
		const hasFiles = attachments.length > 0;

		if (!receiverId || (!hasText && !hasFiles)) {
			return res.status(400).json({ message: "Message cannot be empty" });
		}

		try {
			// ✅ Ensure sender exists in receiver contact list
			const contactCheck = await pool.query(
				`SELECT 1
				 FROM contact_list
				 WHERE user_id = $1 AND contact_user_id = $2`,
				[receiverId, senderId]
			);

			if (contactCheck.rowCount === 0) {
				await pool.query(
					`INSERT INTO contact_list (
						user_id,
						contact_user_id,
						contact_user_name,
						mute,
						pin,
						is_saved
					) VALUES ($1, $2, $3, 0, 0, 0)`,
					[receiverId, senderId, "USER"]
				);
			}

			// ✅ Find or create chat
			const chatResult = await pool.query(
				`INSERT INTO chats (user1_id, user2_id)
				 VALUES (
					LEAST($1::INTEGER, $2::INTEGER),
					GREATEST($1::INTEGER, $2::INTEGER)
				 )
				 ON CONFLICT (user1_id, user2_id)
				 DO NOTHING
				 RETURNING chat_id`,
				[senderId, receiverId]
			);

			let chatId;
			if (chatResult.rowCount > 0) {
				chatId = chatResult.rows[0].chat_id;
			} else {
				const existingChat = await pool.query(
					`SELECT chat_id
					 FROM chats
					 WHERE user1_id = LEAST($1::INTEGER, $2::INTEGER)
					   AND user2_id = GREATEST($1::INTEGER, $2::INTEGER)`,
					[senderId, receiverId]
				);
				chatId = existingChat.rows[0].chat_id;
			}

			// ✅ Insert message
			const messageResult = await pool.query(
				`INSERT INTO messages (
					chat_id,
					sender_id,
					content,
					attachments
				) VALUES ($1, $2, $3, $4)
				RETURNING
					message_id AS id`,
				[
					chatId,
					senderId,
					hasText ? message.trim() : null,
					attachments.length ? JSON.stringify(attachments) : null,
				]
			);

			const savedMessage = messageResult.rows[0];

			// ✅ Message status
			await pool.query(
				`INSERT INTO message_status (message_id, user_id, status)
				 VALUES
				 ($1, $2, 'sent'),
				 ($1, $3, 'sent')`,
				[savedMessage.id, senderId, receiverId]
			);

			const result = await pool.query(`SELECT
					m.message_id AS id,
					m.sender_id,
					m.content AS message,
					m.attachments,
					m.created_at,
					ms.status
				FROM messages m
				LEFT JOIN message_status ms
					ON ms.message_id = m.message_id
					AND ms.user_id = $2
				WHERE m.message_id = $1
				`,
				[savedMessage.id, senderId]
			);

			const getMessage = result.rows[0];

			// ✅ Socket emit
			const roomId = [senderId, receiverId].sort((a, b) => a - b).join("_");
			io.to(roomId).emit("receive_message", getMessage);

			res.json({ success: true, data: getMessage });
		} catch (err) {
			console.error("send_message error:", err);
			res.status(500).json({ message: "Failed to send message" });
		}
	}
);

app.get("/api/get_messages/:contactId", authMiddleware, async (req, res) => {
	const userId = parseInt(req.user.user_id, 10); // ✅ FIX
	const contactId = parseInt(req.params.contactId, 10);

	if (isNaN(userId) || isNaN(contactId)) {
		return res.status(400).json({ message: "Invalid userId or contactId" });
	}

	try {
		const chatResult = await pool.query(`SELECT 
				chat_id
			FROM chats
			WHERE 
				user1_id = LEAST($1::INTEGER, $2::INTEGER)
				AND user2_id = GREATEST($1::INTEGER, $2::INTEGER)
			`,
			[userId, contactId]
		);


		if (chatResult.rows.length === 0) {
			return res.json({ success: true, data: [] });
		}

		const chatId = chatResult.rows[0].chat_id;

		const messagesResult = await pool.query(
			`SELECT 
				m.message_id AS id, 
				m.sender_id, 
				m.content AS message, 
				m.attachments,
				COALESCE(ms.status, 'sent') AS status,
				m.created_at
			FROM messages m
				LEFT JOIN message_status ms on ms.message_id = m.message_id AND ms.user_id = $2 
			WHERE 
				chat_id = $1
				AND is_deleted = FALSE
			ORDER BY 
				created_at ASC
			`,
			[chatId, contactId]
		);

		return res.json({
			success: true,
			data: messagesResult.rows,
		});
	} catch (err) {
		console.error(err);
		res.status(500).json({ message: "Failed to load messages" });
	}
});

app.get("/api/contact_list_detail/:userID/:contactID", async (req, res) => {
	const userID = Number(req.params.userID);
	const contactID = Number(req.params.contactID);

	if (isNaN(userID) || isNaN(contactID)) {
		return res.status(400).json({
			success: false,
			message: "Invalid userID or contactID",
		});
	}

	try {
		const result = await pool.query(`SELECT 
				c.CONTACT_LIST_ID, 
				c.USER_ID, 
				c.CONTACT_USER_ID, 
				c.MUTE, 
				c.PIN, 
				c.CONTACT_USER_NAME,
				c.IS_SAVED,
				u.mobile,
				u.profile_image,
				u.email
			FROM CONTACT_LIST c
				JOIN USERS u on u.USER_ID = c.CONTACT_USER_ID
			WHERE 
				c.USER_ID = $1
				AND c.CONTACT_USER_ID = $2
			`,
			[userID, contactID]
		);

		if (result.rows.length === 0) {
			return res.status(404).json({
				success: false,
				message: "Contact list detail not found",
			});
		}

		return res.status(200).json({
			success: true,
			data: result.rows[0],
		});
	}
	catch (e) {
		console.error(e);
		return res.status(500).json({ message: "Failed to load contact list detail" });
	}
});

app.post(
	"/api/upload-profile-image",
	authMiddleware,
	upload.single("profile_image"),
	async (req, res) => {
		try {
			const userId = req.user.user_id; // ✅ correct

			const imagePath = `/uploads/profile/${req.file.filename}`;

			// 1️⃣ Get old image from DB
			const result = await pool.query(
				"SELECT profile_image FROM users WHERE user_id = $1",
				[userId]
			);

			const oldImage = result.rows[0]?.profile_image;

			// 2️⃣ Delete old file if exists
			if (oldImage) {
				console.log("oldImage", oldImage)
				const oldPath = path.join(
					__dirname,
					oldImage
				);

				if (fs.existsSync(oldPath)) {
					console.log("unlink 1")
					fs.unlinkSync(oldPath);
					console.log("unlink 2")
				}
			}

			await pool.query(
				`UPDATE users SET profile_image = $1 WHERE user_id = $2`,
				[imagePath, userId]
			);

			res.json({
				success: true,
				image: imagePath,
			});
		} catch (err) {
			console.error(err);
			res.status(500).json({ message: "Upload failed" });
		}
	}
);

app.post("/api/contact/mute", authMiddleware, async (req, res) => {
	const loggedInUserId = req.user.user_id;

	try {
		const { contact_list_id, contact_id, mute } = req.body
		console.log(mute, contact_list_id, loggedInUserId, contact_id)
		const result = await pool.query("UPDATE CONTACT_LIST SET MUTE = $1 WHERE CONTACT_LIST_ID = $2 AND USER_ID = $3 AND CONTACT_USER_ID = $4",
			[mute, contact_list_id, loggedInUserId, contact_id]);

		if (result.rowCount === 0) {
			return res.status(404).json({ message: "No record updated" });
		}

		return res.json({ message: "Mute updated successfully", status: true });
	}
	catch {

	}
});

app.post("/api/contact/delete", authMiddleware, async (req, res) => {
	const loggedInUserId = req.user.user_id;

	try {
		const { contact_list_id, contact_id, deleted } = req.body;

		const result = await pool.query("UPDATE CONTACT_LIST SET MUTE = 0, IS_SAVED = $1 WHERE CONTACT_LIST_ID = $2 AND USER_ID = $3 AND CONTACT_USER_ID = $4",
			[deleted, contact_list_id, loggedInUserId, contact_id]);

		if (result.rowCount === 0) {
			return res.status(404).json({ message: "No record deleted" });
		}

		return res.json({ message: "Contact deleted successfully", status: true });
	}
	catch {

	}
});

app.post(
	"/api/tasks/create",
	authMiddleware,
	upload.single("task_attachment"),
	async (req, res) => {
		const client = await pool.connect(); // 🔑 IMPORTANT

		try {
			const senderId = req.user.user_id;
			const { title, description, priority, due_date, contactId } = req.body;
			const receiverId = parseInt(contactId, 10);

			if (!title) {
				return res.status(400).json({ message: "Title cannot be empty" });
			}

			if (Number.isNaN(receiverId)) {
				return res.status(400).json({ message: "Invalid contactId" });
			}

			// ✅ START TRANSACTION
			await client.query("BEGIN");

			// 1️⃣ Ensure contact exists
			const contactCheck = await client.query(
				`SELECT 1
				 FROM contact_list
				 WHERE user_id = $1 AND contact_user_id = $2`,
				[receiverId, senderId]
			);

			if (contactCheck.rowCount === 0) {
				await client.query(
					`INSERT INTO contact_list (
						user_id,
						contact_user_id,
						contact_user_name,
						mute,
						pin,
						is_saved
					) VALUES ($1, $2, $3, 0, 0, 0)`,
					[receiverId, senderId, "USER"]
				);
			}

			// 2️⃣ Find or create chat
			const chatResult = await client.query(
				`INSERT INTO chats (user1_id, user2_id)
				 VALUES (
					LEAST($1::INTEGER, $2::INTEGER),
					GREATEST($1::INTEGER, $2::INTEGER)
				 )
				 ON CONFLICT (user1_id, user2_id)
				 DO NOTHING
				 RETURNING chat_id`,
				[senderId, receiverId]
			);

			let chatId;
			if (chatResult.rowCount > 0) {
				chatId = chatResult.rows[0].chat_id;
			} else {
				const existingChat = await client.query(
					`SELECT chat_id
					 FROM chats
					 WHERE user1_id = LEAST($1::INTEGER, $2::INTEGER)
					   AND user2_id = GREATEST($1::INTEGER, $2::INTEGER)`,
					[senderId, receiverId]
				);
				chatId = existingChat.rows[0].chat_id;
			}

			// 3️⃣ Insert message
			const messageResult = await client.query(
				`INSERT INTO messages (
					chat_id,
					sender_id,
					content
				) VALUES ($1, $2, $3)
				RETURNING message_id, sender_id, content, created_at`,
				[
					chatId,
					senderId,
					`📌 Task Assigned: ${title}`,
				]
			);

			const savedMessage = messageResult.rows[0];

			// 4️⃣ Message status
			await client.query(
				`INSERT INTO message_status (message_id, user_id, status)
				 VALUES
				 ($1, $2, 'sent'),
				 ($1, $3, 'sent')`,
				[savedMessage.message_id, senderId, receiverId]
			);

			// 5️⃣ Insert task (RETURNING task_id)
			const taskResult = await client.query(
				`INSERT INTO tasks (
					title,
					description,
					assigned_to,
					assigned_by,
					status,
					priority,
					due_date,
					chat_id,
					message_id
				) VALUES (
					$1, $2, $3, $4, 'pending', $5, $6, $7, $8
				)
				RETURNING task_id`,
				[
					title,
					description,
					receiverId,
					senderId,
					priority || "medium",
					due_date || null,
					chatId,
					savedMessage.message_id
				]
			);

			const taskId = taskResult.rows[0].task_id;

			// ✅ COMMIT TRANSACTION
			await client.query("COMMIT");

			// 6️⃣ Emit socket AFTER commit
			const roomId = [senderId, receiverId].sort((a, b) => a - b).join("_");

			io.to(roomId).emit("receive_message", savedMessage);
			io.to(roomId).emit("task_assigned", {
				task_id: taskId,
				title,
				assigned_to: receiverId,
				assigned_by: senderId,
				priority,
				due_date
			});

			res.json({
				success: true,
				message: "Task successfully created",
				task_id: taskId
			});
		} catch (err) {
			// ❌ ROLLBACK ON ERROR
			await client.query("ROLLBACK");

			console.error("Create task error:", err);
			res.status(500).json({ message: "Failed to create task" });
		} finally {
			client.release(); // 🔓 ALWAYS RELEASE
		}
	}
);

app.get("/api/tasks/received", authMiddleware, async (req, res) => {
	const userId = parseInt(req.user.user_id, 10);

	try {
		const result = await pool.query(`select 
				t.task_id,
				t.title,
				t.description,
				t.assigned_by,
				u.username as assigned_by_name,
				t.status,
				t.priority,
				t.due_date,
				t.created_at
			from tasks t
				join users u on u.user_id = assigned_by
			where
				t.assigned_to = $1;
			`,
			[userId]
		);

		if (result.rows.length === 0) {
			return res.status(404).json({
				success: false,
				message: "Tasks list not found",
			});
		}

		return res.status(200).json({
			success: true,
			data: result.rows,
		});
	}
	catch (e) {
		console.error(e);
		return res.status(500).json({ message: "Failed to load tasks list" });
	}
});

app.get("/api/tasks/assigned", authMiddleware, async (req, res) => {
	const userId = parseInt(req.user.user_id, 10);

	try {
		const result = await pool.query(`select 
				t.task_id,
				t.title,
				t.description,
				t.assigned_to,
				u.username as assigned_to_name,
				t.status,
				t.priority,
				t.due_date,
				t.created_at
			from tasks t
				join users u on u.user_id = assigned_to
			where
				t.assigned_by = $1;
			`,
			[userId]
		);

		if (result.rows.length === 0) {
			return res.status(404).json({
				success: false,
				message: "Tasks list not found",
			});
		}

		return res.status(200).json({
			success: true,
			data: result.rows,
		});
	}
	catch (e) {
		console.error(e);
		return res.status(500).json({ message: "Failed to load tasks list" });
	}
});

server.listen(PORT, () => {
	console.log("🚀 Server + Socket.IO running on port", PORT);
});
