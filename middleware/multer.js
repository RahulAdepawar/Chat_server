const multer = require("multer");
const sharp = require("sharp");
const path = require("path");
const fs = require("fs");

// 📂 Upload folder
const UPLOAD_DIR = path.join(__dirname, "..", "uploads", "chat");

// Ensure directory exists
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ✅ Multer (memory storage for processing)
const upload_chat_doc = multer({
	storage: multer.memoryStorage(),
	limits: {
		fileSize: 10 * 1024 * 1024, // 10MB
		files: 5,
	},
	fileFilter: (req, file, cb) => {
		const allowedMimeTypes = [
			"image/jpeg",
			"image/png",
			"image/webp",
			"image/gif",
			"application/pdf",
			"application/msword",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		];

		if (allowedMimeTypes.includes(file.mimetype)) {
			cb(null, true);
		} else {
			cb(new Error("Unsupported file type"), false);
		}
	},
});

// 🔧 Process & optimize files
const processChatUploads = async (req, res, next) => {
	if (!req.files || req.files.length === 0) {
		req.attachments = [];
		return next();
	}

	try {
		req.attachments = [];

		for (const file of req.files) {
			const ext = path.extname(file.originalname);
			const uniqueName = `${Date.now()}-${Math.round(
				Math.random() * 1e9
			)}${ext}`;

			const outputPath = path.join(UPLOAD_DIR, uniqueName);

			// 🖼️ Image → compress
			if (file.mimetype.startsWith("image/")) {
				await sharp(file.buffer)
					.resize({ width: 1280, withoutEnlargement: true })
					.toFormat("jpeg", { quality: 75 })
					.toFile(outputPath);
			} else {
				// 📄 Non-image → save as-is
				fs.writeFileSync(outputPath, file.buffer);
			}

			const stats = fs.statSync(outputPath);

			req.attachments.push({
				name: uniqueName,
				original_name: file.originalname,
				type: file.mimetype,
				size: stats.size,
				url: `/uploads/chat/${uniqueName}`,
			});
		}

		next();
	} catch (err) {
		console.error("Upload processing error:", err);
		return res.status(500).json({ message: "File upload failed" });
	}
};

module.exports = {
	upload_chat_doc,
	processChatUploads,
};
