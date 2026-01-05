const multer = require("multer");
const path = require("path");

const storage = multer.diskStorage({
	destination: "uploads/profile",
	filename: (req, file, cb) => {
		cb(null, Date.now() + path.extname(file.originalname));
	},
});

const fileFilter = (req, file, cb) => {
	const allowed = ["image/jpeg", "image/png", "image/webp"];
	cb(null, allowed.includes(file.mimetype));
};

module.exports = multer({
	storage,
	fileFilter,
	limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
});
