const jwt = require("jsonwebtoken");
const cookie = require("cookie");

const socketAuth = (socket, next) => {
	try {
		const cookies = socket.handshake.headers.cookie;
		if (!cookies) {
			return next(new Error("No cookies found"));
		}

		const parsedCookies = cookie.parse(cookies);
		const token = parsedCookies.token; // 🔑 your cookie name

		if (!token) {
			return next(new Error("No token in cookies"));
		}

		const decoded = jwt.verify(token, process.env.JWT_SECRET);

		socket.user = {
			user_id: decoded.user_id,
		};

		next();
	} catch (err) {
		next(new Error("Invalid or expired token"));
	}
};

module.exports = socketAuth;
