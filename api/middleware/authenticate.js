const jwt = require("jsonwebtoken");
require("dotenv").config();

module.exports = (req, res, next) => {
	const { authenticate } = req.headers;

	if (authenticate) {
		const secret = process.env.JWT_SECRET;

		jwt.verify(authenticate, secret, function (err, decodedToken) {
			if (err) {
				res.status(401).json({
					message: "Invalid Token - unfortunately you shall not pass!",
				});
			} else {
				req.token = decodedToken;

				next();
			}
		});
	} else {
		res
			.status(400)
			.json({ message: "Please login and try again - authentication error" });
	}
};
