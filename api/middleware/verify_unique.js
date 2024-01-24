const Users = require("../models/user_model");

module.exports = (req, res, next) => {
	const { username } = req.body;
	Users.findBy({username}).then(
        (user) => {
		if (user[0]) {
			res.status(400).json({ error: "This username is already taken. Please choose another." });
		} else {
			next();
		}
	});
};
