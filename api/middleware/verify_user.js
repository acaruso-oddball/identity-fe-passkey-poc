const Users = require("../models/user_model");

module.exports = (req, res, next) => {
	let  {user_id}  = req.params 
	Users.findById(user_id)
		.then((user) => {
			if (!user) {
				res.status(404).json({ error: "Invalid user ID: User not found." });
			} else {
				next();
			}
		})
		.catch(() =>
			res.status(500).json({ error: "There was an error finding the user." })
		);
};
