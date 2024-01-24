module.exports = (req, res, next) => {
	const { username, password } = req.body;

	if (!username || !password) {
		res.status(400).json({
			error: "Please enter a username and password.",
		});
	} else {
		next();
	}
};
