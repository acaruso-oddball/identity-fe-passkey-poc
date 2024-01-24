const db = require("../../database/dbConfig");


export const findByEmail = async (email) => {
	try {
		const userInformation = await db("profile")
			.select("profile.*", "signIn.*")
			.join("signIn", "profile.signIn_id", "signIn.id")
			.where("profile.email", email)
			.then((data) => {
				return data;
			});

		return userInformation[0];
	} catch (error) {
		console.error(error);
		throw error;
	}
};

export const createUser = async (user) => {
	try {
		const { email, firstName, lastName, password, serviceName } = user;
		console.log(user);
		// Check if the user already exists

		const existingUser = await db("profile").where({ email }).first();
		if (existingUser) {
			("User with this email already exists");
		}

		await db.transaction(async (trx) => {
			const [signIn] = await trx("signIn")
				.insert({
					password,
					serviceName,
				})
				.returning("*");

			const signInId = signIn.id;
			const [profile] = await trx("profile")
				.insert({
					email,
					firstName,
					lastName,
					signIn_id: signInId,
				})
				.returning("*");

			const profile_id = profile.id;

			const [attributes] = await trx("attributes")
				.insert({
					profile_id,
				})
				.returning("*");

			const attributes_id = attributes.id;

			await trx("user")
				.insert({
					attributes_id,
				})
				.returning("*");

			await trx.commit();
		});

		const registeredUser = await findByEmail(email);

		console.log("110", registeredUser);
		return registeredUser;
	} catch (error) {
		console.error(error);
		return error;
	}
};

const verifyAccount = async (email) => {
	try {
		const user = await findByEmail(email);
		console.log("70 user mod", user);
		if (user) {
			console.log(`Found user with email: ${email}, id: ${user.id}`);
			const updateResult = await db("profiles")
				.where({ user_id: user.id })
				.update({ verified: true });

			console.log(`Update result:`, updateResult);
		}

		return user;
	} catch (error) {
		console.error(error);
		throw error;
	}
};

module.exports = {
	createUser,
	findByEmail,
	verifyAccount,
	loginWithPassword,
};
