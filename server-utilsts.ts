import bcrypt from "bcryptjs";

export function uint8ArrayToBase64Url(uint8Array: Uint8Array): string {
	// Step 1: Convert Uint8Array to ArrayBuffer
	console.log("hjhdfs", uint8Array);
	const arrayBuffer = uint8Array.buffer.slice(
		uint8Array.byteOffset,
		uint8Array.byteOffset + uint8Array.byteLength
	);

	// Step 2: Use btoa to Base64 encode the ArrayBuffer
	const base64String = btoa(
		String.fromCharCode(...new Uint8Array(arrayBuffer))
	);

	// Step 3: Replace characters that are not URL-safe
	const base64Url = base64String
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");

	console.log("hhhh", base64String);
	return base64Url;
}

// // Example usage
// const uint8Array = new Uint8Array([72, 101, 108, 108, 111]); // Uint8Array representing 'Hello'
// const base64Url = uint8ArrayToBase64Url(uint8Array);
// console.log(base64Url); // Output: SGVsbG8

export function uint8ArrayToString(uint8Array: Uint8Array): string {
	// Create a TextDecoder with the desired encoding (e.g., 'utf-8')
	const textDecoder = new TextDecoder("utf-8");

	// Decode the Uint8Array to a string
	const decodedString = textDecoder.decode(uint8Array);

	return decodedString;
}

export const findByEmail = async (email: any) => {
	try {
		const userInformation = await dbConfig("users")
			.select("users.*", "profiles.*", "sign_ins.*")
			.join("profiles", "users.id", "profiles.user_id")
			.join("sign_ins", "users.id", "sign_ins.user_id")
			.where("users.email", email)
			.then((data: any) => {
				return data;
			});
		console.log("im here", userInformation);
		return userInformation;
	} catch (error) {
		console.error(error);
		throw error;
	}
};

export const createUser = async (user: {
	email: any;
	firstName: any;
	lastName: any;
	password: any;
	serviceName: any;
}) => {
	try {
		const { email, firstName, lastName, password, serviceName } = user;
		console.log(user);
		// Check if the user already exists

		const existingUser = await dbConfig("users").where({ email }).first();
		if (existingUser) {
			("User with this email already exists");
		}

		await dbConfig.transaction(
			async (trx: {
				(arg0: string): {
					(): any;
					new (): any;
					insert: {
						(arg0: {
							email?: any;
							password?: any;
							webauthn_verified?: boolean;
							user_id?: any;
							first_name?: any;
							last_name?: any;
							verified?: boolean;
							service_name?: any;
						}): {
							(): any;
							new (): any;
							returning: {
								(arg0: string): PromiseLike<[any]> | [any];
								new (): any;
							};
						};
						new (): any;
					};
				};
				(arg0: string): {
					(): any;
					new (): any;
					insert: {
						(arg0: {
							email?: any;
							password?: any;
							webauthn_verified?: boolean;
							user_id?: any;
							first_name?: any;
							last_name?: any;
							verified?: boolean;
							service_name?: any;
						}): {
							(): any;
							new (): any;
							returning: {
								(arg0: string): PromiseLike<[any]> | [any];
								new (): any;
							};
						};
						new (): any;
					};
				};
				commit: any;
			}) => {
				const [userRecord] = await trx("users")
					.insert({ email, password, webauthn_verified: false })
					.returning("*");

				const userId = userRecord.id;

				await trx("profiles")
					.insert({
						user_id: userId,
						first_name: firstName,
						last_name: lastName,
						verified: false,
					})
					.returning("*");

				await trx("sign_ins")
					.insert({
						user_id: userId,
						service_name: serviceName,
					})
					.returning("*");

				await trx.commit();
			}
		);

		const registeredUser = await findByEmail(email);
		return registeredUser[0];
	} catch (error) {
		console.error(error);
		return error;
	}
};

export const verifyAccount = async (email: any) => {
	try {
		const user = await findByEmail(email);

		if (user) {
			await dbConfig("profiles")
				.where({ user_id: user.id })
				.update({ verified: true });
		}
		return user;
	} catch (error) {
		console.error(error);
		throw error;
	}
};

// Function to hash a password
export const hashPassword = async (plainPassword: string) => {
	try {
		const saltRounds = 12;
		const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
		return hashedPassword;
	} catch (error) {
		throw error;
	}
};

// Function to verify a password
export const verifyPassword = async (
	plainPassword: string,
	hashedPassword: any
) => {
	try {
		const passwordMatch = await bcrypt.compare(plainPassword, hashedPassword);
		return passwordMatch;
	} catch (error) {
		throw error;
	}
};

// Example usage
(async () => {
	const userPassword = "mySecurePassword";

	// Hash the password before storing it
	const hashedPassword = await hashPassword(userPassword);
	console.log("Hashed Password:", hashedPassword);

	// Later, when verifying the password during login
	const isPasswordMatch = await verifyPassword(userPassword, hashedPassword);

	if (isPasswordMatch) {
		console.log("Password is correct. Allow access.");
	} else {
		console.log("Invalid password. Deny access.");
	}
})();
