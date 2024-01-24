import bcrypt from "bcryptjs";
import { sign } from "crypto";
import db from "./database/dbConfig.js";

export function uint8ArrayToBase64Url(uint8Array) {
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

export function uint8ArrayToString(uint8Array) {
	// Create a TextDecoder with the desired encoding (e.g., 'utf-8')
	const textDecoder = new TextDecoder("utf-8");

	// Decode the Uint8Array to a string
	const decodedString = textDecoder.decode(uint8Array);

	return decodedString;
}

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

export const verifyAccount = async (email) => {
	try {
		const profileArray = await findByEmail(email);
		console.log("70 user mod", profileArray);

		if (profileArray) {
			const profile = profileArray;

			console.log(`Found user with email: ${email}, id: ${profile.id}`);

			const updateResult = await db("profile")
				.where({ email: email })
				.update({ verified: true });
			console.log(`Update result:`, updateResult);
		}

		return findByEmail(email);
	} catch (error) {
		console.error(error);
		throw error;
	}
};

const findById = async (signInId) => {
	try {
		const signInInfo = await db("signIn")
			.select("signIn.*")
			.where("signIn.id", signInId)
			.then((data) => {
				return data;
			});
		console.log("signin data", signInInfo[0].devices);
		return signInInfo[0];
	} catch (error) {
		console.error(error);
		throw error;
	}
};

export const findRegisteredDevices = async (signInId) => {
	try {
		const registeredDevices = await db("devices")
			.select("devices.*")
			.where("devices.signIn_id", signInId)
			.then((data) => {
				return data;
			});

		console.log("166 registered devices", registeredDevices);

		return registeredDevices;
	} catch (error) {
		console.error(error);
		throw error;
	}
};

export const registerDevice = async (currentDevice, id) => {
	const {
		credentialID,
		rawID,
		rpID,
		type, 
		transports,
		counter,
		credentialPublicKey,
	} = currentDevice; 

	let userDevices;

	try {
		userDevices = await findRegisteredDevices(id);
		console.log("182", userDevices);

		const existingDevice = userDevices.find((device) =>
			isoUint8Array.areEqual(device.credentialID, currentDevice.credentialID)
		);

		if (userDevices.lenght < 1 || !existingDevice) {
			const newDevice = await db("devices")
				.insert({
					rawID,
					credentialID,
					type,
					transports: JSON.stringify(transports),
					counter,
					credentialPublicKey,
					signIn_id: id,
					rpID,
				})
				.returning("*");
			console.log("198", newDevice);
			return await newDevice;
		}
		console.log("201", await userDevices);
	} catch (error) {
		console.error(error);
		throw error;
	}
	console.log("new list:", userDevices);

	console.log("check the beck", await findRegisteredDevices(id));
};

// Function to hash a password
export const hashPassword = async (plainPassword) => {
	try {
		const saltRounds = 12;
		const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
		return hashedPassword;
	} catch (error) {
		throw error;
	}
};

// Function to verify a password
export const verifyPassword = async (plainPassword, hashedPassword) => {
	console.log("hi 134", plainPassword, hashedPassword);
	try {
		const passwordMatch = await bcrypt.compare(plainPassword, hashedPassword);
		console.log(passwordMatch);
		return passwordMatch;
	} catch (error) {
		throw error;
	}
};
