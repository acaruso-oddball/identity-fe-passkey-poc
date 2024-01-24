/**
 * An example Express server showing off a simple integration of @simplewebauthn/server.
 *
 * The webpages served from ./public use @simplewebauthn/browser.
 */

import https from "https";
import http from "http";
import fs from "fs";
import util from "util";
import express from "express";
import session from "express-session";
import memoryStore from "memorystore";
import dotenv from "dotenv";

declare module "express-session" {
	export interface SessionData {
		user: { [key: string]: any };
	}
}

dotenv.config();
import {
	// Authentication
	generateAuthenticationOptions,
	// Registration
	generateRegistrationOptions,
	verifyAuthenticationResponse,
	verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";
import type {
	GenerateAuthenticationOptionsOpts,
	GenerateRegistrationOptionsOpts,
	VerifiedAuthenticationResponse,
	VerifiedRegistrationResponse,
	VerifyAuthenticationResponseOpts,
	VerifyRegistrationResponseOpts,
} from "@simplewebauthn/server";

import type {
	AuthenticationResponseJSON,
	AuthenticatorDevice,
	RegistrationResponseJSON,
	Base64URLString,
	AuthenticatorAttachment,
} from "@simplewebauthn/typescript-types";

import base64url from "base64url";

import { LoggedInUser } from "./example-server";
import { base64 } from "rfc4648";
import {
	hashPassword,
	uint8ArrayToBase64Url,
	uint8ArrayToString,
	verifyPassword,
	createUser,
	findByEmail,
	verifyAccount,
} from "./server-utilsts";
// import { encode } from "punycode";
// import { Console } from "console";
// import * as Users from "./api/models/user_model.js";
// import { isBase64 } from "@simplewebauthn/server/esm/helpers/iso/isoBase64URL";

const app = express();
const MemoryStore = memoryStore(session);

const { ENABLE_CONFORMANCE, ENABLE_HTTPS, RP_ID = "localhost" } = process.env;

app.use(express.json());
app.use(
	session({
		secret: "secret123",
		saveUninitialized: true,
		resave: false,
		cookie: {
			maxAge: 86400000,
			httpOnly: true, // Ensure to not expose session cookies to clientside scripts
		},
		store: new MemoryStore({
			checkPeriod: 86_400_000, // prune expired entries every 24h
		}),
	})
);

/**
 * If the words "metadata statements" mean anything to you, you'll want to enable this route. It
 * contains an example of a more complex deployment of SimpleWebAuthn with support enabled for the
 * FIDO Metadata Service. This enables greater control over the types of authenticators that can
 * interact with the Rely Party (a.k.a. "RP", a.k.a. "this server").
 */
if (ENABLE_CONFORMANCE === "true") {
	import("./fido-conformance").then(
		({ fidoRouteSuffix, fidoConformanceRouter }) => {
			app.use(fidoRouteSuffix, fidoConformanceRouter);
		}
	);
}

/**
 * RP ID represents the "scope" of websites on which a authenticator should be usable. The Origin
 * represents the expected URL from which registration or authentication occurs.
 */
export const rpID = RP_ID;
// This value is set at the bottom of page as part of server initialization (the empty string is
// to appease TypeScript until we determine the expected origin based on whether or not HTTPS
// support is enabled)
export let expectedOrigin = "http://localhost:3000/";

/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs registration or authentication. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the authenticator.
 *
 * Here, the example server assumes the following user has completed login:
 */
const loggedInUserId = "internalUserId";

let inMemoryUserDeviceDB: { [loggedInUserId: string]: LoggedInUser } = {
	[loggedInUserId]: {
		id: loggedInUserId,
		username: `user@${rpID}`,
		devices: [],
	},
};

let user = inMemoryUserDeviceDB[loggedInUserId];

app.get("/api", (req, res) => {
	res.json({ message: "Hello from server!" });
});
/**
 * Registration (a.k.a. "Registration")
 */
app.post("/generate-registration-options", async (req, res) => {
	// const {
	// 	/**
	// 	 * The username can be a human-readable name, email, etc... as it is intended only for display.
	// 	 */
	// 	username,
	// 	devices,
	// } = user;
	const { user, attestation, authenticatorSelection } = req.body;

	const { id, username, devices } = user;
	const opts: GenerateRegistrationOptionsOpts = {
		rpName: "VA-Webauthn-Example",
		rpID,
		userID: id,
		userName: username,
		timeout: 60000,
		attestationType: attestation,
		/**
		 * Passing in a user's list of already-registered authenticator IDs here prevents users from
		 * registering the same device multiple times. The authenticator will simply throw an error in
		 * the browser if it's asked to perform registration when one of these ID's already resides
		 * on it.
		 */
		excludeCredentials: devices.map((dev: { id: any; transports: any }) => ({
			id: dev.id,
			type: "public-key",
			transports: dev.transports,
		})),
		authenticatorSelection,
		/**
		 * Support the two most common algorithms: ES256, and RS256
		 */
		supportedAlgorithmIDs: [-7, -257],
	};
	const options = await generateRegistrationOptions(opts);

	/**
	 * The server needs to temporarily remember this value for verification, so don't lose it until
	 * after you verify an authenticator response.
	 */
	req.session.currentChallenge = options.challenge;

	res.send(options);
});

// Step 1: Decode Base64URL
function decodeBase64URL(encodedStr: string): Buffer {
	// Replace '-' with '+' and '_' with '/' to make it standard Base64
	const standardBase64 = encodedStr.replace(/-/g, "+").replace(/_/g, "/");

	// Add padding if necessary
	const padding = standardBase64.length % 4;
	const paddedBase64 = padding
		? standardBase64 + "=".repeat(4 - padding)
		: standardBase64;

	// Decode Base64URL
	const decodedStr = base64url.toBuffer(paddedBase64);

	return decodedStr;
}

// Step 2: Encode to Base64URL
function encodeBase64URL(str: string): string {
	// Encode to Base64
	const base64 = Buffer.from(str).toString("base64");

	// Convert standard Base64 to Base64URL
	const base64URL = base64
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");

	return base64URL;
}

app.post("/register", async (req, res) => {
	let user = req.body;
	const hash = hashPassword(user.password);
	user.password = hash;

	try {
		// const data = await Users.createUser(user);
		const data = await createUser(user);
		res.status(201).json({ data, message: `Welcome ${data.first_name}!` });
	} catch (err) {
		console.log(err);
		res.status(500).json({ err });
	}
});

app.post("/login", async (req, res) => {
	// Check if the credentials are valid (in a real application, you would use a database for this)
	let user = req.body;
	// const hash = hashPassword(user.password);

	// user.password = hash;

	// const authenticatedUser = await Users.findByEmail(user.email);
	const authenticatedUser = await findByEmail(user.email);

	const loggedInUser = verifyPassword(
		user.password,
		authenticatedUser.password
	);

	console.log(loggedInUser, "how260");
	if (authenticatedUser) {
		// Set user data in the session including an 'authenticated' flag
		req.session.user = {
			...authenticatedUser,
			authenticated: true,
		};
		const userSession = req.session.user;
		console.log(userSession);

		res.redirect("/");
	} else {
		res.send('Invalid credentials. <a href="/login">Try again</a>');
	}
});

app.post("/verify-account", async (req, res) => {
	const { email } = req.body;

	// Check if the credentials are valid (in a real application, you would use a database for this)
	try {
		// const data = await Users.verifyAccount(email);
		const data = await verifyAccount(email);
		res.status(201).json({ data, message: `Account Verified!` });
	} catch (err) {
		console.log(err);
		res.status(500).json({ err });
	}
});

app.post("/verify-registration", async (req, res) => {
	const body = req.body;
	const expectedChallenge = req.session.currentChallenge;
	const recievedChallenge = body.response.clientDataJSON;

	const base64urlEncodedString = recievedChallenge;

	const decodedData = decodeBase64URL(base64urlEncodedString);
	const data = JSON.parse(decodedData.toString());
	const { challenge, origin, crossOrigin } = data;
	let responseJSON = {
		challenge: base64url.decode(challenge),
		origin,
		crossOrigin,
		type: data.type,
	};

	const {
		method,
		id,
		rawId,
		type,
		clientExtensionResults,
		authenticatorAttachment,
		transports,
	} = body;

	const { attestationObject } = body.response;

	let formattedOptionResponse = {
		method,
		id,
		rawId,
		response: {
			clientDataJSON: encodeBase64URL(JSON.stringify(responseJSON)),
			attestationObject,
		},
		type,
		clientExtensionResults,
		authenticatorAttachment,
		transports,
	};

	let verification: VerifiedRegistrationResponse;
	try {
		const opts: VerifyRegistrationResponseOpts = {
			response: formattedOptionResponse,
			expectedChallenge: `${expectedChallenge}`,
			expectedOrigin: "http://localhost:3000",
			expectedRPID: rpID,
			requireUserVerification: true,
		};
		verification = await verifyRegistrationResponse(opts);
	} catch (error) {
		const _error = error as Error;
		console.error(_error);
		return res.status(400).send({ error: _error.message });
	}

	const { verified, registrationInfo } = verification;

	if (verified && registrationInfo) {
		const { credentialPublicKey, credentialID, counter } = registrationInfo;

		const existingDevice = user.devices.find((device) =>
			isoUint8Array.areEqual(device.credentialID, credentialID)
		);
		if (!existingDevice) {
			/**
			 * Add the returned device to the user's list of devices
			 */
			const newDevice: AuthenticatorDevice = {
				credentialPublicKey,
				credentialID,
				counter,
				transports: body.response.transports,
			};
			user.devices.push(newDevice);
			console.log(user.devices);
		}
	}

	req.session.currentChallenge = undefined;

	res.send({ verified, registrationInfo });
});

/**
 * Login (a.k.a. "Authentication")
 */
app.post("/generate-authentication-options", async (req, res) => {
	const credId = req.query.credId || localStorage.getItem("credentialID");
	const {
		attestation,
		userVerification,
		authenticatorSelection,
		requireResidentKey,
	} = req.body;

	// let generateServerGetAssertion = (authenticators) => {
	// 	let allowCredentials = [];
	// 	for (let authr of authenticators) {
	// 		allowCredentials.push({
	// 	 		type: "public-key",
	// 			id: authr.credID,
	// 			transports: ["usb", "nfc", "ble"],
	// 		});
	// 	}
	// 	return {
	// 		challenge: randomBase64URLBuffer(32),
	// 		allowCredentials: allowCredentials,
	// 	};
	// };
	// const opts = JSON.parse(req.body);
	// let { credentialID } = user.devices[0];
	// var string = new TextDecoder().decode(credentialID);
	console.log(user.devices);

	// console.log( attestation, authenticatorSelection);

	// You need to know the user by this point

	// const authenticationOpts: GenerateAuthenticationOptionsOpts = {
	// 	timeout: 60000,
	// 	allowCredentials: user.devices.map((dev) => ({
	// 		id: dev.credentialID,
	// 		type: "public-key",
	// 		transports: dev.transports,
	// 	})),
	// 	userVerification: "required",
	// 	rpID,
	// };
	console.log("338", user);
	const authenticationOpts: GenerateAuthenticationOptionsOpts = {
		timeout: 60000,
		allowCredentials: user.devices.map((dev) => {
			console.log("342", dev);
			console.log(credId, dev.credentialID);
			return {
				id: dev.credentialID,
				type: "public-key",
				// transports: dev.transports,
			};
		}),
		userVerification,
		rpID,
	};

	console.log("351", authenticationOpts);

	const options = await generateAuthenticationOptions(authenticationOpts);

	console.log("355", options);

	// /**
	//  * The server needs to temporarily remember this value for verification, so don't lose it until
	//  * after you verify an authenticator response.
	//  */
	// req.session.currentChallenge = options.challenge;

	res.send(options);
});

app.post("/verify-authentication", async (req, res) => {
	const body: AuthenticationResponseJSON = req.body;

	const expectedChallenge = req.session.currentChallenge;
	console.log("372 hello there");

	let dbAuthenticator;
	const bodyCredIDBuffer = isoBase64URL.toBuffer(body.rawId);
	// "Query the DB" here for an authenticator matching `credentialID`
	for (const dev of user.devices) {
		if (isoUint8Array.areEqual(dev.credentialID, bodyCredIDBuffer)) {
			dbAuthenticator = dev;
			break;
		}
	}
	console.log("hello there");
	if (!dbAuthenticator) {
		return res.status(400).send({
			error: "Authenticator is not registered with this site",
		});
	}

	let verification: VerifiedAuthenticationResponse;
	try {
		const opts: VerifyAuthenticationResponseOpts = {
			response: body,
			expectedChallenge: `${expectedChallenge}`,
			expectedOrigin,
			expectedRPID: rpID,
			authenticator: dbAuthenticator,
			requireUserVerification: true,
		};
		verification = await verifyAuthenticationResponse(opts);
	} catch (error) {
		const _error = error as Error;
		console.error(_error);
		return res.status(400).send({ error: _error.message });
	}

	const { verified, authenticationInfo } = verification;

	if (verified) {
		// Update the authenticator's counter in the DB to the newest count in the authentication
		dbAuthenticator.counter = authenticationInfo.newCounter;
	}

	req.session.currentChallenge = undefined;

	res.send({ verified });
});

if (ENABLE_HTTPS) {
	const host = "0.0.0.0";
	const port = 443;
	expectedOrigin = `https://${rpID}`;

	https
		.createServer(
			{
				/**
				 * See the README on how to generate this SSL cert and key pair using mkcert
				 */
				key: fs.readFileSync(`./${rpID}.key`),
				cert: fs.readFileSync(`./${rpID}.crt`),
			},
			app
		)
		.listen(port, host, () => {
			console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
		});
} else {
	const host = "127.0.0.1";
	const port = 8000;
	expectedOrigin = `http://localhost:${port}`;

	http.createServer(app).listen(port, host, () => {
		console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
	});
}
