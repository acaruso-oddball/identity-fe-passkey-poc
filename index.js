import https from "https";
import http from "http";
import fs from "fs";
import util from "util";
import express from "express";
import session from "express-session";
import memoryStore from "memorystore";
import dotenv from "dotenv";

// declare module "express-session" {
// 	export interface SessionData {
// 		user: { [key: string]: any };
// 	}
// }

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


import base64url from "base64url";
import {
	hashPassword,
	registerDevice,
	verifyPassword,
	createUser,
	findByEmail,
	verifyAccount,
	findRegisteredDevices,
} from "./server-utils.js";

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
const rpID = RP_ID;
// This value is set at the bottom of page as part of server initialization (the empty string is
// to appease TypeScript until we determine the expected origin based on whether or not HTTPS
// support is enabled)
let expectedOrigin = "http://localhost:3000/";
export { rpID, expectedOrigin };
/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs registration or authentication. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the authenticator.
 *
 * Here, the example server assumes the following user has completed login:
 */
const loggedInUserId = "internalUserId";

// let inMemoryUserDeviceDB: { [loggedInUserId: string]: LoggedInUser } = {
// 	[loggedInUserId]: {
// 		id: loggedInUserId,
// 		username: `user@${rpID}`,
// 		devices: [],
// 	},
// };

// let user = inMemoryUserDeviceDB[loggedInUserId];

app.get("/api", (req, res) => {
	res.json({ message: "Hello from server!" });
});

/** Regular Account Creation */

app.post("/register", async (req, res) => {
	let user = req.body;
	const hash = await hashPassword(user.password);
	user.password = hash;
	console.log("247", user);
	try {
		// const data = await Users.createUser(user);
		const data = await createUser(user);

		console.log("252", data);
		res.status(201).json({ data, message: `Welcome ${data.firstName}!` });
	} catch (err) {
		console.log(err);
		res.status(500).json({ err });
	}
});

app.post("/login", async (req, res) => {
	// Check if the credentials are valid (in a real application, you would use a database for this)
	let user = req.body;

	const authenticatedUser = await findByEmail(user.email);

	console.log("267", authenticatedUser);

	const loggedInUser = await verifyPassword(
		user.password,
		authenticatedUser.password
	);

	console.log("274", loggedInUser);

	if (loggedInUser === true) {
		req.session.user = {
			...authenticatedUser,
			authenticated: true,
		};

		const userSession = req.session.user;

		console.log(userSession);

		res.status(201).json({
			authenticatedUser,
			message: `Welcome BCK ${authenticatedUser.firstName}!`,
		});
	} else {
		res.send('Invalid credentials. <a href="/login">Try again</a>');
	}
});

app.put("/verify-account", async (req, res) => {
	const { email } = req.body;
	try {
		const data = await verifyAccount(email);

		console.log("301", data);
		res.status(201).json({ data, message: `Account Verified!` });
	} catch (err) {
		console.log(err);
		res.status(500).json({ err });
	}
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

	const { id, name } = user;

	const devices = await findRegisteredDevices(id);
	console.log("250", devices);

	const opts = {
		rpName: "VA-Webauthn-Example",
		rpID,
		userID: id,
		userName: name,
		timeout: 60000,
		attestationType: attestation,
		/**
		 * Passing in a user's list of already-registered authenticator IDs here prevents users from
		 * registering the same device multiple times. The authenticator will simply throw an error in
		 * the browser if it's asked to perform registration when one of these ID's already resides
		 * on it.
		 */
		excludeCredentials: devices?.map((dev) => ({
			id: dev.credentialID,
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

const decodeBase64URL = (base64url) => {
	const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
	const buffer = Buffer.from(base64, "base64");
	return new Uint8Array(buffer).buffer;
};

// Step 2: Encode to Base64URL
function encodeBase64URL(str) {
	// Encode to Base64
	const base64 = Buffer.from(str).toString("base64");

	// Convert standard Base64 to Base64URL
	const base64URL = base64
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");

	return base64URL;
}

app.post("/verify-registration", async (req, res) => {
	const { body } = req;
	const { rawId } = req.body;
	const { clientDataJSON } = body.response;
	const expectedChallenge = req.session.currentChallenge;
	console.log(rawId);
	const encodedRawID = rawId;

	const decodedRawId = decodeBase64URL(encodedRawID);
	const rawID = new Uint8Array(decodedRawId).buffer;
	const rawIdString = Buffer.from(rawID).toString("base64");

	console.log("Decoded Raw ID:", rawIdString);

	const encodedClientDataJSON = body.response.clientDataJSON;
	const decodedClientData = decodeBase64URL(encodedClientDataJSON);
	const clientData = JSON.parse(
		Buffer.from(decodedClientData).toString("utf-8")
	);

	console.log("Decoded Client Data:", clientData);
	const { challenge, origin } = clientData;

	let responseJSON = {
		challenge: base64url.decode(challenge),
		origin,
		crossOrigin: true,
		type: clientData.type,
	};

	console.log("333", body);

	const {
		method,
		id,
		// rawId,
		type,
		clientExtensionResults,
		authenticatorAttachment,
		transports,
	} = body;

	console.log(
		"345 index",
		method,
		id,
		rawId,
		type,
		clientExtensionResults,
		authenticatorAttachment,
		transports
	);

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

	let verification;
	try {
		const opts = {
			response: formattedOptionResponse,
			expectedChallenge: `${expectedChallenge}`,
			expectedOrigin: "http://localhost:3000",
			expectedRPID: rpID,
			requireUserVerification: true,
		};
		verification = await verifyRegistrationResponse(opts);
	} catch (error) {
		const _error = error;
		console.error(_error);
		return res.status(400).send({ error: _error.message });
	}
	console.log("418", verification);
	const { verified, registrationInfo } = verification;

	req.session.currentChallenge = undefined;

	res.send({ verified, registrationInfo, transports });
});

app.post("/device-registry/:id", async (req, res) => {
	const currentDevice = req.body;
	console.log("383", currentDevice);
	const { id } = req.params;
	try {
		const registeredDevice = await registerDevice(currentDevice, id);
		res
			.status(201)
			.json({ registeredDevice, message: `Device Registry Updated.` });
	} catch (err) {
		console.log(err);
		res.status(500).json({ err });
	}
});

/**
 * Login (a.k.a. "Authentication")
 */
app.post("/generate-authentication-options", async (req, res) => {
	const { email } = req.body;
	const { signIn_id } = await findByEmail(email);
	console.log("user with this signin id found:", signIn_id);

	const devices = await findRegisteredDevices(signIn_id);
	console.log("417", devices);

	const opts = {
		timeout: 60000,
		allowCredentials: devices?.map(({ rawID, type, transports }) => ({
			id: rawID,
			type,
			transports,
		})),
		userVerification: "required",
		rpID,
	};
	console.log("430", opts);

	const options = await generateAuthenticationOptions(opts);
	console.log("options 433", options);
	req.session.currentChallenge = options.challenge;

	res.send(options);
});

app.post("/verify-authentication", async (req, res) => {
	const body = req.body;

	const expectedChallenge = req.session.currentChallenge;
	console.log("443 hello there");

	let dbAuthenticator;
	const bodyCredIDBuffer = isoBase64URL.toBuffer(body.rawID);
	// "Query the DB" here for an authenticator matching `credentialID`
	for (const dev of user.devices) {
		if (isoUint8Array.areEqual(dev.rawID, bodyCredIDBuffer)) {
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

	let verification;
	try {
		const opts = {
			response: body,
			expectedChallenge: `${expectedChallenge}`,
			expectedOrigin,
			expectedRPID: rpID,
			authenticator: dbAuthenticator,
			requireUserVerification: true,
		};
		verification = await verifyAuthenticationResponse(opts);
	} catch (error) {
		const _error = error;
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
