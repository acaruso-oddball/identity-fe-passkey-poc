"use strict";
/**
 * An example Express server showing off a simple integration of @simplewebauthn/server.
 *
 * The webpages served from ./public use @simplewebauthn/browser.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.expectedOrigin = exports.rpID = void 0;
const https_1 = __importDefault(require("https"));
const http_1 = __importDefault(require("http"));
const fs_1 = __importDefault(require("fs"));
const express_1 = __importDefault(require("express"));
const express_session_1 = __importDefault(require("express-session"));
const memorystore_1 = __importDefault(require("memorystore"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const server_1 = require("@simplewebauthn/server");
// import { isBase64 } from "@simplewebauthn/server/esm/helpers/iso/isoBase64URL";
// import { isBase64url } from "@simplewebauthn/server/esm/helpers/iso/isoBase64URL";
const app = (0, express_1.default)();
const MemoryStore = (0, memorystore_1.default)(express_session_1.default);
const { ENABLE_CONFORMANCE, ENABLE_HTTPS, RP_ID = "localhost" } = process.env;
app.use(express_1.default.json());
app.use((0, express_session_1.default)({
    secret: "secret123",
    saveUninitialized: true,
    resave: false,
    cookie: {
        maxAge: 86400000,
        httpOnly: true, // Ensure to not expose session cookies to clientside scripts
    },
    store: new MemoryStore({
        checkPeriod: 86400000, // prune expired entries every 24h
    }),
}));
/**
 * If the words "metadata statements" mean anything to you, you'll want to enable this route. It
 * contains an example of a more complex deployment of SimpleWebAuthn with support enabled for the
 * FIDO Metadata Service. This enables greater control over the types of authenticators that can
 * interact with the Rely Party (a.k.a. "RP", a.k.a. "this server").
 */
if (ENABLE_CONFORMANCE === "true") {
    Promise.resolve().then(() => __importStar(require("./fido-conformance"))).then(({ fidoRouteSuffix, fidoConformanceRouter }) => {
        app.use(fidoRouteSuffix, fidoConformanceRouter);
    });
}
/**
 * RP ID represents the "scope" of websites on which a authenticator should be usable. The Origin
 * represents the expected URL from which registration or authentication occurs.
 */
exports.rpID = RP_ID;
// This value is set at the bottom of page as part of server initialization (the empty string is
// to appease TypeScript until we determine the expected origin based on whether or not HTTPS
// support is enabled)
exports.expectedOrigin = "";
/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs registration or authentication. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the authenticator.
 *
 * Here, the example server assumes the following user has completed login:
 */
const loggedInUserId = "internalUserId";
const inMemoryUserDeviceDB = {
    [loggedInUserId]: {
        id: loggedInUserId,
        username: `user@${exports.rpID}`,
        devices: [],
    },
};
app.get("/api", (req, res) => {
    res.json({ message: "Hello from server!" });
});
/**
 * Registration (a.k.a. "Registration")
 */
app.get("/generate-registration-options", async (req, res) => {
    const user = inMemoryUserDeviceDB[loggedInUserId];
    const { 
    /**
     * The username can be a human-readable name, email, etc... as it is intended only for display.
     */
    username, devices, } = user;
    const opts = {
        rpName: "VA-Webauthn-Example",
        rpID: exports.rpID,
        userID: loggedInUserId,
        userName: username,
        timeout: 60000,
        attestationType: "none",
        /**
         * Passing in a user's list of already-registered authenticator IDs here prevents users from
         * registering the same device multiple times. The authenticator will simply throw an error in
         * the browser if it's asked to perform registration when one of these ID's already resides
         * on it.
         */
        excludeCredentials: devices.map((dev) => ({
            id: dev.credentialID,
            type: "public-key",
            transports: dev.transports,
        })),
        authenticatorSelection: {
            residentKey: "discouraged",
        },
        /**
         * Support the two most common algorithms: ES256, and RS256
         */
        supportedAlgorithmIDs: [-7, -257],
    };
    const options = await (0, server_1.generateRegistrationOptions)(opts);
    /**
     * The server needs to temporarily remember this value for verification, so don't lose it until
     * after you verify an authenticator response.
     */
    req.session.currentChallenge = options.challenge;
    res.send(options);
});
app.post("/verify-registration", async (req, res) => {
    const { credential } = req.body;
    // console.log(credential);
    // const { id, rawId, type, clientExtensionResults } = credential;
    // const user = inMemoryUserDeviceDB[loggedInUserId];
    // const expectedChallenge = req.session.currentChallenge;
    // let verification;
    // const { id, rawId, type, clientExtensionResults } = JSON.parse(credential);
    // const utf8Decoder = new TextDecoder("utf-8");
    // const decodedClientData = utf8Decoder.decode(
    // 	credential.response.clientDataJSON
    // );
    // const clientDataObj = JSON.parse(decodedClientData);
    // console.log(clientDataObj);
    // let { id, rawId, type, clientExtensionResults } = JSON.parse(credential);
    // console.log(id, rawId, type, clientExtensionResults);
    // // id = base64url(id);
    console.log(credential);
    try {
        // const verifyOptions = {
        // 	response: {
        // 		id: base64url(id),
        // 		rawId,
        // 		type,
        // 		response: credential.response,
        // 	},
        // 	expectedChallenge: `${expectedChallenge}`,
        // 	expectedOrigin,
        // 	expectedRPID: rpID,
        // 	requireUserVerification: true,
        // };
        // console.log("hoio", base64url(id));
        // const id64 = base64url.encode(id);
        // // console.log("hi", id, "ho", id64, typeof id64);
        // const base64urlEncode = (data: string) =>
        // 	btoa(data).replace("+", "-").replace("/", "_").replace(/=+$/, "");
        // console.log(typeof id64);
        // verification = await verifyRegistrationResponse({
        // 	response: {
        // 		id,
        // 		rawId,
        // 		type,
        // 		response: credential.response,
        // 		clientExtensionResults,
        // 	},
        // 	expectedChallenge: `${expectedChallenge}`,
        // 	expectedOrigin,
        // 	expectedRPID: rpID,
        // 	requireUserVerification: true,
        // });
        // console.log("there", verification);
    }
    catch (error) {
        const _error = error;
        "here";
        return res.status(400).send({ error: _error.message });
    }
    // console.log("here", verification);
    // const { verified, registrationInfo } = verification;
    // if (verified && registrationInfo) {
    // 	const { credentialPublicKey, credentialID, counter } = registrationInfo;
    // 	const existingDevice = user.devices.find((device) =>
    // 		isoUint8Array.areEqual(device.credentialID, credentialID)
    // 	);
    // 	if (!existingDevice) {
    // 		/**
    // 		 * Add the returned device to the user's list of devices
    // 		 */
    // 		const newDevice: AuthenticatorDevice = {
    // 			credentialPublicKey,
    // 			credentialID,
    // 			counter,
    // 			transports: body.response.transports,
    // 		};
    // 		user.devices.push(newDevice);
    // 	}
    // }
    // req.session.currentChallenge = undefined;
    // res.send({ verified });
});
// /**
//  * Login (a.k.a. "Authentication")
//  */
// app.get("/generate-authentication-options", async (req, res) => {
// 	// You need to know the user by this point
// 	const user = inMemoryUserDeviceDB[loggedInUserId];
// 	const opts: GenerateAuthenticationOptionsOpts = {
// 		timeout: 60000,
// 		allowCredentials: user.devices.map((dev) => ({
// 			id: dev.credentialID,
// 			type: "public-key",
// 			transports: dev.transports,
// 		})),
// 		userVerification: "required",
// 		rpID,
// 	};
// 	const options = await generateAuthenticationOptions(opts);
// 	/**
// 	 * The server needs to temporarily remember this value for verification, so don't lose it until
// 	 * after you verify an authenticator response.
// 	 */
// 	req.session.currentChallenge = options.challenge;
// 	res.send(options);
// });
// app.post("/verify-authentication", async (req, res) => {
// 	const body: AuthenticationResponseJSON = req.body;
// 	const user = inMemoryUserDeviceDB[loggedInUserId];
// 	const expectedChallenge = req.session.currentChallenge;
// 	let dbAuthenticator;
// 	const bodyCredIDBuffer = isoBase64URL.toBuffer(body.rawId);
// 	// "Query the DB" here for an authenticator matching `credentialID`
// 	for (const dev of user.devices) {
// 		if (isoUint8Array.areEqual(dev.credentialID, bodyCredIDBuffer)) {
// 			dbAuthenticator = dev;
// 			break;
// 		}
// 	}
// 	if (!dbAuthenticator) {
// 		return res.status(400).send({
// 			error: "Authenticator is not registered with this site",
// 		});
// 	}
// 	let verification: VerifiedAuthenticationResponse;
// 	try {
// 		const opts: VerifyAuthenticationResponseOpts = {
// 			response: body,
// 			expectedChallenge: `${expectedChallenge}`,
// 			expectedOrigin,
// 			expectedRPID: rpID,
// 			authenticator: dbAuthenticator,
// 			requireUserVerification: true,
// 		};
// 		verification = await verifyAuthenticationResponse(opts);
// 	} catch (error) {
// 		const _error = error as Error;
// 		console.error(_error);
// 		return res.status(400).send({ error: _error.message });
// 	}
// 	const { verified, authenticationInfo } = verification;
// 	if (verified) {
// 		// Update the authenticator's counter in the DB to the newest count in the authentication
// 		dbAuthenticator.counter = authenticationInfo.newCounter;
// 	}
// 	req.session.currentChallenge = undefined;
// 	res.send({ verified });
// });
if (ENABLE_HTTPS) {
    const host = "0.0.0.0";
    const port = 443;
    exports.expectedOrigin = `https://${exports.rpID}`;
    https_1.default
        .createServer({
        /**
         * See the README on how to generate this SSL cert and key pair using mkcert
         */
        key: fs_1.default.readFileSync(`./${exports.rpID}.key`),
        cert: fs_1.default.readFileSync(`./${exports.rpID}.crt`),
    }, app)
        .listen(port, host, () => {
        console.log(`🚀 Server ready at ${exports.expectedOrigin} (${host}:${port})`);
    });
}
else {
    const host = "127.0.0.1";
    const port = 8000;
    exports.expectedOrigin = `http://localhost:${port}`;
    http_1.default.createServer(app).listen(port, host, () => {
        console.log(`🚀 Server ready at ${exports.expectedOrigin} (${host}:${port})`);
    });
}
//# sourceMappingURL=index.js.map