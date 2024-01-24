import * as env from "dotenv";
env.config();

const config = {
	development: {
		client: "pg",
		connection: process.env.DB_URL,
		pool: {
			min: 2,
			max: 15,
		},
		migrations: {
			directory: "./database/migrations",
		},
		seeds: {
			directory: "./database/seeds",
		},
	},
	testing: {
		client: "cypress",
		connection: {
			filename: "./cypress/server_test.spec.js",
		},
		migrations: {
			directory: "./database/migrations",
		},
		seeds: {
			directory: "./database/seeds",
		},
	},
	production: {
		client: "pg",
		connection: process.env.DB_URL,
		pool: {
			min: 2,
			max: 15,
		},
		migrations: {
			directory: "./database/migrations",
		},
		seeds: {
			directory: "./database/seeds",
		},
	},
};
export default config;
