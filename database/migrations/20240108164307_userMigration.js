export const up = async (knex) => {
	await knex.schema.createTable("signIn", (table) => {
		table.uuid("id").primary().defaultTo(knex.raw("uuid_generate_v4()"));
		table.string("password").notNullable();
		table.string("serviceName");
		table.string("accountType");
		table.boolean("ssoe").defaultTo(false);
		table.boolean("webauthnVerified").defaultTo(false);
	});

	await knex.schema.createTable("devices", (table) => {
		table.uuid("id").primary().defaultTo(knex.raw("uuid_generate_v4()"));
		table.binary("credentialID");
		table.binary("rawID");
		table.string("type").defaultTo("public-key");
		table.string("rpID")
		table.jsonb("transports");
		table.integer("counter");
		table.binary("credentialPublicKey");
		table.uuid("signIn_id").references("id").inTable("signIn");
	});

	await knex.schema.createTable("profile", (table) => {
		table.uuid("id").primary().defaultTo(knex.raw("uuid_generate_v4()"));
		table.string("email").unique().notNullable();
		table.string("firstName");
		table.string("middleName");
		table.string("lastName");
		table.boolean("verified").defaultTo(false);
		table.uuid("signIn_id").references("id").inTable("signIn");
	});

	await knex.schema.createTable("attributes", (table) => {
		table.uuid("id").primary().defaultTo(knex.raw("uuid_generate_v4()"));
		table.uuid("accountUuid").defaultTo(knex.raw("uuid_generate_v4()"));
		table.uuid("profile_id").references("id").inTable("profile");
	});

	await knex.schema.createTable("user", (table) => {
		table.uuid("id").primary().defaultTo(knex.raw("uuid_generate_v4()"));
		table.uuid("attributes_id").references("id").inTable("attributes");
	});
};

export const down = async (knex) => {
	await knex.schema
		.dropTableIfExists("user")
		.dropTableIfExists("attributes")
		.dropTableIfExists("profile")
		.dropTableIfExists("devices")
		.dropTableIfExists("signIn");

	await knex.raw("DROP TYPE IF EXISTS device;");
};
