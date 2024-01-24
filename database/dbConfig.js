import knex from "knex";

import config from "../knexfile.js";

const env = process.env.NODE_ENV || "development";

const configOptions = config[env];

const db = knex(configOptions);

export default db;

// // dbConfig.ts
// import * as Knex from 'knex';
// import * as config from '../knexfile';

// const env: string = process.env.NODE_ENV || 'development';

// const configOptions: Knex.Config = config[env];

// const db: Knex = Knex(configOptions);

// export default db;
