'use strict';
// Print a bcrypt hash for a password. Usage: node src/hash.js '<password>'
// Prints ONLY the hash (safe to store in .env); never echoes the password.
const bcrypt = require('bcryptjs');
const pw = process.argv[2];
if (!pw) { console.error("usage: node src/hash.js '<password>'"); process.exit(1); }
process.stdout.write(bcrypt.hashSync(pw, 12) + '\n');
