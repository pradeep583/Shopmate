// import bcrypt from "bcrypt";
// import pool from "./routes/db.js";

// async function hashPlainPasswords() {
//   try {
//     // Select users whose password is NOT hashed yet
//     const [users] = await pool.query("SELECT id, username, password FROM users");

//     for (const user of users) {
//       // bcrypt hashed passwords start with $2b$ or $2a$
//       if (!user.password.startsWith("$2")) {
//         const hashedPassword = await bcrypt.hash(user.password, 10);

//         // Determine role: keep existing role unless username is "admin"
//         const role = user.username === "admin" ? "admin" : user.role;

//         await pool.query("UPDATE users SET password = ?, role = ? WHERE id = ?", [
//           hashedPassword,
//           role,
//           user.id,
//         ]);

//         console.log(`User '${user.username}' password hashed, role set to '${role}'`);
//       }
//     }

//     console.log("All plain passwords have been hashed.");
//     process.exit(0);
//   } catch (err) {
//     console.error("Error hashing passwords:", err);
//     process.exit(1);
//   }
// }

// hashPlainPasswords();


import bcrypt from "bcrypt";
import pool from "./routes/db.js";

async function createUsers() {
  try {
    const usersToCreate = [
      { username: "admin2", password: "admin2@123", role: "admin" },
      { username: "superadmin", password: "super@123", role: "admin" },
    ];

    for (const user of usersToCreate) {
      const [existing] = await pool.query(
        "SELECT * FROM users WHERE username = ?",
        [user.username]
      );

      if (existing.length > 0) {
        console.log(`User '${user.username}' already exists.`);
        continue;
      }

      const hashedPassword = await bcrypt.hash(user.password, 10);

      // Insert user with automatic created_at
      await pool.query(
        "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, NOW())",
        [user.username, hashedPassword, user.role]
      );

      console.log(`User '${user.username}' created successfully.`);
    }

    console.log("All user creation tasks completed.");
    process.exit(0);
  } catch (err) {
    console.error("Error creating users:", err);
    process.exit(1);
  }
}

createUsers();

