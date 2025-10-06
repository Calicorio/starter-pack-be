import mysql from "mysql2";
import "dotenv/config";

const pool = mysql.createPool({
  host: process.env.DB_HOST!,
  user: process.env.DB_USER!,
  password: process.env.DB_PASSWORD!,
  database: process.env.DB_NAME!
});

pool.getConnection((err, connection) => {
  if (err) console.error("Error connecting to DB:", err);
  else {
    console.log("Connected to MySQL DB!");
    connection.release();
  }
});

export default pool;
