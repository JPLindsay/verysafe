const express = require("express");
const { MongoClient } = require("mongodb");
const prompt = require("prompt-sync");
const readline = require("readline");
const fs = require("fs");
const { Client } = require("pg");
const { exec } = require("child_process");

const app = express();
const uri = prompt("Enter connection string:");
const client = new MongoClient(uri); // Connection string not sanitized
const db = client.testDb;
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

app.get("/search", (req, res) => {
  const results = db.coll.find(req.query.product);
  if (results.length === 0) {
    return res.send(`<p>No results found for "${req.query.product}"</p>`);
  }
  return res.send("<p>Something found</p>");
});

app.get("/delete", (req, res) => {
  db.coll.deleteOne({ _id: req.query.item });
  return res.send("Deleted!");
});

app.get("/eval-delete", (req, res) => {
  db.coll.deleteOne(eval(req.query.item));
  return res.send("Deleted!");
});

// Hardcoded secret
const secret = "ASIROTRSENTNnetnternisienrt78";

// Secret in connection string
const newClient = MongoClient("mongodb://myuser:AIESNTEIRSNenteternEE@example.com:27017");

// Unsafe eval() using external library
eval(prompt("Give me some JS to run! It's safe, I promise!"));

// Unsafe eval() using internal library
rl.question("What JS should I run?", input => {
  eval(input);
});

// Path traversal
rl.question("Give me a file. I'll see if it exists.", filename => {
  if (fs.existsSync(filename)) {
    console.log("It exists. Deleting");
    fs.unlinkSync(filename);
  } else {
    console.log("It does not exist");
  }
});

// SQL injection
pgClient = new Client();
pgClient.connect();

rl.question("What SQL should I execute?", sql => {
  pgClient.query(sql, null, (err, res) => {
    console.log(err ? err.stack : res.rows[0].message);
    pgClient.end();
  });
});

// Local file inclusion
rl.question("What should I include?", toInclude => {
  thing = require(toInclude);
});

// Code injection from command line arguments
const arg = process.argv.slice(2);
eval(arg[0]);

// Command injection from command line arguments
exec(arg[0], (error, stdout, stderr) => {
  console.log("This really should cause the tool to complain");
});

// Unsanitized connection string using CLI arguments
pgClient = new Client(arg[0]);