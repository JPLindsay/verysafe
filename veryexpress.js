// SAST test using a very insecure Express web/API server.

const express = require("express");
const { MongoClient } = require("mongodb");
const { Client } = require("pg");
const { exec } = require("child_process");
const fs = require("fs");

const app = express();
const client = new MongoClient("mongodb://localhost");
const db = client.fake;

app.get("/xss", (req, res) => {
  // XSS vulnerability
  const stuff = req.query.stuff;
  res.send(stuff);
});

app.get("/stored-xss/:ident", (req, res) => {
  // Stored XSS vulnerability
  const doc = db.collection.findOne({ _id: req.params.ident });
  res.send(doc.content);
});

app.get("/ReDoS", (req, res) => {
  // Regular expression denial of service
  const pattern = req.query.pattern;
  const search = req.query.search;
  res.json({ matches: search.match(pattern) });
});

app.get("/unsafe-exec", (req, res) => {
  // Command injection
  const command = req.query.command;
  exec(command, (error, stdout, stderr) => {
    res.send(stdout);
  });
});

app.get("/os-access-violation-and-path-traversal", (req, res) => {
  const filename = req.query.filename;
  if (fs.existsSync(filename)) {
    fs.unlinkSnyk(filename);
    return res.json({ deleted: true });
  }
  return res.json({ deleted: false });
});

app.get("/sql-injection", (req, res) => {
  const client = new Client("postgresql://fake:F4k3p4SsW0rD@example.com/fakebase");
  const sql = req.query.sql;
  client.query(sql, null, (err, result) => {
    res.json({ status: "ok" });
  });
});

app.post("/nosql-unsafe-find", (req, res) => {
  query = req.body;
  res.json({ found: db.collection.findOne(query) });
});

app.get("/unsafe-import", (req, res) => {
  const module = req.query.module;
  const command = req.query.command;
  require(module);
  res.json({ output: eval(command) });
});

app.get("/delete/:ident", (req, res) => {
  db.collection.deleteOne({ _id: req.params.ident });
  res.json({ status: "ok" });
});

app.post("/nosql-injection", (req, res) => {
  const command = req.body;
  res.json(db.runCommand(command));
})

// Run
const port = 5000;
app.listen(port, () => {
  console.log(`Running on port http://127.0.0.1:${port}/`);
});