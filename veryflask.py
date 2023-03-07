"""SAST test using a somewhat more realistic application."""

import importlib
import os
import re
from urllib.parse import unquote_plus as unescape

import psycopg2
from flask import Flask, abort, request
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient()
db = client.fake


@app.route("/ReDoS", methods=["GET", "POST"])
def redos():
  """Has a ReDoS vulnerability."""
  if request.method == "GET":
    pattern = request.args.get("pattern", "")
    search = request.args.get("search", "")
  elif request.method == "POST":
    pattern = request.form["pattern"]
    search = request.form["search"]
  else:
    abort(404)

  matches = re.findall(pattern, search)
  return str(matches)


# NOT CAUGHT
@app.route("/delete/<ident>")
def delete_by_id(ident):
  """No input sanitization is done, so the user can delete whatever they want."""
  db.collection.delete_one({"_id": ident})


# DOES NOT FIND SQL INJECTION
@app.route("/unsafe-find", methods=["POST"])
def unsafe_find():
  """Find and return a document via unsafe eval()."""
  match_doc = eval(request.form["doc"])
  return str(db.collection.find_one(match_doc))


# DOES NOT CATCH UNSAFE IMPORT
@app.route("/unsafe-eval", methods=["GET"])
def unsafe_eval():
  """Also has local file inclusion."""
  if include := request.args.get("include"):
    importlib.import_module(include)

  command = request.args.get("command", "")
  return str(eval(command))


@app.route("/unsafe-exec", methods=["GET"])
def unsafe_exec():
  """Could also trigger path traversal."""
  cmd = unescape(request.args.get("exec", "ls"))
  out = os.popen(cmd)
  return out.read()


# PATH TRAVERSAL NOT CAUGHT
@app.route("/os-access-violation-and-path-traversal", methods=["GET"])
def os_access_violation():
  if filename := request.args.get("filename"):
    if os.path.exists(filename):
      os.unlink(filename)
      return "Deleted"
    return "File doesn't exist!"

  abort(400)


# NOT CAUGHT
@app.route("/sql-injection", methods=["GET"])
def sql_injection():
  if query := request.args.get("query"):
    with psycopg2.connect("postgresql://fake:F4k3p4SsW0rD@example.com/fakebase") as conn:
      cur = conn.cursor()
      cur.execute(query)
    return "Done!"

  abort(400)