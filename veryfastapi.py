"""SAST test using FastAPI instead of Flask.
(Testing a less common but still popular framework.)"""

import importlib
import os
import re
from urllib.parse import unquote_plus as unescape

import psycopg2
import uvicorn
from fastapi import FastAPI, Form
from fastapi.exceptions import HTTPException
from pymongo import MongoClient

app = FastAPI()
client = MongoClient()
db = client.fake

# ACCURATE FINDINGS


@app.get("/ReDoS")
async def redos_get(pattern: str, search: str):
  """ReDoS vulnerability: arbitrary Regex."""
  return {"matches": re.findall(pattern, search)}


@app.get("/unsafe-exec")
async def unsafe_exec(command: str):
  out = os.popen(unescape(command))
  return {"output": out.read()}


@app.get("/os-access-violation-and-path-traversal")
async def os_access_violation(filename: str):
  # The tool should generate two identical defects
  if os.path.exists(filename):
    os.unlink(filename)
    return {"deleted": True}
  return {"deleted": False}


# MIXED RESULT


# CodeQL finds the SQL injection but not the hardcoded secret.
# I expect it can be configured to complain about it, however; this test was
# run on default settings.
@app.get("/sql-injection")
async def sql_injection(query: str):
  with psycopg2.connect("postgresql://fake:F4k3p4SsW0rD@example.com/fakebase") as conn:
    cur = conn.cursor()
    cur.execute(query)

  return {"status": "OK"}


# CodeQL finds the code injection but not the NoSQL vuln
@app.post("/nosql-unsafe-find-and-code-injection")
async def nosql_unsafe_find(params: str = Form()):
  return {"found": db.collection.find_one(eval(params))}


# CodeQL finds the code injection but not the unsafe import vuln
@app.get("/unsafe-import")
async def unsafe_import(include: str, command: str):
  importlib.import_module(include)
  output = eval(command)
  return {"output": output}


# NOT CAUGHT AT ALL


@app.get("/delete/{ident}")
async def delete_by_id(ident: str):
  """No input sanitization done, allowing the user to delete arbitrary items
    from the database."""
  db.collection.delete_one({"_id": ident})
  return {"status": "OK"}


@app.post("/nosql-injection")
async def nosql_injection(command: str = Form(), collection: str = Form()):
  db.command(command, collection)


if __name__ == "__main__":
  uvicorn.run(app, host="0.0.0.0", port=8000)