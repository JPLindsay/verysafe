"""This is not actually very safe.

This script is an attempt at generating as many true positives in Checkmarx
as possible. Where a specific defect is named, it does NOT guarantee that
Checkmarx will list it AS a defect. Named defects are best-effort attempts
at triggering a warning, nothing more.

The Checkmarx output should be compared against Snyk Code's output.
"""

import importlib
import logging
import os
import pickle
import random
import re
import socket
import subprocess
import sys

import psycopg2
import pymongo
import requests
from fastapi import FastAPI, Request

print("YOU SHOULD NOT RUN THIS COMMAND! YOU MIGHT BREAK SOMETHING!")
i = input("Enter I DO NOT CARE to ignore this warning:")
if i != "I DO NOT CARE":
  print("Good decision")
  sys.exit()

print("CODE/COMMAND INJECTION")
user_input = input("Something to execute:")

print("eval:", eval(user_input))
print("os.system:", os.system(user_input))
print("subprocess.Popen:", subprocess.Popen(user_input.split()))

if sys.argv:
  print("\nArgv:")
  args = " ".join(sys.argv)
  print("eval:", eval(args))
  print("os.system:", os.system(args))
  print("subprocess.Popen:", subprocess.Popen(sys.argv))

if os.path.exists(user_input):
  print("You gave me a file!")
  with open(user_input, "r") as f:
    contents = f.read()
    print("eval on file contents:", eval(contents))
    print("os.system on file contents:", os.system(contents))
    print("subprocess.Popen:", subprocess.Popen(contents.split()))

r = requests.get("https://dog.ceo/api/breeds/list/all")
r.raise_for_status()
dogs = r.json()

status = dogs["status"]
print("eval:", eval(status))
print("os.system:", os.system(status))
print("subprocess.Popen:", subprocess.Popen(status.split()))


def sanitize(stuff: str) -> str:
  return stuff


print("INJECTION WITH BAD SANITIZATION")
to_sanitize = input("Something to sanitize:")
sanitized = sanitize(to_sanitize)
print(to_sanitize)
print(sanitized)
print("eval:", eval(to_sanitize))
print("eval:", eval(sanitized))

sanitized = input("Enter something:")
print("eval:", eval(sanitized))


def desanitize(stuff):
  return stuff


desanitized = desanitize(to_sanitize)
print("eval:", eval(desanitized))

test = sanitize(3)  # Not sure if Checkmarx will or should complain; Snyk does not

print("REGEX-BASED SANITIZATION")
test = input("Give me some input:")
m = re.match(r"(.*)", test)  # Snyk accepts this line, which doesn't do anything, as sanitization
sanitized = m.group(1)
print("eval:", eval(test))
print("eval:", eval(sanitized))

print("HARDCODED ABSOLUTE PATH")
with open("/Users/c517600/Developer/verysafe/verysafe.py", "r") as f:
  print(f.read())

print("CONNECTION STRING INJECTION")
client = pymongo.MongoClient(user_input)

print("LOCAL FILE INCLUSION")
importlib.import_module(user_input)

print("OS ACCESS VIOLATION")
if os.path.exists(user_input):
  print("Deleting the user-input file")
  os.unlink(user_input)

print("SQL INJECTION")
db = client.test
db.collection.delete_one(eval(user_input))
db.collection.delete_one({"name": user_input})

# Alternate method
client["test"]["collection"].delete_one({"_id": user_input})

conn = psycopg2.connect(user_input)
cur = conn.cursor()
cur.execute(user_input)

print("UNSAFE DESERIALIZATION")
if os.path.exists(user_input):
  with open(user_input, "rb") as f:
    na = pickle.load(f)
    eval(na)

print("COMMUNICATION OVER HTTP and HARDCODED SECRET")
header = {"Authorization": "token AOriesnTIOEARNTIOENARIEST"}
r = requests.get("http://example.com", headers=header)

print("HARDCODED PASSWORD IN CONNECTION STRING")
r = requests.get("http://myfakeuser:AIOSENTAIREONestntrsenetrsnienrsNEINEIRST@example.com")

print("LOG SPOOFING")
logging.basicConfig(level=user_input)
logging.info(user_input)

print("INSECURE RANDOMNESS")
password = random.random() * 1000  # Should not be caught

print("RESOURCE INJECTION")
app = FastAPI()  # By not disabling the autodocs, this should probably also flag a warning


@app.api_route("/test", methods=["GET", "POST", "DELETE"])
async def do_something_unsafe(request: Request):
  try:
    port = int(request.args.get("PortNo"))
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_sock.bind(("", port))
    server_sock.listen(500)

    while True:
      (client_sock, address) = server_sock.accept()
      # Not sure if we need to actually do anything with this socket to trigger the defect

  except Exception:
    pass