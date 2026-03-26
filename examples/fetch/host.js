#!/usr/bin/env node

// Host: spawns hermit, loads the wrapper and untrusted code,
// and fulfills get() requests by fetching URLs with Node's fetch.

const { spawn } = require("child_process");
const { createInterface } = require("readline");
const path = require("path");
const fs = require("fs");

const hermitBin = process.env.HERMIT_BIN || "hermit";
const wrapperJs = fs.readFileSync(path.join(__dirname, "wrapper.js"), "utf8");
const untrustedJs = fs.readFileSync(
  path.join(__dirname, "untrusted.js"),
  "utf8"
);

const child = spawn(hermitBin, [], {
  stdio: ["pipe", "pipe", "inherit"],
});

const rl = createInterface({ input: child.stdout });

// Send a block of JS to hermit (code + blank line to trigger eval).
function send(code) {
  child.stdin.write(code + "\n\n");
}

// Load the wrapper, then the untrusted code.
send(wrapperJs);
send(untrustedJs);

// Read JSON messages from hermit's stdout.
rl.on("line", async (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    console.log("[hermit stdout]", line);
    return;
  }

  if (msg.type === "get") {
    console.error(`[host] fetching ${msg.url}`);
    try {
      const res = await fetch(msg.url);
      const body = await res.text();
      // Send the response back into the sandbox.
      send(`respond(${msg.id}, ${JSON.stringify(body)})`);
    } catch (err) {
      send(`respond(${msg.id}, ${JSON.stringify("error: " + err.message)})`);
    }
  } else if (msg.type === "result") {
    console.log("[result]", msg.body.slice(0, 200) + "...");
    child.stdin.end();
  }
});

child.on("exit", (code) => {
  console.error(`[host] hermit exited with code ${code}`);
});
