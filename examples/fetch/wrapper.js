// Wrapper: provides a get(url) API to untrusted code.
// The host fulfills requests by reading JSON from hermit's stdout
// and sending JSON responses back via stdin.

const pending = {};
let nextId = 0;

// Request a URL from the host. Returns a promise that resolves
// with the response body string.
const get = (url) => {
  const id = nextId++;
  console.log(JSON.stringify({ type: "get", id, url }));
  return new Promise((resolve) => {
    pending[id] = resolve;
  });
};

// Called by the host to deliver a response.
const respond = (id, body) => {
  pending[id](body);
  delete pending[id];
};
