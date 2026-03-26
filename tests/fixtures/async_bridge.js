// Pending resolvers keyed by id
const pending = {};

// handler returns a promise that waits for a resolve(id, value) call
const handler = (id) => {
  return new Promise((resolve) => {
    pending[id] = resolve;
  });
};

// resolve a pending handler by id
const resolve = (id, value) => {
  pending[id](value);
  delete pending[id];
};
