// Untrusted code: uses the get() API provided by the wrapper,
// reverses the response body, and outputs the result.

get("http://example.com").then((body) => {
  const reversed = body.split("").reverse().join("");
  console.log(JSON.stringify({ type: "result", body: reversed }));
});
