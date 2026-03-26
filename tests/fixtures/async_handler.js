const handler = async (input) => {
  const step1 = await Promise.resolve(input.toUpperCase());
  const step2 = await Promise.resolve(`processed: ${step1}`);
  return `handled: ${step2}`;
};
