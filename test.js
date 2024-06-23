const {
  postTemplate,
  metaTemplate,
  encodeMessage,
  createCommit,
  createIdentity,
} = require("./main");

const identity = createIdentity();

const privateKey = identity.privateKey;

async function main() {
  const postdata = postTemplate("Hello Boy", ["news"], []);

  const commitData = createCommit(privateKey, postdata, "post", 4);

  console.log(commitData);
}

main();
