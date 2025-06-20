const { assertEquals, runTest } = require("@stacks/clarity-js-sdk");

const contractName = "refugee-vault";
const adminAddress = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM";

describe("refugee identity vault", () => {
  let client;

  before(async () => {
    client = await Client.createDefaultClient();
    await client.deployContract(contractName, adminAddress);
  });

  it("should add a refugee", async () => {
    const result = await client.executeContract({
      contractName,
      functionName: "add-refugee",
      sender: adminAddress,
      args: ["u1", "John Doe", "u19900101", "Syria", "Asylum Seeker", "Camp A"]
    });
    assertEquals(result.success, true);
  });

  it("should not allow duplicate refugee IDs", async () => {
    const result = await client.executeContract({
      contractName,
      functionName: "add-refugee",
      sender: adminAddress,
      args: ["u1", "Jane Doe", "u19900101", "Syria", "Asylum Seeker", "Camp A"]
    });
    assertEquals(result.success, false);
  });

  // Add more tests...
});
