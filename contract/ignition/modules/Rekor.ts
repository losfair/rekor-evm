import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const RekorModule = buildModule("RekorModule", (m) => {
  const rekor = m.contract("RekorWitness", []);
  return { rekor };
});

export default RekorModule;
