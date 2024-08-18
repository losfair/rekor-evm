import { ethers } from "hardhat";

async function main() {
    const RekorWitness = await ethers.getContractFactory("RekorWitness");
    const deploy = await RekorWitness.deploy();
    const address = await deploy.getAddress()

    console.log(`Deployed to ${address}`);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});