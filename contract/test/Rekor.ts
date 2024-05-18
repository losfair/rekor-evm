import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import hre from "hardhat";
import * as fs from "fs/promises";
import { RekorWitness } from "../typechain-types";

describe("RekorWitness", function () {
  const rekorOrigin = "rekor.sigstore.dev - 2605736670972794746";
  const rekorPubkey = {
    x: "0xd86d98fb6b5a6dd4d5e41706881231d1af5f005c2b9016e62d21ad92ce0bdea5",
    y: "0xfac98634cee7c19e10bc52bfe2cb9e468563fff40fdb6362e10b7d0cf7e458b7",
  };

  async function deployRekorFixture() {
    await hre.network.provider.send("hardhat_setCode", [
      "0xc2b78104907F722DABAc4C69f826a522B2754De4",
      new TextDecoder().decode(await fs.readFile("./test/P256Verifier.txt")),
    ]);

    const Rekor = await hre.ethers.getContractFactory("RekorWitness");
    const rekor = await Rekor.deploy();

    return { rekor };
  }

  describe("Sigstore Signature", function () {
    const r =
      "0x010DC86FF5BF20601716B83B9BA928FC39CBE7456C2DDEAD23E01B259B264CB8";
    const s =
      "0x098E934EA77554A7FAE79824EB9BE8CD03A4E1B2B648BB011D22AF00F7ACDAF6";
    const badS =
      "0x098E934EA77554A7FAE79824EB9BE8CD03A4E1B2B648BB011D22AF00F7ACDAF7";
    const checkpoint = new TextEncoder().encode(
      "rekor.sigstore.dev - 2605736670972794746\n76248355\n26muLFizqqekbWk9HLW74JRAv4gDzntlDA37rYx05Kg=\n",
    );

    it("accepts valid signatures", async function () {
      const { rekor } = await loadFixture(deployRekorFixture);
      const output = await rekor.decodeAndVerifySignedCheckpoint(
        r,
        s,
        rekorPubkey.x,
        rekorPubkey.y,
        checkpoint,
      );
      //console.log(output);
      expect(new TextDecoder().decode(hre.ethers.getBytes(output[0]))).to.eq(
        "rekor.sigstore.dev - 2605736670972794746",
        "bad origin",
      );
      expect(output[1]).to.eq(76248355n, "bad tree size");
      expect(output[2]).to.eq(
        "0xdba9ae2c58b3aaa7a46d693d1cb5bbe09440bf8803ce7b650c0dfbad8c74e4a8",
        "bad hash",
      );
    });

    it("rejects invalid signatures", async function () {
      const { rekor } = await loadFixture(deployRekorFixture);
      await expect(rekor.decodeAndVerifySignedCheckpoint(
        r,
        badS,
        rekorPubkey.x,
        rekorPubkey.y,
        checkpoint,
      )).to.be.revertedWith("R003");
    });
  });

  describe("Merkle Consistency Proof", function () {
    const submit_76274621 = (
      rekor: RekorWitness,
      prevTreeSize: number,
      proof: string[],
    ) =>
      rekor.submitSignedTreeHead(
        "0x87689EA2E216D9381AA047C3C916BFCF7B2A70497FD535E9A660CC8F0DFC53FD",
        "0xA3C7D5F47E74B5295157601CD6C538D565351AFC5D827E0A799BDA2739579046",
        rekorPubkey.x,
        rekorPubkey.y,
        new TextEncoder().encode(
          "rekor.sigstore.dev - 2605736670972794746\n76274621\ncFjFvFpkH6/l+N7kiTTx1LML/7iICENBL0ZuZZVnQpI=\n",
        ),
        prevTreeSize,
        proof,
      );
    const submit_76274624 = (
      rekor: RekorWitness,
      prevTreeSize: number,
      proof: string[],
    ) =>
      rekor.submitSignedTreeHead(
        "0x3AF345C993CC5162AB115F2DDF51E3C7975F1F0E049F83B7A71762BFBF853D85",
        "0x5283D2698ACA2CC6AD0EFAD6526D21B50588A747580CA217DFF67C07293AF20A",
        rekorPubkey.x,
        rekorPubkey.y,
        new TextEncoder().encode(
          "rekor.sigstore.dev - 2605736670972794746\n76274624\nyriqX4RBeOxNs2yBkEzkW5eq6nbR7NKKX5D7bvX9Ej4=\n",
        ),
        prevTreeSize,
        proof,
      );
    const submit_76276175 = (
      rekor: RekorWitness,
      prevTreeSize: number,
      proof: string[],
    ) =>
      rekor.submitSignedTreeHead(
        "0x50ACD6E0242EEDABDDFD8A538C3893A0B0919CED91FAAF97F37B8C12002085A9",
        "0xD2E9AC1F53B6FD5CCC7317D24977B22F6886935F0841AD0CA9D6A531E432DC8D",
        rekorPubkey.x,
        rekorPubkey.y,
        new TextEncoder().encode(
          "rekor.sigstore.dev - 2605736670972794746\n76276175\n4pUtBB9nuoT08HA5CmEK2MjAmMdmEJ77wY9wEwLsTmA=\n",
        ),
        prevTreeSize,
        proof,
      );

    const proof_76274621_76274624 = [
      "1a25c8c8d1d03c5d19c05ce0dee85c2252191a924aaa2eae7a251459254a5195",
      "df1a43578ba729c8488701a60de4b740d1078ad8cdc2d4d3061b0458176da1d7",
      "c207a01293a43ee57a540bf0723bd1c073ea25aca0b7d6dc897349d87711b46f",
      "8ac09effd27097f9e7da4cb1f7654ceaf272bfc616d3376da10cb7e40149e9d4",
      "2e5131fa0d4d6f090be236c57e7a81e6f78b56f17e03f9138a74060f60aa039c",
      "956b6e498857ce6c8fe60a254ad239fb40fb19eae1b01350df3e18d0ce8f0987",
      "6dbd8b63befbcb71c666800e9e143317f95f469cf82cd42c5d9dd10b1a3ec74c",
      "208d13f996799b64a76e5fdf56272ad0004370a7982e90a0ee618cb437dc5466",
      "8853fedc3be4111b70e6d0187c9eee90b1d2704eb02a7e9ae66b6bfc504f002d",
      "465ff55928491033304657396a7fd7a089c702b3455ec748b0341b07c2737ee6",
      "1413ef9c5ac40118d265ae832975714f8a556e08b9b63d4386bf3e63cd81bd9e",
      "c875a2395b15480332347f464c564e8d085e805b653fc5a8f9afecfc2a372d1f",
      "e3cc44962241367a1f90e160d21cebba9479a2809286ae37b58999333759aeac",
      "1ed35bde6930f0c4e04da426a2cc21683d3dc324cee9eadcbfed080991d17e0a",
      "94293c9157efff6e2695d6de89e13d561b1a6bb20b51d74ef79b2fb53a3bed6e",
      "06831561217d9fb425c66cc048510f5321dabe64ff72d46877481e584dbc8771",
      "5c41951863c1a9133e8c53f426f5830c0451986995805ba7ca3e5dcc35353fa3",
      "0c60918bcf6f554648566bcad8014e99e32a101ea7f91f7a65efaf8d601906fc",
      "f7c7a7ccc682fb1e6808cbc8650039cfcbeed9aa4330216f13ff77e4d7ee3f0f",
    ].map((x) => "0x" + x);

    const proof_76274624_76276175 = [
      "79972c9418bac8e9ad8bdddd00757a54ae797863731dda210c3c26015f59ac8f",
      "196c794d4ab522b03dbb6b8cdf208e545baacb07a756ac4f466fa6d6f37506f9",
      "208d13f996799b64a76e5fdf56272ad0004370a7982e90a0ee618cb437dc5466",
      "8853fedc3be4111b70e6d0187c9eee90b1d2704eb02a7e9ae66b6bfc504f002d",
      "465ff55928491033304657396a7fd7a089c702b3455ec748b0341b07c2737ee6",
      "fbf1df58d7d08a094f80c1ea674060c39a346e58c24ba4792296e68cc20fe253",
      "1413ef9c5ac40118d265ae832975714f8a556e08b9b63d4386bf3e63cd81bd9e",
      "c875a2395b15480332347f464c564e8d085e805b653fc5a8f9afecfc2a372d1f",
      "01a68a3ca13b11d78365861e85979fa01afdc05261d9c1460e24a47eb598ea24",
      "e3cc44962241367a1f90e160d21cebba9479a2809286ae37b58999333759aeac",
      "1ed35bde6930f0c4e04da426a2cc21683d3dc324cee9eadcbfed080991d17e0a",
      "94293c9157efff6e2695d6de89e13d561b1a6bb20b51d74ef79b2fb53a3bed6e",
      "06831561217d9fb425c66cc048510f5321dabe64ff72d46877481e584dbc8771",
      "5c41951863c1a9133e8c53f426f5830c0451986995805ba7ca3e5dcc35353fa3",
      "0c60918bcf6f554648566bcad8014e99e32a101ea7f91f7a65efaf8d601906fc",
      "f7c7a7ccc682fb1e6808cbc8650039cfcbeed9aa4330216f13ff77e4d7ee3f0f",
    ].map((x) => "0x" + x);

    const proof_76274621_76276175 = [
      "1a25c8c8d1d03c5d19c05ce0dee85c2252191a924aaa2eae7a251459254a5195",
      "df1a43578ba729c8488701a60de4b740d1078ad8cdc2d4d3061b0458176da1d7",
      "c207a01293a43ee57a540bf0723bd1c073ea25aca0b7d6dc897349d87711b46f",
      "8ac09effd27097f9e7da4cb1f7654ceaf272bfc616d3376da10cb7e40149e9d4",
      "2e5131fa0d4d6f090be236c57e7a81e6f78b56f17e03f9138a74060f60aa039c",
      "956b6e498857ce6c8fe60a254ad239fb40fb19eae1b01350df3e18d0ce8f0987",
      "6dbd8b63befbcb71c666800e9e143317f95f469cf82cd42c5d9dd10b1a3ec74c",
      "196c794d4ab522b03dbb6b8cdf208e545baacb07a756ac4f466fa6d6f37506f9",
      "208d13f996799b64a76e5fdf56272ad0004370a7982e90a0ee618cb437dc5466",
      "8853fedc3be4111b70e6d0187c9eee90b1d2704eb02a7e9ae66b6bfc504f002d",
      "465ff55928491033304657396a7fd7a089c702b3455ec748b0341b07c2737ee6",
      "fbf1df58d7d08a094f80c1ea674060c39a346e58c24ba4792296e68cc20fe253",
      "1413ef9c5ac40118d265ae832975714f8a556e08b9b63d4386bf3e63cd81bd9e",
      "c875a2395b15480332347f464c564e8d085e805b653fc5a8f9afecfc2a372d1f",
      "01a68a3ca13b11d78365861e85979fa01afdc05261d9c1460e24a47eb598ea24",
      "e3cc44962241367a1f90e160d21cebba9479a2809286ae37b58999333759aeac",
      "1ed35bde6930f0c4e04da426a2cc21683d3dc324cee9eadcbfed080991d17e0a",
      "94293c9157efff6e2695d6de89e13d561b1a6bb20b51d74ef79b2fb53a3bed6e",
      "06831561217d9fb425c66cc048510f5321dabe64ff72d46877481e584dbc8771",
      "5c41951863c1a9133e8c53f426f5830c0451986995805ba7ca3e5dcc35353fa3",
      "0c60918bcf6f554648566bcad8014e99e32a101ea7f91f7a65efaf8d601906fc",
      "f7c7a7ccc682fb1e6808cbc8650039cfcbeed9aa4330216f13ff77e4d7ee3f0f",
    ].map((x) => "0x" + x);

    it("accepts sequentially submitted proofs", async function () {
      const { rekor } = await loadFixture(deployRekorFixture);

      await submit_76274621(rekor, 0, []);
      await submit_76274624(
        rekor,
        76274621,
        proof_76274621_76274624,
      );
      await submit_76276175(
        rekor,
        76274624,
        proof_76274624_76276175,
      );

      const g = await rekor.getTreeHead(
        new TextEncoder().encode(rekorOrigin),
        rekorPubkey.x,
        rekorPubkey.y,
      );
      expect(g[0]).to.eq(76276175n);
      expect(g[1]).to.eq(
        "0xe2952d041f67ba84f4f070390a610ad8c8c098c766109efbc18f701302ec4e60",
      );
    });

    it("rejects reversely submitted proofs", async function () {
      const { rekor } = await loadFixture(deployRekorFixture);

      await submit_76276175(
        rekor,
        0,
        [],
      );
      await expect(submit_76274624(
        rekor,
        76276175,
        proof_76274624_76276175,
      )).to.be.revertedWith("P001");

      const g = await rekor.getTreeHead(
        new TextEncoder().encode(rekorOrigin),
        rekorPubkey.x,
        rekorPubkey.y,
      );
      expect(g[0]).to.eq(76276175n);
      expect(g[1]).to.eq(
        "0xe2952d041f67ba84f4f070390a610ad8c8c098c766109efbc18f701302ec4e60",
      );
    });

    it("rejects inserted proofs", async function () {
      const { rekor } = await loadFixture(deployRekorFixture);

      await submit_76274621(rekor, 0, []);
      await submit_76276175(
        rekor,
        76274621,
        proof_76274621_76276175,
      );
      await expect(submit_76274624(
        rekor,
        76274621,
        proof_76274621_76274624,
      )).to.be.revertedWith("R001");
    });

    it("rejects invalid proofs", async function () {
      const { rekor } = await loadFixture(deployRekorFixture);

      await submit_76274621(rekor, 0, []);
      await expect(submit_76276175(
        rekor,
        76274621,
        proof_76274621_76274624,
      )).to.be.revertedWith("P002");
      await expect(submit_76276175(
        rekor,
        76274621,
        [proof_76274624_76276175[0], ...proof_76274621_76276175.slice(1)],
      )).to.be.revertedWith("R002");
    });

    it("passes consistency check", async function () {
      const { rekor } = await loadFixture(deployRekorFixture);

      await submit_76274621(rekor, 0, []);
      await submit_76276175(
        rekor,
        76274621,
        proof_76274621_76276175,
      );

      const g = await rekor.getTreeHead(
        new TextEncoder().encode(rekorOrigin),
        rekorPubkey.x,
        rekorPubkey.y,
      );

      let output = await rekor.checkConsistency(
        { size: g[0], hash_: g[1] },
        "0x3AF345C993CC5162AB115F2DDF51E3C7975F1F0E049F83B7A71762BFBF853D85",
        "0x5283D2698ACA2CC6AD0EFAD6526D21B50588A747580CA217DFF67C07293AF20A",
        rekorPubkey.x,
        rekorPubkey.y,
        new TextEncoder().encode(
          "rekor.sigstore.dev - 2605736670972794746\n76274624\nyriqX4RBeOxNs2yBkEzkW5eq6nbR7NKKX5D7bvX9Ej4=\n",
        ),
        proof_76274624_76276175,
      );
      expect(output[0]).to.eq(true);
      expect(new TextDecoder().decode(hre.ethers.getBytes(output[1][0]))).to.eq(
        "rekor.sigstore.dev - 2605736670972794746",
      );
      expect(output[1][1]).to.eq(76274624);
      expect(output[1][2]).to.eq(
        "0xcab8aa5f844178ec4db36c81904ce45b97aaea76d1ecd28a5f90fb6ef5fd123e",
      );

      output = await rekor.checkConsistency(
        { size: g[0], hash_: g[1] },
        "0x3AF345C993CC5162AB115F2DDF51E3C7975F1F0E049F83B7A71762BFBF853D85",
        "0x5283D2698ACA2CC6AD0EFAD6526D21B50588A747580CA217DFF67C07293AF20A",
        rekorPubkey.x,
        rekorPubkey.y,
        new TextEncoder().encode(
          "rekor.sigstore.dev - 2605736670972794746\n76274624\nyriqX4RBeOxNs2yBkEzkW5eq6nbR7NKKX5D7bvX9Ej4=\n",
        ),
        [proof_76274624_76276175[1], ...proof_76274624_76276175.slice(1)],
      );
      expect(output[0]).to.eq(false);
      expect(new TextDecoder().decode(hre.ethers.getBytes(output[1][0]))).to.eq(
        "rekor.sigstore.dev - 2605736670972794746",
      );
      expect(output[1][1]).to.eq(76274624);
      expect(output[1][2]).to.eq(
        "0xcab8aa5f844178ec4db36c81904ce45b97aaea76d1ecd28a5f90fb6ef5fd123e",
      );
    });
    it("passes inclusion check", async function () {
      // https://rekor.sigstore.dev/api/v1/log/entries/24296fb24b8ad77ac2b938a518cbc2cb459657502d2463b4317a592c95bc00e0274fcfa3ec695dc0

      const { rekor } = await loadFixture(deployRekorFixture);

      const proof = [
        "ff394cc496ef20276caf2d412ba8cecddc481066339b041dfeba2104db17ee65",
        "5e0120b021569cc8469921d13eb4a3c0e8d972c1e91f7984108688adc053bc2c",
        "3d668560bb0edfdc552ad978ed00018c7c3e80abd370a540d01d2103679d6c83",
        "98f6e2a82ef8197ac6a8b31cc5786b6c8f80d91675faab642a0ff53101462a79",
        "5731cecb5a0e5fcbe0c935fcb190c7ec513f1d65549e48ac1d89e434ad44de89",
        "7f95e874d908eb9afd0ae07e41df59501cd35fb8be91dad1f99aefd5db5ecc2b",
        "c76dbe62e9debd6c07a8b6f36d3f24d04bfad77e2543ce6015997a6f15ac8843",
        "9d05b155ce634186de469666528ad4689840c4d2364be3288e1ef6609364a9a1",
        "e577f6b57528ff4fcbfd345631ab775e1fce4c91e66f4f74ab52e4f792e593b7",
        "df9487517a7e6a9f8e922471996f72d284775750fde8fa848639f0d15548d528",
        "9bf973cbe15042921c50bef75086f65f1bc4beaf2c7e7d09c105c929068aa1b7",
        "3567553c4598945584a74f34f4fee41ce643e22ced9e8463e5d5d17a403ca90c",
        "e5363462c9f64d71afdb733f9dc681941f3b289d3b2f5b9d31466fa98ca1dfab",
        "fc8e3a3983df08296a26ac0156751d0542a113b6d82d4828d674730e05e32fbc",
        "19d8bedc9ce596dd52119bb982fb8998a76caae2ddcfc379f842df1dfc4d57f1",
        "a02354c6a05077c25b36132b42a225c62d03e1984bd1be1beb05952b9c2e4ef8",
        "167b36231563e317cb696fc581d21dbec0b47f3de99c0728810f559613f4ae7a",
        "a30b621c43a16689e426ea825bd5e090e41da93426186ded99dea1e3ed8adc49",
        "b49b2165fff1c0c1fe12fc8b78aeca23f851315ff42672c76a90db243dff9972",
        "da194f30c85438f6fa6c2f955addc62969ca0acf1910cdf277b19a9e913f7297",
        "99386b70279ba2db47d6a3e876495531b5195f07a6e435f071f8b4db843d5399",
        "614d63658fdfa79b4974617f8beffb7b3f35d3b3b8fe5394a7b69c30f14468e0",
        "ed9d7c60b040bde8c45789c91c82a892cff19628e7851d34e6a4d6db0e10b478",
        "f75f7a3f25037c33a115ed9a2df05a53c6e248f68600877d01cc5e6aad02a4dd",
        "f7c7a7ccc682fb1e6808cbc8650039cfcbeed9aa4330216f13ff77e4d7ee3f0f",
      ].map((x) => "0x" + x);
      let output = await rekor.checkInclusion(
        {
          size: 76348395,
          hash_:
            "0x428099682bab11564ea9ab21fb0de84ec54b4eb58c3afb7776cd9fc397458aab",
        },
        74195363,
        // sha256(\x00 + b64decode(body))
        "0xc2b938a518cbc2cb459657502d2463b4317a592c95bc00e0274fcfa3ec695dc0",
        proof,
      );
      expect(output).to.eq(true);
      output = await rekor.checkInclusion(
        {
          size: 76348395,
          hash_:
            "0x428099682bab11564ea9ab21fb0de84ec54b4eb58c3afb7776cd9fc397458aab",
        },
        74195363,
        // sha256(\x01 + b64decode(body))
        "0xd03c3f573653cbd8c680e521c1998117ccdd2420f118227aa0557b3ff9a2bf2a",
        proof,
      );
      expect(output).to.eq(false);
    });
  });
});
