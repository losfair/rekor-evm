// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.21;

library Prover {
    function verifyConsistency(
        bytes32 root1,
        bytes32 root2,
        uint size1,
        uint size2,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        require(
            proof.length > 0 &&
                size1 > 0 &&
                size2 > size1 &&
                0xffffffff_ffffffff > size2,
            "P001"
        );

        (uint inner, uint border) = decompInclProof(size1 - 1, size2);
        uint shift = ctz64(uint64(size1));
        inner -= shift;

        bytes32 seed = proof[0];
        uint start = 1;
        if (size1 == (1 << shift)) {
            seed = root1;
            start = 0;
        }
        require(proof.length == start + inner + border, "P002");
        proof = proof[start:];

        uint mask = (size1 - 1) >> uint(shift);
        bytes32 hash1_ = chainInnerRight(seed, proof[:inner], mask);
        hash1_ = chainBorderRight(hash1_, proof[inner:]);
        if (hash1_ != root1) {
            return false;
        }

        bytes32 hash2_ = chainInner(seed, proof[:inner], mask);
        hash2_ = chainBorderRight(hash2_, proof[inner:]);
        return hash2_ == root2;
    }

    function verifyInclusion(
        uint index,
        uint size,
        bytes32 leafHash,
        bytes32[] calldata proof,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 calcRoot = rootFromInclusionProof(index, size, leafHash, proof);
        return calcRoot == root;
    }

    function rootFromInclusionProof(
        uint index,
        uint size,
        bytes32 leafHash,
        bytes32[] calldata proof
    ) private pure returns (bytes32) {
        require(index < size && size < 0xffffffff_ffffffff, "P003");
        (uint inner, uint border) = decompInclProof(index, size);
        require(proof.length == inner + border, "P004");
        bytes32 res = chainInner(leafHash, proof[:inner], index);
        res = chainBorderRight(res, proof[inner:]);
        return res;
    }

    function decompInclProof(
        uint index,
        uint size
    ) private pure returns (uint, uint) {
        uint inner = innerProofSize(index, size);
        uint border = countSetBits(index >> inner);
        return (inner, border);
    }

    function chainInner(
        bytes32 seed,
        bytes32[] calldata proof,
        uint index
    ) private pure returns (bytes32) {
        for (uint i = 0; i < proof.length; ++i) {
            if ((index >> i) & 1 == 0) {
                seed = hashChildren(seed, proof[i]);
            } else {
                seed = hashChildren(proof[i], seed);
            }
        }
        return seed;
    }

    function chainInnerRight(
        bytes32 seed,
        bytes32[] calldata proof,
        uint index
    ) private pure returns (bytes32) {
        for (uint i = 0; i < proof.length; ++i) {
            if ((index >> i) & 1 == 1) {
                seed = hashChildren(proof[i], seed);
            }
        }
        return seed;
    }

    function chainBorderRight(
        bytes32 seed,
        bytes32[] calldata proof
    ) private pure returns (bytes32) {
        for (uint i = 0; i < proof.length; ++i) {
            seed = hashChildren(proof[i], seed);
        }
        return seed;
    }

    function hashChildren(bytes32 l, bytes32 r) private pure returns (bytes32) {
        bytes memory buffer = new bytes(65);
        buffer[0] = 0x01; // RFC6962NodeHashPrefix
        for (uint i = 0; i < 32; ++i) {
            buffer[1 + i] = l[i];
            buffer[33 + i] = r[i];
        }
        return sha256(buffer);
    }

    function countSetBits(uint x) private pure returns (uint) {
        uint count;
        while (x != 0) {
            x &= x - 1;
            count++;
        }
        return count;
    }

    function innerProofSize(uint index, uint size) private pure returns (uint) {
        return 64 - clz64(uint64(index ^ (size - 1)));
    }

    function clz64(uint64 x) private pure returns (uint64) {
        uint64 n = 64;
        uint64 y;

        y = x >> 32;
        if (y != 0) {
            n = n - 32;
            x = y;
        }
        y = x >> 16;
        if (y != 0) {
            n = n - 16;
            x = y;
        }
        y = x >> 8;
        if (y != 0) {
            n = n - 8;
            x = y;
        }
        y = x >> 4;
        if (y != 0) {
            n = n - 4;
            x = y;
        }
        y = x >> 2;
        if (y != 0) {
            n = n - 2;
            x = y;
        }
        y = x >> 1;
        if (y != 0) return n - 2;
        return n - x;
    }

    function ctz64(uint64 x) private pure returns (uint64) {
        if (x == 0) {
            return 64;
        }
        return uint64(countSetBits((~x) & (x - 1)));
    }
}
