// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.21;

import {Base64} from "./Base64.sol";
import {P256} from "./P256.sol";
import {Prover} from "./Prover.sol";

contract RekorWitness {
    struct SignedCheckpoint {
        bytes origin;
        uint256 size;
        bytes32 hash_;
    }

    struct TreeHead {
        uint256 size;
        bytes32 hash_;
    }

    event UpdatedTreeHead(
        bytes origin,
        bytes32 x,
        bytes32 y,
        bytes32 newHead,
        uint256 newSize
    );

    // x => (y => (origin => TreeHead))
    mapping(bytes32 => mapping(bytes32 => mapping(bytes => TreeHead))) treeHeads;

    function getTreeHead(
        bytes calldata origin,
        bytes32 x,
        bytes32 y
    ) external view returns (TreeHead memory g) {
        g = treeHeads[x][y][origin];
    }

    function checkInclusion(
        TreeHead calldata head,
        uint index,
        bytes32 leafHash,
        bytes32[] calldata inclusionProof
    ) external pure returns (bool) {
        return
            Prover.verifyInclusion(
                index,
                head.size,
                leafHash,
                inclusionProof,
                head.hash_
            );
    }

    function checkConsistency(
        TreeHead calldata head,
        bytes32 r,
        bytes32 s,
        bytes32 x,
        bytes32 y,
        bytes calldata data,
        bytes32[] calldata consistencyProof
    ) external view returns (bool success, SignedCheckpoint memory ckpt) {
        ckpt = decodeAndVerifySignedCheckpoint(r, s, x, y, data);

        if (ckpt.size < head.size) {
            success = Prover.verifyConsistency(
                ckpt.hash_,
                head.hash_,
                ckpt.size,
                head.size,
                consistencyProof
            );
        } else if (ckpt.size == head.size && head.size != 0) {
            success = ckpt.hash_ == head.hash_;
        }
    }

    function submitSignedTreeHead(
        bytes32 r,
        bytes32 s,
        bytes32 x,
        bytes32 y,
        bytes calldata data,
        uint256 prevTreeSize,
        bytes32[] calldata consistencyProof
    ) external {
        SignedCheckpoint memory ckpt = decodeAndVerifySignedCheckpoint(
            r,
            s,
            x,
            y,
            data
        );

        TreeHead storage g = treeHeads[x][y][ckpt.origin];
        uint256 gSize = g.size;
        bytes32 gHash = g.hash_;

        require(gSize == prevTreeSize, "R001");

        if (gSize != 0) {
            bool success = Prover.verifyConsistency(
                gHash,
                ckpt.hash_,
                gSize,
                ckpt.size,
                consistencyProof
            );
            require(success, "R002");
        } else {
            require(consistencyProof.length == 0, "R002");
        }

        g.hash_ = ckpt.hash_;
        g.size = ckpt.size;

        emit UpdatedTreeHead({
            origin: ckpt.origin,
            x: x,
            y: y,
            newHead: ckpt.hash_,
            newSize: ckpt.size
        });
    }

    function decodeAndVerifySignedCheckpoint(
        bytes32 r,
        bytes32 s,
        bytes32 x,
        bytes32 y,
        bytes calldata data
    ) public view returns (SignedCheckpoint memory result) {
        bytes32 dataHash = sha256(data);
        bool ok = P256.verifySignatureAllowMalleability(
            dataHash,
            uint256(r),
            uint256(s),
            uint256(x),
            uint256(y)
        );
        require(ok, "R003");

        uint endOfOrigin = 0;
        uint endOfSize = 0;
        uint endOfHash = 0;

        for (uint i = 0; i < data.length; i++) {
            if (data[i] == 0x0a) {
                endOfOrigin = i;
                break;
            }
        }
        require(endOfOrigin > 0, "R004");
        result.origin = data[0:endOfOrigin];

        for (uint i = endOfOrigin + 1; i < data.length; i++) {
            if (data[i] == 0x0a) {
                endOfSize = i;
                break;
            }
        }
        require(endOfSize > 0, "R005");
        // max decimal length == 30, plus prefix newline - max total length == 31
        require(endOfSize - endOfOrigin < 32, "R006");
        result.size = 0;
        for (uint i = endOfOrigin + 1; i < endOfSize; i++) {
            uint256 c = uint8(data[i]);
            require(c >= 48 && c <= 57, "R007");
            result.size = result.size * 10 + (c - 48);
        }
        require(result.size > 0, "R008");

        for (uint i = endOfSize + 1; i < data.length; i++) {
            if (data[i] == 0x0a) {
                endOfHash = i;
                break;
            }
        }
        require(endOfHash > 0, "R009");
        // base64(32 bytes).length + 1
        require(endOfHash - endOfSize == 45, "R010");
        bytes memory hashBytes = Base64.decode(data[endOfSize + 1:endOfHash]);

        require(hashBytes.length == 32, "R011");
        bytes32 hashValue;
        assembly {
            hashValue := mload(add(hashBytes, 32))
        }
        result.hash_ = hashValue;

        // Trailing data is allowed
    }
}
