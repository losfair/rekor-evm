package prover

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"go.uber.org/zap"
)

//go:embed arb-rollup-abi.json
var arbRollupAbiJson []byte
var arbRollupAbi abi.ABI

func init() {
	abi_, err := abi.JSON(bytes.NewReader(arbRollupAbiJson))
	if err != nil {
		panic(fmt.Errorf("failed to parse arb-rollup-abi: %w", err))
	}

	arbRollupAbi = abi_
}

type Prover struct {
	config *ProverConfig
}

type ProverConfig struct {
	// A list of Ethereum endpoints. Secure as long as any one of them is honest.
	EthApiEndpointList []string

	// Arbitrum L2 EVM-compatible endpoint. This does not have to be trusted.
	UntrustedArbApiEndpoint string

	// Arbitrum rollup contract address on L1.
	ArbRollupContractAddress common.Address
}

type EthProofResult struct {
	AccountProof []hexutil.Bytes `json:"accountProof"`
	Balance      hexutil.Big     `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        hexutil.Uint64  `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []struct {
		Key   hexutil.Big     `json:"key"`
		Proof []hexutil.Bytes `json:"proof"`
		Value hexutil.Big     `json:"value"`
	} `json:"storageProof"`
}

func NewProver(config *ProverConfig) *Prover {
	return &Prover{
		config: config,
	}
}

func (p *Prover) GetVerifiedStorageValues(ctx context.Context, logger *zap.Logger, address common.Address, slots []hexutil.Big) ([]hexutil.Big, error) {
	arbc, err := ethclient.Dial(p.config.UntrustedArbApiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize arb client: %w", err)
	}
	defer arbc.Close()

	head, err := FetchRollupHead(ctx, p.config.ArbRollupContractAddress, p.config.EthApiEndpointList)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch rollup head: %w", err)
	}

	l2h, err := loadAndVerifyL2Header(ctx, logger, p.config, arbc, head.NodeIndex, head.CreatedAtBlock, head.ConfirmData)
	if err != nil {
		return nil, fmt.Errorf("failed to load and verify L2 header: %w", err)
	}

	logger.Info("l2 block verified", zap.Any("blockNumber", l2h.Number), zap.String("stateRoot", l2h.Root.String()))

	// Now the L2 block is verified
	// Get proofs
	var proof EthProofResult
	err = arbc.Client().CallContext(ctx, &proof, "eth_getProof", address, slots, hexutil.EncodeBig(l2h.Number))
	if err != nil {
		return nil, fmt.Errorf("failed to get proofs: %w", err)
	}

	// verify account proof
	buf, err := rlp.EncodeToBytes([]interface{}{
		proof.Nonce, proof.Balance.ToInt(), proof.StorageHash, proof.CodeHash,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode account proof: %w", err)
	}
	ok, err := VerifyProof(l2h.Root, address.Bytes(), buf, proof.AccountProof)
	if err != nil {
		return nil, fmt.Errorf("failed to verify account proof: %w", err)
	}
	if !ok {
		return nil, errors.New("account proof verification failed")
	}

	// verify slot proofs
	if len(slots) != len(proof.StorageProof) {
		return nil, errors.New("slot proof count mismatch")
	}

	var outputs []hexutil.Big
	for i, slot := range slots {
		thisProof := proof.StorageProof[i]
		if slot.ToInt().Cmp(thisProof.Key.ToInt()) != 0 {
			return nil, errors.New("slot proof key mismatch")
		}

		var value []byte
		if thisProof.Value.ToInt().Cmp(&big.Int{}) != 0 {
			value_, err := rlp.EncodeToBytes(thisProof.Value.ToInt())
			if err != nil {
				return nil, fmt.Errorf("failed to encode slot proof value: %w", err)
			}
			value = value_
		}

		ok, err := VerifyProof(proof.StorageHash, thisProof.Key.ToInt().Bytes(), value, thisProof.Proof)
		if err != nil {
			return nil, fmt.Errorf("failed to verify slot proof: %w", err)
		}
		if !ok {
			return nil, errors.New("slot proof verification failed")
		}

		outputs = append(outputs, thisProof.Value)
	}

	return outputs, nil
}

func loadAndVerifyL2Header(ctx context.Context, logger *zap.Logger, config *ProverConfig, arbc *ethclient.Client, nodeIndex uint64, createdAtBlock uint64, confirmData [32]byte) (*types.Header, error) {
	untrustedEthApiEndpoint := config.EthApiEndpointList[0]
	untrustedEthc, err := ethclient.Dial(untrustedEthApiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize untrusted eth client: %w", err)
	}
	defer untrustedEthc.Close()

	var nodeIndex32b [32]byte
	binary.BigEndian.PutUint64(nodeIndex32b[24:], nodeIndex)

	untrustedLogs, err := untrustedEthc.FilterLogs(ctx, ethereum.FilterQuery{
		Addresses: []common.Address{config.ArbRollupContractAddress},
		Topics:    [][]common.Hash{{arbRollupAbi.Events["NodeCreated"].ID}, {common.Hash(nodeIndex32b)}},
		FromBlock: new(big.Int).SetUint64(createdAtBlock),
		ToBlock:   new(big.Int).SetUint64(createdAtBlock),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to filter logs: %w", err)
	}
	if len(untrustedLogs) != 1 {
		return nil, fmt.Errorf("unexpected number of logs: %+v", untrustedLogs)
	}
	out, err := arbRollupAbi.Unpack("NodeCreated", untrustedLogs[0].Data)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack NodeCreated output: %w", err)
	}
	untrustedGs := reflect.ValueOf(out[1]).FieldByName("AfterState").FieldByName("GlobalState").FieldByName("Bytes32Vals").Interface().([2][32]byte)
	untrustedBlockHash := untrustedGs[0]
	untrustedSendRoot := untrustedGs[1]

	logger.Info(
		"l1 node info",
		zap.Uint64("nodeIndex", nodeIndex),
		zap.String("confirmData", hexutil.Encode(confirmData[:])),
		zap.String("untrustedL2BlockHash", hexutil.Encode(untrustedBlockHash[:])),
		zap.String("untrustedL2SendRoot", hexutil.Encode(untrustedSendRoot[:])),
	)

	l2h, err := arbc.HeaderByHash(ctx, untrustedBlockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get L2 block: %w", err)
	}
	rlpEncodedBlock, err := rlp.EncodeToBytes(l2h)
	if err != nil {
		return nil, fmt.Errorf("failed to RLP encode block: %w", err)
	}

	// Verify L2 block info
	// keccak256(abi.encodePacked(keccak256(arbData.rlpEncodedBlock), arbData.sendRoot))
	untrustedConfirmData := crypto.Keccak256Hash(crypto.Keccak256(rlpEncodedBlock), untrustedSendRoot[:])
	if !bytes.Equal(confirmData[:], untrustedConfirmData[:]) {
		return nil, errors.New("confirmData mismatch")
	}

	return l2h, nil
}
