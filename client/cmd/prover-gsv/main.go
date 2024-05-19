package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/losfair/rekor-evm/client/prover"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"
)

func main() {
	// Parse command line arguments
	ethRpcList_ := flag.String(
		"eth-rpc-list",
		"https://rpc.flashbots.net,https://eth.llamarpc.com,https://ethereum-rpc.publicnode.com,https://cloudflare-eth.com",
		"Comma-separated Ethereum RPC endpoint list. At least one of them should be honest.",
	)
	arbRpc := flag.String("arb-rpc", "https://arbitrum-one.publicnode.com", "Arbitrum RPC endpoint. This does not need to be trusted.")
	arbRollupContractAddr := flag.String("arb-rollup-contract", "0x5eF0D09d1E6204141B4d37530808eD19f60FBa35", "Arbitrum Rollup contract address on Ethereum")
	rekorWitnessContractAddr := flag.String("rekor-witness-contract", "0x50D49737c69eB3b6621f825CfFD2b13B9e41dDa3", "Rekor Witness contract address on Arbitrum")
	flag.Parse()

	ethRpcList := strings.Split(*ethRpcList_, ",")

	// Setup logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	defer logger.Sync() // flushes buffer, if any

	// Initialize Prover
	config := &prover.ProverConfig{
		EthApiEndpointList:       ethRpcList,
		UntrustedArbApiEndpoint:  *arbRpc,
		ArbRollupContractAddress: common.HexToAddress(*arbRollupContractAddr),
	}
	p := prover.NewProver(config)

	// Example call to GetStorageValues (adjust according to your needs)
	ctx := context.Background()
	address := common.HexToAddress(*rekorWitnessContractAddr)

	var zero32 [32]byte
	slot := new(big.Int).SetBytes(crypto.Keccak256Hash(common.Hex2Bytes("72656B6F722E73696773746F72652E646576202D2032363035373336363730393732373934373436"), crypto.Keccak256(common.Hex2Bytes("FAC98634CEE7C19E10BC52BFE2CB9E468563FFF40FDB6362E10B7D0CF7E458B7"), crypto.Keccak256(common.Hex2Bytes("D86D98FB6B5A6DD4D5E41706881231D1AF5F005C2B9016E62D21AD92CE0BDEA5"), zero32[:]))).Bytes())
	logger.Info("calculated slot", zap.String("slot", hexutil.EncodeBig(slot)))
	slots := []hexutil.Big{hexutil.Big(*slot), hexutil.Big(*new(big.Int).Add(slot, big.NewInt(1)))}
	values, err := p.GetVerifiedStorageValues(ctx, logger, address, slots)
	if err != nil {
		logger.Error("Error getting storage values", zap.Error(err))
		return
	}

	fmt.Println("Storage Values:", values)
}
