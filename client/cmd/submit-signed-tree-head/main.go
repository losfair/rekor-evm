package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"reflect"

	_ "embed"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	"go.uber.org/zap"
)

//go:embed rekor-witness-abi.json
var rekorWitnessAbiJson []byte
var rekorWitnessAbi abi.ABI

func init() {
	abi_, err := abi.JSON(bytes.NewReader(rekorWitnessAbiJson))
	if err != nil {
		panic(fmt.Errorf("failed to parse rekor-witness-abi: %w", err))
	}

	rekorWitnessAbi = abi_
}

func main() {
	l2RPCEndpoint := flag.String("l2-rpc", "https://rpc.scroll.io", "L2 RPC endpoint")
	contractAddr_ := flag.String("contract", "0x91249a54EfEFF79e333D4c9C49fcfAbE72687909", "Rekor Witness contract address on L2")
	rekorAPIEndpoint := flag.String("rekor-api", "https://rekor.sigstore.dev", "Rekor API endpoint")
	chainID := flag.Int("chain-id", 534352, "Chain ID")
	maxGasPriceGwei := flag.Float64("max-gas-price-gwei", 0.1, "Max gas price in Gwei")
	maxGasLimit := flag.Uint64("max-gas-limit", 2000000, "Max gas limit")
	live := flag.Bool("live", false, "Submit transaction to network")
	flag.Parse()

	// Setup logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	defer logger.Sync() // flushes buffer, if any

	privateKeyHex := os.Getenv("ETH_PRIVATE_KEY")
	if privateKeyHex == "" {
		logger.Fatal("ETH_PRIVATE_KEY env var is required")
	}

	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		logger.Fatal("Failed to parse ETH_PRIVATE_KEY", zap.Error(err))
	}

	l2c, err := ethclient.Dial(*l2RPCEndpoint)
	if err != nil {
		logger.Fatal("Failed to connect to L2 RPC", zap.Error(err))
	}
	defer l2c.Close()

	contractAddr := common.HexToAddress(*contractAddr_)

	httpc := http.Client{}
	res, err := httpc.Get(*rekorAPIEndpoint + "/api/v1/log")
	if err != nil {
		logger.Fatal("Failed to get log info", zap.Error(err))
	}
	if res.StatusCode != http.StatusOK {
		logger.Fatal("Failed to get log info", zap.Int("status", res.StatusCode))
	}

	var body models.LogInfo
	err = json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close()

	if err != nil {
		logger.Fatal("Failed to decode log info", zap.Error(err))
	}

	var sth util.SignedCheckpoint
	err = sth.UnmarshalText([]byte(*body.SignedTreeHead))
	if err != nil {
		logger.Fatal("Failed to unmarshal signed tree head", zap.Error(err))
	}

	rawSig, err := base64.StdEncoding.DecodeString(sth.Signatures[0].Base64)
	if err != nil {
		logger.Fatal("Failed to decode signature", zap.Error(err))
	}
	r_, s_, err := parseASN1ECDSASignature(rawSig)
	if err != nil {
		logger.Fatal("Failed to parse signature", zap.Error(err))
	}

	var r, s [32]byte
	r_.FillBytes(r[:])
	s_.FillBytes(s[:])

	th, err := sth.MarshalCheckpoint()
	if err != nil {
		logger.Fatal("Failed to marshal checkpoint", zap.Error(err))
	}

	res, err = httpc.Get(*rekorAPIEndpoint + "/api/v1/log/publicKey")
	if err != nil {
		logger.Fatal("Failed to get public key", zap.Error(err))
	}
	if res.StatusCode != http.StatusOK {
		logger.Fatal("Failed to get public key", zap.Int("status", res.StatusCode))
	}

	rawPubKey, err := io.ReadAll(res.Body)
	res.Body.Close()

	if err != nil {
		logger.Fatal("Failed to read public key", zap.Error(err))
	}

	pubKey, err := parseASN1ECDSAPublicKeyPem(rawPubKey)
	if err != nil {
		logger.Fatal("Failed to parse public key", zap.Error(err))
	}

	var x, y [32]byte
	pubKey.X.FillBytes(x[:])
	pubKey.Y.FillBytes(y[:])

	payload, err := rekorWitnessAbi.Pack("getTreeHead", []byte(sth.Origin), x, y)
	if err != nil {
		logger.Fatal("Failed to pack payload", zap.Error(err))
	}

	callRes, err := l2c.CallContract(context.Background(), ethereum.CallMsg{
		To:   &contractAddr,
		Data: payload,
	}, nil)
	if err != nil {
		logger.Fatal("Failed to call contract", zap.Error(err))
	}
	witnessedTh, err := rekorWitnessAbi.Unpack("getTreeHead", callRes)
	if err != nil {
		logger.Fatal("Failed to unpack call result", zap.Error(err))
	}
	witnessedSize := reflect.ValueOf(witnessedTh[0]).FieldByName("Size").Interface().(*big.Int).Uint64()

	if sth.Checkpoint.Size <= witnessedSize {
		logger.Info("No new tree heads to submit", zap.Uint64("witnessedSize", witnessedSize), zap.Uint64("sthSize", sth.Checkpoint.Size))
		return
	}

	logger.Info("tree heads", zap.Any("witnessedTh", witnessedTh), zap.Any("sth", sth.Checkpoint))

	var proof [][32]byte
	if witnessedSize != 0 {
		// generate proof
		res, err := httpc.Get(*rekorAPIEndpoint + fmt.Sprintf("/api/v1/log/proof?firstSize=%d&lastSize=%d", witnessedSize, sth.Checkpoint.Size))
		if err != nil {
			logger.Fatal("Failed to get log proof", zap.Error(err))
		}
		if res.StatusCode != http.StatusOK {
			logger.Fatal("Failed to get log proof", zap.Int("status", res.StatusCode))
		}

		var body models.ConsistencyProof
		err = json.NewDecoder(res.Body).Decode(&body)
		res.Body.Close()

		if err != nil {
			logger.Fatal("Failed to decode log proof", zap.Error(err))
		}

		proof = make([][32]byte, len(body.Hashes))
		for i, entry := range body.Hashes {
			copy(proof[i][:], common.Hex2Bytes(entry))
		}
	}

	gasPrice, err := l2c.SuggestGasPrice(context.Background())
	if err != nil {
		logger.Fatal("Failed to get gas price", zap.Error(err))
	}

	gasPrice = new(big.Int).Div(new(big.Int).Mul(gasPrice, big.NewInt(110)), big.NewInt(100))
	if gasPrice.Cmp(new(big.Int).SetUint64(uint64(float64(1e9)**maxGasPriceGwei))) == 1 {
		logger.Fatal("Gas price too high", zap.String("gasPrice", fmt.Sprintf("%.3f Gwei", float64(new(big.Int).Div(gasPrice, big.NewInt(1e6)).Uint64())/1000.0)), zap.String("maxGasPrice", fmt.Sprintf("%.3f Gwei", *maxGasPriceGwei)))
	}

	payload, err = rekorWitnessAbi.Pack("submitSignedTreeHead", r, s, x, y, th, new(big.Int).SetUint64(witnessedSize), proof)
	if err != nil {
		logger.Fatal("Failed to pack submitSignedTreeHead payload", zap.Error(err))
	}

	gas, err := l2c.EstimateGas(context.Background(), ethereum.CallMsg{
		To:   &contractAddr,
		Data: payload,
	})
	if err != nil {
		logger.Fatal("Failed to estimate gas", zap.Error(err))
	}
	if gas > *maxGasLimit {
		logger.Fatal("Estimated gas too high", zap.Uint64("gas", gas), zap.Uint64("maxGasLimit", *maxGasLimit))
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	logger.Info("wallet address", zap.String("address", address.Hex()))

	nonce, err := l2c.PendingNonceAt(context.Background(), address)
	if err != nil {
		logger.Fatal("Failed to get nonce", zap.Error(err))
	}

	rawTx := types.DynamicFeeTx{
		To:        &contractAddr,
		Nonce:     nonce,
		Data:      payload,
		Gas:       gas,
		GasFeeCap: gasPrice,
		ChainID:   big.NewInt(int64(*chainID)),
	}
	wrappedTx := types.NewTx(&rawTx)
	signer := types.NewLondonSigner(big.NewInt(int64(*chainID)))
	txHash := signer.Hash(wrappedTx)
	logger.Info("transaction created", zap.Any("rawTx", rawTx), zap.String("unsignedTxHash", txHash.Hex()))

	if *live {
		sig, err := crypto.Sign(txHash[:], privateKey)
		if err != nil {
			logger.Fatal("Failed to sign transaction", zap.Error(err))
		}

		tx, err := wrappedTx.WithSignature(signer, sig)
		if err != nil {
			logger.Fatal("Failed to get signed transaction", zap.Error(err))
		}

		err = l2c.SendTransaction(context.Background(), tx)
		if err != nil {
			logger.Fatal("Failed to send transaction", zap.Error(err))
		}

		logger.Info("transaction sent", zap.String("txHash", tx.Hash().Hex()))
	}
}
