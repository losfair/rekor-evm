package prover

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
)

type RollupHead struct {
	NodeIndex      uint64
	CreatedAtBlock uint64
	ConfirmData    [32]byte
}

func FetchRollupHead(ctx context.Context, arbRollupContractAddr common.Address, ethEndpoints []string) (*RollupHead, error) {
	type clientEntry struct {
		err                  error
		endpoint             string
		ethc                 *ethclient.Client
		finalizedBlockNumber hexutil.Uint64
		head                 RollupHead
	}

	if len(ethEndpoints) == 0 {
		return nil, fmt.Errorf("no eth endpoints provided")
	}

	wg := sync.WaitGroup{}
	clients := make([]*clientEntry, len(ethEndpoints))
	for i, endpoint := range ethEndpoints {
		wg.Add(1)

		clients[i] = &clientEntry{endpoint: endpoint}
		c := clients[i]
		go func() {
			c.ethc, c.err = ethclient.DialContext(ctx, c.endpoint)
			wg.Done()
		}()
	}
	wg.Wait()

	defer func() {
		for _, c := range clients {
			if c.ethc != nil {
				c.ethc.Close()
			}
		}
	}()
	for _, c := range clients {
		if c.err != nil {
			return nil, fmt.Errorf("failed to initialize eth client to %s: %w", c.endpoint, c.err)
		}
	}

	for _, c := range clients {
		c := c
		wg.Add(1)
		go func() {
			var result struct {
				Number hexutil.Uint64 `json:"number"`
			}

			c.err = c.ethc.Client().CallContext(ctx, &result, "eth_getBlockByNumber", "finalized", false)
			c.finalizedBlockNumber = result.Number
			wg.Done()
		}()
	}
	wg.Wait()
	for _, c := range clients {
		if c.err != nil {
			return nil, fmt.Errorf("failed to read finalized block number from eth client %s: %w", c.endpoint, c.err)
		}
	}

	minBlockNumber := clients[0].finalizedBlockNumber
	maxBlockNumber := clients[0].finalizedBlockNumber

	for _, c := range clients[1:] {
		if c.finalizedBlockNumber < minBlockNumber {
			minBlockNumber = c.finalizedBlockNumber
		}
		if c.finalizedBlockNumber > maxBlockNumber {
			maxBlockNumber = c.finalizedBlockNumber
		}
	}

	if maxBlockNumber-minBlockNumber > 3 {
		return nil, fmt.Errorf("block numbers from eth clients are too far apart: %d - %d", minBlockNumber, maxBlockNumber)
	}
	selectedBlockNumber := minBlockNumber

	latestNodeCreatedData, err := arbRollupAbi.Pack("latestNodeCreated")
	if err != nil {
		return nil, err
	}

	for _, c := range clients {
		c := c
		wg.Add(1)
		go func() {
			var res hexutil.Bytes
			c.err = c.ethc.Client().CallContext(ctx, &res, "eth_call", map[string]interface{}{
				"from": common.Address{},
				"to":   arbRollupContractAddr,
				"data": hexutil.Encode(latestNodeCreatedData),
			}, selectedBlockNumber)

			var unpacked []interface{}
			if c.err == nil {
				unpacked, c.err = arbRollupAbi.Unpack("latestNodeCreated", res)
			}

			var nodeIndex uint64
			if c.err == nil {
				nodeIndex = unpacked[0].(uint64)
			}

			var getNodeData []byte
			if c.err == nil {
				getNodeData, c.err = arbRollupAbi.Pack("getNode", nodeIndex)
			}

			if c.err == nil {
				c.err = c.ethc.Client().CallContext(ctx, &res, "eth_call", map[string]interface{}{
					"from": common.Address{},
					"to":   arbRollupContractAddr,
					"data": hexutil.Encode(getNodeData),
				}, selectedBlockNumber)
			}

			if c.err == nil {
				unpacked, c.err = arbRollupAbi.Unpack("getNode", res)
			}

			if c.err == nil {
				c.head = RollupHead{
					NodeIndex:      nodeIndex,
					CreatedAtBlock: reflect.ValueOf(unpacked[0]).FieldByName("CreatedAtBlock").Interface().(uint64),
					ConfirmData:    reflect.ValueOf(unpacked[0]).FieldByName("ConfirmData").Interface().([32]byte),
				}
			}

			wg.Done()
		}()
	}

	wg.Wait()
	for _, c := range clients {
		if c.err != nil {
			return nil, fmt.Errorf("failed to read rollup state from eth client %s: %w", c.endpoint, c.err)
		}
	}

	for _, c := range clients[1:] {
		firstHead := &clients[0].head
		thisHead := &c.head

		if firstHead.NodeIndex != thisHead.NodeIndex || firstHead.CreatedAtBlock != thisHead.CreatedAtBlock || firstHead.ConfirmData != thisHead.ConfirmData {
			return nil, fmt.Errorf("rollup state mismatch between eth clients %s and %s: %+v, %+v", clients[0].endpoint, c.endpoint, firstHead, thisHead)
		}
	}

	return &clients[0].head, nil
}
