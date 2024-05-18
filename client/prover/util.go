package prover

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/trie"
)

type MemDB struct {
	data map[common.Hash][]byte
}

func NewMemDB() *MemDB {
	return &MemDB{
		data: make(map[common.Hash][]byte),
	}
}

func (m *MemDB) Has(key []byte) (bool, error) {
	_, ok := m.data[common.BytesToHash(key)]
	return ok, nil
}

func (m *MemDB) Get(key []byte) ([]byte, error) {
	value, ok := m.data[common.BytesToHash(key)]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	return value, nil
}

func (m *MemDB) Put(key []byte, value []byte) {
	m.data[common.BytesToHash(key)] = value
}

func VerifyProof(root common.Hash, key []byte, value []byte, proof []hexutil.Bytes) (bool, error) {
	db := NewMemDB()
	for _, node := range proof {
		db.Put(crypto.Keccak256(node), node)
	}

	out, err := trie.VerifyProof(root, crypto.Keccak256(key), db)
	if err != nil {
		return false, err
	}
	return bytes.Equal(value, out), nil
}
