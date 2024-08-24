package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
)

// parseASN1ECDSAPublicKeyPem takes a PEM encoded ECDSA public key as input and returns the *ecdsa.PublicKey and an error if any.
func parseASN1ECDSAPublicKeyPem(raw []byte) (*ecdsa.PublicKey, error) {
	// Decode the PEM block from the raw input
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	// Parse the public key from the DER encoded data
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Attempt to assert the type of the parsed key to *ecdsa.PublicKey
	ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key type is not ECDSA")
	}

	return ecdsaPubKey, nil
}

// parseASN1ECDSASignature takes a byte slice containing an ASN.1 encoded ECDSA signature
// and returns the r and s values as *big.Int, along with any error encountered.
func parseASN1ECDSASignature(sig []byte) (r, s *big.Int, err error) {
	// Define a struct to hold the R and S values of the signature
	var rs struct {
		R, S *big.Int
	}

	// Unmarshal the ASN.1 encoded signature into the rs struct
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		return nil, nil, err
	}

	// Check if either R or S is nil, which would indicate a parsing issue
	if rs.R == nil || rs.S == nil {
		return nil, nil, errors.New("failed to parse ECDSA signature: R or S values are nil")
	}

	return rs.R, rs.S, nil
}
