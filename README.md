# rekor-evm

This repository implements a witness of the
[Rekor](https://github.com/sigstore/rekor) tamper-resistant transparency log on
EVM-compatible Ethereum L2 networks.

With a trusted Ethereum beacon chain checkpoint, it's possible to verify the
inclusion of any log entry in a Rekor log, in a way that is secure against a
compromised or malicious log operator (e.g. split-view attacks, leaked signing
keys).

## Deployments

- Scroll:
  [0x91249a54EfEFF79e333D4c9C49fcfAbE72687909](https://scrollscan.com/address/0x91249a54efeff79e333d4c9c49fcfabe72687909)
- Arbitrum One (deprecated): 0x50D49737c69eB3b6621f825CfFD2b13B9e41dDa3

## Tools

### Submit a new signed tree head for witness

```bash
export ETH_PRIVATE_KEY=<hex-encoded Ethereum private key>
cd client

# See advanced usage with -help, e.g. custom L2s, private Rekor deployments
go run github.com/losfair/rekor-evm/client/cmd/submit-signed-tree-head -live
```

### Run a proof generation server

```bash
deno run -A sigstore-scroll-witness.ts
```

### Run a proof verifier

```bash
cd sigcheck
cargo run --release

# wait for the first "buffering new finalized block" log line
# then, in another terminal
curl https://sigstore-scroll-witness.deno.dev/proof/123772604 > proof.json
curl http://localhost:2915/verify -d @proof.json -H "content-type: application/json"
```
