mod error;
mod helpers;
mod rekor;
mod types;

use std::{
    collections::VecDeque,
    str::FromStr,
    sync::{Arc, Mutex},
};

use alloy_primitives::keccak256;
use alloy_primitives::{Address, B256, U256};
use anyhow::Context;
use axum::{
    extract::State,
    http::HeaderValue,
    response::{IntoResponse, Response},
    Json, Router,
};
use base64::Engine;
use clap::Parser;
use error::ApiError;
use helios_common::types::Block;
use helios_config::Network;
use helios_consensus::{database::ConfigDB, rpc::nimbus_rpc::NimbusRpc, ConsensusClient};
use hex::ToHex;
use p256::{
    elliptic_curve::{sec1::Coordinates, sec1::ToEncodedPoint},
    PublicKey,
};
use rekor::{
    verify_consistency_proof, verify_inclusion_proof, verify_tree_head_signature,
    CanonicalInclusionProof,
};
use serde::Serialize;
use tokio::sync::watch::Receiver;
use types::FullProof;

const SCROLL_L1_PROXY: &str = "0xa13BAF47339d63B743e7Da8741db5456DAc1E556";
const REKOR_WITNESS_ON_SCROLL: &str = "0x91249a54EfEFF79e333D4c9C49fcfAbE72687909";
const REKOR_PUBLIC_KEY: (&str, &str) = (
    "D86D98FB6B5A6DD4D5E41706881231D1AF5F005C2B9016E62D21AD92CE0BDEA5",
    "FAC98634CEE7C19E10BC52BFE2CB9E468563FFF40FDB6362E10B7D0CF7E458B7",
);

/// Sigstore + Scroll signature validator server
#[derive(clap::Parser)]
struct Args {
    /// Ethereum beacon block root to use as checkpoint
    #[arg(
        long,
        env = "SIGCHECK_CHECKPOINT",
        default_value = "0x7b455055f8deb9ed45513c2c629ce3c1782fad0292eb35a1cd17f916e21f9a90"
    )]
    checkpoint: String,

    /// Ethereum consensus RPC endpoint
    #[arg(
        long,
        env = "SIGCHECK_CONSENSUS_RPC",
        default_value = "https://www.lightclientdata.org"
    )]
    consensus_rpc: String,

    /// HTTP listen address
    #[arg(long, env = "SIGCHECK_LISTEN", default_value = "127.0.0.1:2915")]
    listen: String,
}

struct AppState {
    finalized_block_recv: Receiver<Option<Block>>,
    recent_finalized_blocks: Mutex<VecDeque<Block>>,
    rekor_public_key: PublicKey,
}

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }

    tracing_subscriber::fmt::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let ret = rt.block_on(async_main());
    if let Err(error) = ret {
        tracing::error!(?error, "exiting with error");
        std::process::exit(1);
    }
}

async fn async_main() -> anyhow::Result<()> {
    zktrie::init_hash_scheme_simple(helpers::poseidon_hash_scheme);

    let args = Args::parse();

    let mut checkpoint = [0u8; 32];
    faster_hex::hex_decode(
        args.checkpoint
            .strip_prefix("0x")
            .unwrap_or(args.checkpoint.as_str())
            .as_bytes(),
        &mut checkpoint,
    )
    .with_context(|| "invalid checkpoint hex str")?;
    let base = Network::MAINNET.to_base_config();
    let config = helios_config::Config {
        checkpoint: Some(checkpoint.to_vec()),
        chain: base.chain,
        forks: base.forks,
        max_checkpoint_age: 1209600, // 14 days
        ..Default::default()
    };
    let config = Arc::new(config);

    // decode Rekor public key
    let jwk = {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];

        faster_hex::hex_decode(REKOR_PUBLIC_KEY.0.as_bytes(), &mut x).unwrap();
        faster_hex::hex_decode(REKOR_PUBLIC_KEY.1.as_bytes(), &mut y).unwrap();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y);

        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        })
        .to_string()
    };

    let rekor_public_key =
        PublicKey::from_jwk_str(&jwk).with_context(|| "failed to load rekor public key")?;

    let mut client =
        ConsensusClient::<NimbusRpc, ConfigDB>::new(&args.consensus_rpc, config.clone())
            .map_err(|e| anyhow::anyhow!("failed to create consensus client: {:?}", e))?;
    tracing::info!("consensus client created");

    let mut blocks = client
        .finalized_block_recv
        .take()
        .with_context(|| "missing finalized_block_recv")?;

    // wait for first block
    loop {
        if blocks.borrow().is_some() {
            break;
        }
        blocks
            .changed()
            .await
            .with_context(|| "block receiver broken")?;
    }

    let state = Arc::new(AppState {
        finalized_block_recv: blocks,
        recent_finalized_blocks: Mutex::new(VecDeque::new()),
        rekor_public_key,
    });

    let state_clone = state.clone();
    tokio::spawn(async move {
        let mut rx = state_clone.finalized_block_recv.clone();
        loop {
            let mut block = rx.borrow().as_ref().unwrap().clone();
            {
                let mut recent = state_clone.recent_finalized_blocks.lock().unwrap();
                while recent.len() >= 10 {
                    recent.pop_front();
                }
                if recent.is_empty() || recent.back().unwrap().number < block.number {
                    let block_hash: String = block.hash.encode_hex();
                    block.transactions = Default::default();
                    tracing::info!(
                        block_number = block.number.as_limbs()[0],
                        block_hash,
                        "buffering new finalized block"
                    );
                    recent.push_back(block);
                }
            }
            tokio::select! {
                biased;
                x = rx.changed() => {
                    x.expect("block receiver broken");
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(600)) => {
                    panic!("watchdog: no finalized block has been received in 10 minutes");
                }
            }
        }
    });

    let app = Router::new()
        // `GET /` goes to `root`
        .route("/finalized", axum::routing::get(finalized_handler))
        .route("/verify", axum::routing::post(verify_handler))
        .fallback(fallback_handler)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .with_context(|| "failed to listen")?;
    tracing::info!(listen = args.listen, "started listener");
    axum::serve(listener, app)
        .await
        .with_context(|| "server exited")?;

    Ok(())
}

async fn finalized_handler(State(st): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let block = serde_json::to_string(
        &st.recent_finalized_blocks
            .lock()
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
    )
    .with_context(|| "failed to serialize block")?;
    let mut res = Response::new(block);
    res.headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    Ok(res.into_response())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedEntry {
    body: sigstore::rekor::models::log_entry::Body,
    unverified_attestation: Option<serde_json::Value>,
}

async fn verify_handler(
    State(st): State<Arc<AppState>>,
    req: Json<FullProof>,
) -> Result<Json<VerifiedEntry>, ApiError> {
    let block = st
        .recent_finalized_blocks
        .lock()
        .unwrap()
        .iter()
        .find(|x| x.number == req.0.block_number)
        .cloned();
    let Some(block) = block else {
        return Err(ApiError::UnknownBlockNumber);
    };

    if let Err(error) = req.0.finalization_proof.verify(block.state_root) {
        tracing::error!(?error, "failed to verify finalization proof");
        return Err(ApiError::InvalidFinalizationProof);
    }

    if req.0.finalization_proof.address != Address::from_str(SCROLL_L1_PROXY).unwrap() {
        return Err(ApiError::InvalidAddress("scroll l1 proxy"));
    }

    let Some(batch_index) = req
        .0
        .finalization_proof
        .storage_proof
        .iter()
        .find(|x| x.key == U256::from(0x9c))
        .map(|x| x.value)
    else {
        return Err(ApiError::MissingStorageProof);
    };

    let l2_state_root_key = U256::from_be_bytes(
        keccak256(
            [
                &batch_index.to_be_bytes::<32>()[..],
                &U256::from(0x9e).to_be_bytes::<32>()[..],
            ]
            .concat(),
        )
        .0,
    );
    let Some(l2_state_root) = req
        .0
        .finalization_proof
        .storage_proof
        .iter()
        .find(|x| x.key == l2_state_root_key)
        .map(|x| B256::from(x.value.to_be_bytes()))
    else {
        return Err(ApiError::MissingStorageProof);
    };

    if let Err(error) = req.0.l2_proof.verify_l2(l2_state_root) {
        tracing::error!(?error, ?l2_state_root, "failed to verify l2 proof");
        return Err(ApiError::InvalidL2Proof);
    }

    if req.0.l2_proof.address != Address::from_str(REKOR_WITNESS_ON_SCROLL).unwrap() {
        return Err(ApiError::InvalidAddress("rekor witness on scroll"));
    }

    let Some(inclusion_proof) = req.0.rekor_entry.verification.inclusion_proof else {
        return Err(ApiError::MissingInclusionProof);
    };

    let inclusion_proof = CanonicalInclusionProof::decode(&inclusion_proof).map_err(|error| {
        tracing::error!(?error, "failed to decode inclusion proof");
        ApiError::InvalidInclusionProof
    })?;

    let rekor_public_key = st.rekor_public_key.to_encoded_point(false);
    let Coordinates::Uncompressed { x, y } = rekor_public_key.coordinates() else {
        panic!("failed to get coordinates from rekor public key");
    };

    let storage_key_0 =
        U256::from_be_bytes(
            keccak256(
                [
                    inclusion_proof.origin.as_bytes(),
                    &keccak256([&y[..], &keccak256([&x[..], &[0u8; 32]].concat()).0[..]].concat())
                        .0[..],
                ]
                .concat(),
            )
            .0,
        );
    let storage_key_1 = storage_key_0 + U256::from(1);

    let Some(witnessed_tree_size) = req
        .0
        .l2_proof
        .storage_proof
        .iter()
        .find(|x| x.key == storage_key_0)
        .map(|x| x.value)
    else {
        return Err(ApiError::MissingStorageProof);
    };

    let Some(witnessed_tree_root) = req
        .0
        .l2_proof
        .storage_proof
        .iter()
        .find(|x| x.key == storage_key_1)
        .map(|x| x.value)
    else {
        return Err(ApiError::MissingStorageProof);
    };

    let Ok(witnessed_tree_size) = u64::try_from(witnessed_tree_size) else {
        tracing::error!(%witnessed_tree_size, "witnessed tree size out of bounds");
        return Err(ApiError::InternalError);
    };

    let witnessed_tree_root = witnessed_tree_root.to_be_bytes::<32>();

    if witnessed_tree_root != inclusion_proof.root_hash
        || witnessed_tree_size != inclusion_proof.tree_size as u64
    {
        let Some(consistency_proof) = &req.0.consistency_proof else {
            return Err(ApiError::MissingConsistencyProof);
        };

        if let Err(error) = verify_consistency_proof(
            consistency_proof,
            witnessed_tree_root,
            inclusion_proof.root_hash,
            witnessed_tree_size,
            inclusion_proof.tree_size as u64,
        ) {
            tracing::error!(?error, "failed to verify consistency proof");
            return Err(ApiError::InvalidConsistencyProof);
        }
    }

    if inclusion_proof.log_index >= witnessed_tree_size {
        return Err(ApiError::EntryNewerThanWitness);
    }

    let body =
        verify_inclusion_proof(&req.0.rekor_entry.body, &inclusion_proof).map_err(|error| {
            tracing::error!(?error, "failed to verify inclusion proof");
            ApiError::InvalidInclusionProof
        })?;

    // Independently verify tree head signature
    verify_tree_head_signature(&st.rekor_public_key, &inclusion_proof, "rekor.sigstore.dev")
        .map_err(|error| {
            tracing::error!(?error, "failed to verify tree head signature");
            ApiError::InvalidInclusionProof
        })?;

    let body = serde_json::from_slice::<'_, sigstore::rekor::models::log_entry::Body>(&body)
        .map_err(|error| {
            tracing::error!(?error, "failed to parse rekor entry body");
            ApiError::InvalidRekorEntryBody
        })?;

    Ok(Json(VerifiedEntry {
        body,
        unverified_attestation: req.0.rekor_entry.attestation,
    }))
}

async fn fallback_handler() -> ApiError {
    ApiError::NotFound
}
