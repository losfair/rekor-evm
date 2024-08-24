use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("internal error")]
    InternalError,
    #[error("unknown block number")]
    UnknownBlockNumber,
    #[error("invalid address for {0}")]
    InvalidAddress(&'static str),
    #[error("missing inclusion proof")]
    MissingInclusionProof,
    #[error("missing consistency proof")]
    MissingConsistencyProof,
    #[error("invalid consistency proof")]
    InvalidConsistencyProof,
    #[error("invalid inclusion proof")]
    InvalidInclusionProof,
    #[error("missing storage proof")]
    MissingStorageProof,
    #[error("invalid finalization proof")]
    InvalidFinalizationProof,
    #[error("invalid l2 proof")]
    InvalidL2Proof,
    #[error("invalid rekor entry body")]
    InvalidRekorEntryBody,
    #[error("entry is newer than witness")]
    EntryNewerThanWitness,
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::UnknownBlockNumber => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::InvalidAddress(_) => StatusCode::BAD_REQUEST,
            ApiError::MissingInclusionProof => StatusCode::BAD_REQUEST,
            ApiError::MissingConsistencyProof => StatusCode::BAD_REQUEST,
            ApiError::MissingStorageProof => StatusCode::BAD_REQUEST,
            ApiError::InvalidFinalizationProof
            | ApiError::InvalidL2Proof
            | ApiError::InvalidConsistencyProof
            | ApiError::InvalidInclusionProof => StatusCode::BAD_REQUEST,
            ApiError::InvalidRekorEntryBody => StatusCode::BAD_REQUEST,
            ApiError::EntryNewerThanWitness => StatusCode::BAD_REQUEST,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status(), format!("{}", self)).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        tracing::error!(?error, "internal error");
        ApiError::InternalError
    }
}
