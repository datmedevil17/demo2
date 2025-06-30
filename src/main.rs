use actix_web::{middleware::Logger, web, App, HttpResponse, HttpServer, Result};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    system_instruction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::{
    instruction::{initialize_mint2, mint_to_checked, transfer_checked},
    ID as TOKEN_PROGRAM_ID,
};
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose};

// Response types
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: &str) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message.to_string()),
        }
    }
}

// Data structures for endpoints
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<SendTokenAccountInfo>,
    instruction_data: String,
}

// Helper functions
fn validate_pubkey(key_str: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(key_str).map_err(|_| "Invalid public key format".to_string())
}

fn decode_secret_key(secret_str: &str) -> Result<Keypair, String> {
    let decoded = bs58::decode(secret_str)
        .into_vec()
        .map_err(|_| "Invalid secret key format")?;
    
    if decoded.len() != 64 {
        return Err("Secret key must be 64 bytes".to_string());
    }
    
    // Convert Vec<u8> to [u8; 64] and create keypair
    let bytes: [u8; 64] = decoded.try_into()
        .map_err(|_| "Failed to convert secret key")?;
    
    Keypair::from_bytes(&bytes).map_err(|e| format!("Invalid keypair: {}", e))
}

// Endpoint handlers
async fn generate_keypair() -> Result<HttpResponse> {
    let keypair = Keypair::new();
    let response = KeypairResponse {
        pubkey: keypair.pubkey().to_string(),
        secret: bs58::encode(keypair.to_bytes()).into_string(),
    };
    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    let mint_authority = match validate_pubkey(&req.mint_authority) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let mint = match validate_pubkey(&req.mint) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let instruction = initialize_mint2(
        &TOKEN_PROGRAM_ID,
        &mint,
        &mint_authority,
        Some(&mint_authority),
        req.decimals,
    ).map_err(|e| format!("Failed to create mint instruction: {}", e));

    match instruction {
        Ok(ix) => {
            let accounts: Vec<AccountInfo> = ix.accounts.iter().map(|acc| AccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }).collect();

            let response = InstructionResponse {
                program_id: ix.program_id.to_string(),
                accounts,
                instruction_data: general_purpose::STANDARD.encode(&ix.data),
            };
            Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
        }
        Err(e) => Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    }
}

async fn mint_token(req: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    let mint = match validate_pubkey(&req.mint) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let destination = match validate_pubkey(&req.destination) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let authority = match validate_pubkey(&req.authority) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let instruction = mint_to_checked(
        &TOKEN_PROGRAM_ID,
        &mint,
        &destination,
        &authority,
        &[&authority],
        req.amount,
        9, // Default decimals
    ).map_err(|e| format!("Failed to create mint instruction: {}", e));

    match instruction {
        Ok(ix) => {
            let accounts: Vec<AccountInfo> = ix.accounts.iter().map(|acc| AccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }).collect();

            let response = InstructionResponse {
                program_id: ix.program_id.to_string(),
                accounts,
                instruction_data: general_purpose::STANDARD.encode(&ix.data),
            };
            Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
        }
        Err(e) => Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    }
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    if req.message.is_empty() || req.secret.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Missing required fields")));
    }

    let keypair = match decode_secret_key(&req.secret) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let signature = keypair.sign_message(req.message.as_bytes());
    
    let response = SignMessageResponse {
        signature: general_purpose::STANDARD.encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: req.message.clone(),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    let pubkey = match validate_pubkey(&req.pubkey) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid signature format"))),
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid signature"))),
    };

    let is_valid = signature.verify(&pubkey.to_bytes(), req.message.as_bytes());

    let response = VerifyMessageResponse {
        valid: is_valid,
        message: req.message.clone(),
        pubkey: req.pubkey.clone(),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    let from = match validate_pubkey(&req.from) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let to = match validate_pubkey(&req.to) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    if req.lamports == 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Amount must be greater than 0")));
    }

    let instruction = system_instruction::transfer(&from, &to, req.lamports);

    let response = SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    let mint = match validate_pubkey(&req.mint) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let owner = match validate_pubkey(&req.owner) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let destination = match validate_pubkey(&req.destination) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    if req.amount == 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Amount must be greater than 0")));
    }

    // Get associated token accounts
    let source_ata = get_associated_token_address(&owner, &mint);
    let dest_ata = get_associated_token_address(&destination, &mint);

    let instruction = transfer_checked(
        &TOKEN_PROGRAM_ID,
        &source_ata,
        &mint,
        &dest_ata,
        &owner,
        &[&owner],
        req.amount,
        9, // Default decimals
    ).map_err(|e| format!("Failed to create transfer instruction: {}", e));

    match instruction {
        Ok(ix) => {
            let accounts: Vec<SendTokenAccountInfo> = ix.accounts.iter().map(|acc| SendTokenAccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
            }).collect();

            let response = SendTokenResponse {
                program_id: ix.program_id.to_string(),
                accounts,
                instruction_data: general_purpose::STANDARD.encode(&ix.data),
            };
            Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
        }
        Err(e) => Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    println!("🚀 Starting Solana HTTP Server on http://localhost:8080");

    HttpServer::new(|| {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            .wrap(Logger::default())
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}