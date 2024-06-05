use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::{Extension, Router};
use serde::{Deserialize, Serialize};
use axum::routing::{get, post};
use jsonwebtoken::{decode, DecodingKey, Validation};

#[derive(Serialize, Deserialize, Clone)]
pub enum Role {
    Admin,
    User,
}

#[derive(Serialize, Deserialize, Clone)]
struct UserClaim {
    id: i32,
    username: String,
    role: Role
}

pub async fn validate_jwt(mut req: Request, next: Next) -> Result<Response, &'static str> {
    // get jwt token from request headers
    let jwt_token = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());
    
    // check if jwt token is present in the request headers or not, replace "Bearer " with empty string
    let jwt_token = match jwt_token {
        Some(jwt_token) => jwt_token.replace("Bearer ", ""),
        None => return Err("Authorization token is missing"),
    };
    // get jwt secret key from environment variable
    let jwt_secret_key = std::env::var("JWT_SECRET_KEY").unwrap();
    
    // decode jwt token and get the payload
    let token_payload = decode::<UserClaim>(
        &jwt_token,
        &DecodingKey::from_secret(jwt_secret_key.as_ref()),
        &Validation::default(),
    );
    
    // check if token is valid or not
    match token_payload {
        Ok(token_payload) => {
            // add to request extensions for later use
            req.extensions_mut().insert(token_payload.claims);
            // call next middleware/handler
            Ok(next.run(req).await)
        },
        Err(_) => Err("Invalid Token"),
    }
}

async fn login_handler() -> String {
    "Login".to_string()
}

#[axum::debug_handler]
async fn account_handler(
    Extension(user): Extension<UserClaim>,
) -> String {
    user.username
}

#[tokio::main]
async fn main() {

    // add routes here that require JWT validation
    let secure_routes = Router::new()
        .route("/account", get(account_handler))
        .layer(axum::middleware::from_fn(validate_jwt));
    
    // add routes here that do not require JWT validation
    let router = Router::new().route("/login", post(login_handler));
    
    // merge both routers to create a single router
    let app = Router::new().merge(router).merge(secure_routes);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", 3000))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
