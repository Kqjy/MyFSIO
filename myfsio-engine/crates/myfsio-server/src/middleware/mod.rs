mod auth;

pub use auth::auth_layer;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

pub async fn server_header(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        "server",
        crate::SERVER_HEADER.parse().unwrap(),
    );
    resp
}
