//Author Omid Ghtbi (TAO)

use hyper::{body::to_bytes, Body, Client, Request, Response, Server, Uri};
use hyper::service::{make_service_fn, service_fn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use hyper::server::conn::AddrStream;
use base64::{Engine as _, engine::{general_purpose}};

async fn proxy(
    mut req: Request<Body>,
    traffic: Arc<Mutex<HashMap<String, usize>>>,
    peer_addr: SocketAddr,
) -> Result<Response<Body>, hyper::Error> {
    println!(
        "x-forwarded-for: {:?}",
        req.headers().get("x-forwarded-for")
    );
    if let Some(auth_header) = req.headers().get("Authorization") {
        let auth_header = auth_header.to_str().unwrap();
        let auth_parts: Vec<&str> = auth_header.split(" ").collect();
        if auth_parts.len() == 2 && auth_parts[0] == "Basic" {
            //let decoded = decode(auth_parts[1]).unwrap();
            let decoded = general_purpose::STANDARD.decode(auth_parts[1]).unwrap();
            let decoded_str = String::from_utf8(decoded).unwrap();
            let user_pass: Vec<&str> = decoded_str.split(":").collect();
            if user_pass.len() == 2 {
                let username = user_pass[0];
                let password = user_pass[1];
                if username == "admin" && password == "password" {

                    // Print out the request headers
                    println!("request headers: {:?}", req.headers());

                    // Update the traffic data for the user
                    let peer_addr = peer_addr.to_string();
                    let body_bytes = to_bytes(req.body_mut()).await.unwrap();

                    // Print out the size of the request body
                    println!("request body size: {}", body_bytes.len());
                    println!("=====================");
                    let method = req.method().as_str();
                    println!("{} request with {} bytes", method, body_bytes.len());

                    let mut traffic = traffic.lock().await;
                    *traffic.entry(peer_addr).or_insert(0) += body_bytes.len();

                    // Forward the request to the destination server
                    *req.body_mut() = Body::from(body_bytes);
                    let _uri_string = format!(
                        "http://{}{}",
                        req.uri().host().unwrap(),
                        req.uri()
                            .path_and_query()
                            .map(|x| x.as_str())
                            .unwrap_or("")
                    );
                    let _uri = _uri_string.parse::<Uri>().unwrap();
                    let client = Client::new();
                    let resp = client.request(req).await?;
                    return Ok(resp);
                }
            }
        }
    }
    Ok(Response::builder()
        .status(401)
        .header("WWW-Authenticate", "Basic realm=\"Proxy\"")
        .body(Body::from("Unauthorized"))
        .unwrap())
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let traffic = Arc::new(Mutex::new(HashMap::new()));
    let make_service = {
        let traffic = traffic.clone();
        make_service_fn(move |conn: &AddrStream| {
            let remote_addr = conn.remote_addr();
            let traffic = traffic.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    proxy(req, traffic.clone(), remote_addr)
                }))
            }
        })
    };
    let server = Server::bind(&addr).serve(make_service);

    // Spawn a task to periodically print out the traffic data
    let _traffic_task = {
        let traffic = traffic.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                for (addr, bytes) in traffic.lock().await.iter() {
                    println!("{}: {} bytes", addr, bytes);
                }
            }
        })
    };

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}