use clap::Parser;
use futures_util::StreamExt;
use hyper::server::accept;
use hyper::server::conn::{AddrIncoming, AddrStream};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, StatusCode};
use rcgen::generate_simple_self_signed;
use std::convert::Infallible;
use std::env;
use std::fmt::Write;
use std::future::ready;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tls_listener::TlsListener;
use tokio::fs::File;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{BytesCodec, FramedRead};

#[derive(Parser)]
/// HTTP server that serves files from a local directory (default: current directory).
struct Args {
    #[arg(default_value = "3000")]
    /// Specify the TCP port the server is listening on.
    port: u16,
    #[arg(short = 'b', long = "bind", default_value = "127.0.0.1")]
    /// Specify the IP address the server is listening on.
    address: std::net::IpAddr,
    #[arg(short, long, default_value_os_t = env::current_dir().unwrap())]
    /// Specify the directory that is accessible by clients.
    directory: PathBuf,
    #[arg(short, long, default_value_t = false)]
    /// Run server in TLS mode
    tls: bool,
    #[arg(long, default_value_t = false)]
    /// Show TLS accept errors
    tls_show_accept_errors: bool,
}

#[derive(Clone)]
struct Config {
    addr: SocketAddr,
    dir: PathBuf,
    tls: bool,
    tls_show_accept_errors: bool,
}

impl Config {
    fn new() -> Self {
        let args = Args::parse();
        let addr = SocketAddr::from((args.address, args.port));
        let dir = args.directory;
        let tls = args.tls;
        let tls_show_accept_errors = args.tls_show_accept_errors;
        Config {
            addr,
            dir,
            tls,
            tls_show_accept_errors,
        }
    }
}

struct Server {
    config: Config,
}

impl Server {
    fn new(config: Config) -> Self {
        Server { config }
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self.config.tls {
            false => self._run().await,
            true => self._run_tls().await,
        }
    }

    async fn _run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // create request handler that uses remote address
        let make_service = make_service_fn(|conn: &AddrStream| {
            let config = self.config.clone();
            let remote_addr = conn.remote_addr();
            let service = service_fn(move |req| Self::handle(config.clone(), remote_addr, req));

            async move { Ok::<_, Infallible>(service) }
        });

        let addr = self.config.addr;
        let server = hyper::Server::bind(&addr).serve(make_service);

        println!(
            "Serving HTTP on {} port {} (http://{}/)...",
            addr.ip(),
            addr.port(),
            addr
        );
        if let Err(e) = server.await {
            eprintln!("server error: {}", e);
        }
        Ok(())
    }

    async fn _run_tls(&self) -> Result<(), Box<dyn std::error::Error>> {
        // create request handler that uses remote address
        let make_service = make_service_fn(|conn: &tokio_rustls::server::TlsStream<AddrStream>| {
            let config = self.config.clone();
            let remote_addr = conn.get_ref().0.remote_addr();
            let service = service_fn(move |req| Self::handle(config.clone(), remote_addr, req));

            async move { Ok::<_, Infallible>(service) }
        });

        let addr = self.config.addr;
        let incoming =
            TlsListener::new(Self::tls_acceptor(), AddrIncoming::bind(&addr)?).filter(|conn| {
                if let Err(err) = conn {
                    if self.config.tls_show_accept_errors {
                        eprintln!("Error: {:?}", err);
                    }
                    ready(false)
                } else {
                    ready(true)
                }
            });
        let server = hyper::Server::builder(accept::from_stream(incoming)).serve(make_service);

        println!(
            "Serving HTTP on {} port {} (https://{}/)...",
            addr.ip(),
            addr.port(),
            addr
        );
        if let Err(e) = server.await {
            eprintln!("server error: {}", e);
        }
        Ok(())
    }

    async fn handle(
        config: Config,
        remote_addr: SocketAddr,
        request: hyper::Request<Body>,
    ) -> Result<hyper::Response<Body>, Infallible> {
        println!(
            "{} {} {}",
            remote_addr,
            request.method(),
            request.uri().path()
        );

        let request = Request::new(config.clone(), request);
        let handler = Handler::new(config, request);
        Ok(handler.handle().await.into())
    }

    fn tls_acceptor() -> TlsAcceptor {
        // generate certificate and private key
        let cert = generate_simple_self_signed(Vec::new()).unwrap();
        let key = PrivateKey(cert.serialize_private_key_der());
        let cert = Certificate(cert.serialize_der().unwrap());

        Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        )
        .into()
    }
}

struct Request {
    config: Config,
    request: hyper::Request<Body>,
}

impl Request {
    fn new(config: Config, request: hyper::Request<Body>) -> Self {
        Request { config, request }
    }

    fn method(&self) -> &hyper::Method {
        self.request.method()
    }

    fn local_path(&self) -> PathBuf {
        let mut path = self.uri_path();
        if path.len() > 0 {
            path = &path[1..];
        }
        self.config.dir.join(path)
    }

    fn uri_path(&self) -> &str {
        self.request.uri().path()
    }

    fn uri_path_parent(&self) -> &str {
        let path = self.uri_path();
        match path.rsplit_once("/") {
            Some(("", _right)) => "/",
            Some((left, _right)) => left,
            None => path,
        }
    }
}

struct Response {
    response: hyper::Response<Body>,
}

impl Response {
    fn new(body: Body) -> Self {
        let response = hyper::Response::new(body);
        Response { response }
    }

    fn bad_request() -> Self {
        let response = hyper::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .unwrap();
        Response { response }
    }
}

impl From<Response> for hyper::Response<Body> {
    fn from(response: Response) -> Self {
        response.response
    }
}

struct Handler {
    _config: Config, // TODO: remove?
    request: Request,
}

impl Handler {
    fn new(config: Config, request: Request) -> Self {
        Handler {
            _config: config,
            request,
        }
    }

    async fn handle(&self) -> Response {
        match self.request.method() {
            &Method::GET => self.handle_get().await,
            _ => Response::bad_request(),
        }
    }

    async fn handle_get(&self) -> Response {
        if self.is_local_dir().await {
            self.handle_get_dir().await
        } else {
            self.handle_get_file().await
        }
    }

    async fn is_local_dir(&self) -> bool {
        let path = self.request.local_path();
        match tokio::fs::metadata(path).await {
            Ok(metadata) => metadata.is_dir(),
            Err(_) => false,
        }
    }

    async fn handle_get_dir(&self) -> Response {
        let mut html = format!(
            "<!DOCTYPE html>\n\
            <html>\n\
            <head>\n\
            <title>Directory listing for {0}</title>\n\
            </head>\n\
            <body>\n\
            <h1>Directory listing for {0}</h1>\n\
            <hr>\n\
            <ul>\n\
            <li><a href={1}>..</a></li>",
            self.request.uri_path(),
            self.request.uri_path_parent(),
        );

        for (name, is_dir) in self.get_local_dir_entries().await {
            let is_dir = if is_dir { "/" } else { "" };
            match self.request.uri_path() {
                "/" => write!(html, "<li><a href=/{0}>{0}{1}</a></li>\n", name, is_dir).unwrap(),
                _ => write!(
                    html,
                    "<li><a href={0}/{1}>{1}{2}</a></li>\n",
                    self.request.uri_path(),
                    name,
                    is_dir,
                )
                .unwrap(),
            };
        }

        write!(
            html,
            "</ul>\n\
            <hr>\n\
            </body>\n\
            </html>"
        )
        .unwrap();

        let body = Body::from(html);
        Response::new(body)
    }

    async fn get_local_dir_entries(&self) -> Vec<(String, bool)> {
        let mut dir_entries = Vec::new();

        if let Ok(mut entries) = tokio::fs::read_dir(self.request.local_path()).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(filetype) = entry.file_type().await {
                    if filetype.is_symlink() {
                        continue;
                    }

                    if let Ok(name) = entry.file_name().into_string() {
                        dir_entries.push((name, filetype.is_dir()));
                    };
                }
            }
        }

        dir_entries
    }

    async fn handle_get_file(&self) -> Response {
        let path = self.request.local_path();
        match File::open(path).await {
            Ok(file) => {
                let stream = FramedRead::new(file, BytesCodec::new());
                let body = Body::wrap_stream(stream);
                Response::new(body)
            }
            _ => Response::bad_request(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new();
    Server::new(config).run().await
}
