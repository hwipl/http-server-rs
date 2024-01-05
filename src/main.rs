use clap::Parser;
use futures_util::TryStreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::service::service_fn;
use hyper::{Method, StatusCode};
use hyper_util::rt::TokioIo;
use hyper_util::server;
use rcgen::generate_simple_self_signed;
use rustls_pemfile::{read_one, Item};
use std::convert::Infallible;
use std::env;
use std::fmt::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tls_listener::TlsListener;
use tokio::fs::File;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;

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
    #[arg(long)]
    /// Load TLS certificate from file
    tls_cert_file: Option<String>,
    #[arg(long)]
    /// Load TLS key from file
    tls_key_file: Option<String>,
    #[arg(long, default_value_t = false)]
    /// Show TLS accept errors
    tls_show_accept_errors: bool,
}

struct Config {
    addr: SocketAddr,
    dir: PathBuf,
    tls: bool,
    tls_cert: CertificateDer<'static>,
    tls_key: PrivateKeyDer<'static>,
    tls_show_accept_errors: bool,
}

impl Config {
    fn new() -> Self {
        let args = Args::parse();
        let addr = SocketAddr::from((args.address, args.port));
        let dir = args.directory;
        let tls = args.tls;
        let (tls_key, tls_cert) =
            if let (Some(key_file), Some(cert_file)) = (args.tls_key_file, args.tls_cert_file) {
                Self::load_key_and_cert(key_file, cert_file)
            } else {
                Self::generate_key_and_cert()
            };
        let tls_show_accept_errors = args.tls_show_accept_errors;

        Config {
            addr,
            dir,
            tls,
            tls_cert,
            tls_key,
            tls_show_accept_errors,
        }
    }

    fn load_key_and_cert(
        key_file: String,
        cert_file: String,
    ) -> (PrivateKeyDer<'static>, CertificateDer<'static>) {
        let key = Self::load_key_file(key_file).unwrap();
        let cert = Self::load_cert_file(cert_file).unwrap();

        (key, cert)
    }

    fn load_key_file(file: String) -> std::io::Result<PrivateKeyDer<'static>> {
        // open file
        let f = std::fs::File::open(file)?;
        let mut reader = std::io::BufReader::new(f);

        // parse file
        for item in std::iter::from_fn(|| read_one(&mut reader).transpose()) {
            match item.unwrap() {
                Item::Pkcs1Key(key) => return Ok(key.into()),
                Item::Pkcs8Key(key) => return Ok(key.into()),
                Item::Sec1Key(key) => return Ok(key.into()),
                _ => (),
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "no key found in file",
        ))
    }

    fn load_cert_file(file: String) -> std::io::Result<CertificateDer<'static>> {
        // open file
        let f = std::fs::File::open(file)?;
        let mut reader = std::io::BufReader::new(f);

        // parse file
        for item in std::iter::from_fn(|| read_one(&mut reader).transpose()) {
            match item.unwrap() {
                Item::X509Certificate(cert) => {
                    return Ok(cert);
                }
                _ => (),
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "no cert found in file",
        ))
    }

    fn generate_key_and_cert() -> (PrivateKeyDer<'static>, CertificateDer<'static>) {
        let cert = generate_simple_self_signed(Vec::new()).unwrap();
        let tls_key = cert.serialize_private_key_der();
        let tls_cert = cert.serialize_der().unwrap();

        (PrivatePkcs8KeyDer::from(tls_key).into(), tls_cert.into())
    }
}

struct Server {
    config: Arc<Config>,
}

impl Server {
    fn new(config: Config) -> Self {
        Server {
            config: config.into(),
        }
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self.config.tls {
            false => self._run().await,
            true => self._run_tls().await,
        }
    }

    async fn _run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // create listener
        let addr = self.config.addr;
        let listener = TcpListener::bind(addr).await?;

        println!(
            "Serving HTTP on {} port {} (http://{}/)...",
            addr.ip(),
            addr.port(),
            addr
        );

        // main loop
        loop {
            // get connection from listener
            let (stream, remote_addr) = listener.accept().await?;
            let io = TokioIo::new(stream);

            // set service function
            let config = self.config.clone();
            let service = move |req: hyper::Request<hyper::body::Incoming>| {
                let config = config.clone();
                async move { Self::handle(config, remote_addr, req).await }
            };

            // handle connection
            tokio::task::spawn(async move {
                if let Err(err) =
                    server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(io, service_fn(service))
                        .await
                {
                    eprintln!("server error: {}", err);
                }
            });
        }
    }

    async fn _run_tls(&self) -> Result<(), Box<dyn std::error::Error>> {
        // create listener
        let addr = self.config.addr;
        let mut listener = TlsListener::new(self.tls_acceptor(), TcpListener::bind(addr).await?);

        println!(
            "Serving HTTP on {} port {} (https://{}/)...",
            addr.ip(),
            addr.port(),
            addr
        );

        // main loop
        loop {
            // get connection from listener
            let (stream, remote_addr) = match listener.accept().await {
                Ok((stream, remote_addr)) => (stream, remote_addr),
                Err(err) => {
                    if self.config.tls_show_accept_errors {
                        eprintln!("Error: {:?}", err);
                    }
                    continue;
                }
            };
            let io = TokioIo::new(stream);

            // set service function
            let config = self.config.clone();
            let service = move |req: hyper::Request<hyper::body::Incoming>| {
                let config = config.clone();
                async move { Self::handle(config, remote_addr, req).await }
            };

            // handle connection
            tokio::task::spawn(async move {
                if let Err(err) =
                    server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(io, service_fn(service))
                        .await
                {
                    eprintln!("server error: {}", err);
                }
            });
        }
    }

    async fn handle(
        config: Arc<Config>,
        remote_addr: SocketAddr,
        request: hyper::Request<hyper::body::Incoming>,
    ) -> Result<hyper::Response<BoxBody<Bytes, std::io::Error>>, Infallible> {
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

    fn tls_acceptor(&self) -> TlsAcceptor {
        let cert = self.config.tls_cert.clone();
        let key = self.config.tls_key.clone_key();

        Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.into()], key)
                .unwrap(),
        )
        .into()
    }
}

struct Request {
    config: Arc<Config>,
    request: hyper::Request<hyper::body::Incoming>,
}

impl Request {
    fn new(config: Arc<Config>, request: hyper::Request<hyper::body::Incoming>) -> Self {
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
    response: hyper::Response<BoxBody<Bytes, std::io::Error>>,
}

impl Response {
    fn new(body: BoxBody<Bytes, std::io::Error>) -> Self {
        let response = hyper::Response::new(body);
        Response { response }
    }

    fn bad_request() -> Self {
        let response = hyper::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Empty::new().map_err(|e| match e {}).boxed())
            .unwrap();
        Response { response }
    }
}

impl From<Response> for hyper::Response<BoxBody<Bytes, std::io::Error>> {
    fn from(response: Response) -> Self {
        response.response
    }
}

struct Handler {
    _config: Arc<Config>, // TODO: remove?
    request: Request,
}

impl Handler {
    fn new(config: Arc<Config>, request: Request) -> Self {
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

        let body = Full::from(html);
        Response::new(body.map_err(|e| match e {}).boxed())
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
                let stream = ReaderStream::new(file);
                let body = StreamBody::new(stream.map_ok(Frame::data));
                Response::new(body.boxed())
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
