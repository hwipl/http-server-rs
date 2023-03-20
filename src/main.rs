use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, StatusCode};
use std::convert::Infallible;
use std::env;
use std::fmt::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};

#[derive(Clone)]
struct Config {
    addr: SocketAddr,
    dir: PathBuf,
}

impl Config {
    fn new() -> Self {
        let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
        let dir = env::current_dir().unwrap();
        Config { addr, dir }
    }
}

struct Server {
    config: Config,
}

impl Server {
    fn new(config: Config) -> Self {
        Server { config }
    }

    async fn run(&self) {
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
        let html = self.get_local_dir_html().await;
        let body = Body::from(html);
        Response::new(body)
    }

    fn get_local_dir_html_start(&self) -> String {
        let html = format!(
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
        html
    }

    async fn get_local_dir_html_li(&self, html: &mut String) {
        let req_path = self.request.uri_path();
        let local_path = self.request.local_path();
        if let Ok(mut entries) = tokio::fs::read_dir(local_path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(filetype) = entry.file_type().await {
                    if filetype.is_symlink() {
                        continue;
                    }
                    let is_dir = match filetype.is_dir() {
                        true => "/",
                        false => "",
                    };
                    if let Some(name) = entry.file_name().to_str() {
                        match req_path {
                            "/" => write!(html, "<li><a href=/{0}>{0}{1}</a></li>\n", name, is_dir)
                                .unwrap(),
                            _ => write!(
                                html,
                                "<li><a href={0}/{1}>{1}{2}</a></li>\n",
                                req_path, name, is_dir
                            )
                            .unwrap(),
                        };
                    }
                }
            }
        }
    }

    fn get_local_dir_html_end(&self, html: &mut String) {
        write!(
            html,
            "</ul>\n\
        <hr>\n\
        </body>\n\
        </html>"
        )
        .unwrap();
    }

    async fn get_local_dir_html(&self) -> String {
        let mut html = self.get_local_dir_html_start();
        self.get_local_dir_html_li(&mut html).await;
        self.get_local_dir_html_end(&mut html);
        html
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
async fn main() {
    let config = Config::new();
    Server::new(config).run().await
}
