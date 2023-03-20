use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, StatusCode};
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
        request: Request<Body>,
    ) -> Result<Response<Body>, Infallible> {
        println!(
            "{} {} {}",
            remote_addr,
            request.method(),
            request.uri().path()
        );

        let handler = Handler::new(config, request);
        handler.handle().await
    }
}

struct Handler {
    config: Config,
    request: Request<Body>,
}

impl Handler {
    fn new(config: Config, request: Request<Body>) -> Self {
        Handler { config, request }
    }

    async fn handle(&self) -> Result<Response<Body>, Infallible> {
        match self.request.method() {
            &Method::GET => self.handle_get().await,
            _ => self.bad_request(),
        }
    }

    fn bad_request(&self) -> Result<Response<Body>, Infallible> {
        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .unwrap())
    }

    async fn handle_get(&self) -> Result<Response<Body>, Infallible> {
        if self.is_local_dir().await {
            self.handle_get_dir().await
        } else {
            self.handle_get_file().await
        }
    }

    async fn is_local_dir(&self) -> bool {
        let path = self.get_local_path();
        match tokio::fs::metadata(path).await {
            Ok(metadata) => metadata.is_dir(),
            Err(_) => false,
        }
    }

    async fn handle_get_dir(&self) -> Result<Response<Body>, Infallible> {
        let html = self.get_local_dir_html().await;
        let body = Body::from(html);
        Ok(Response::new(body))
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
            self.request.uri().path(),
            self.get_uri_path_parent(),
        );
        html
    }

    async fn get_local_dir_html_li(&self, html: &mut String) {
        let req_path = self.request.uri().path();
        let local_path = self.get_local_path();
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

    async fn handle_get_file(&self) -> Result<Response<Body>, Infallible> {
        let path = self.get_local_path();
        match File::open(path).await {
            Ok(file) => {
                let stream = FramedRead::new(file, BytesCodec::new());
                let body = Body::wrap_stream(stream);
                Ok(Response::new(body))
            }
            _ => self.bad_request(),
        }
    }

    fn get_local_path(&self) -> PathBuf {
        let mut path = self.request.uri().path();
        if path.len() > 0 {
            path = &path[1..];
        }
        self.config.dir.join(path)
    }

    fn get_uri_path_parent(&self) -> &str {
        let path = self.request.uri().path();
        match path.rsplit_once("/") {
            Some(("", _right)) => "/",
            Some((left, _right)) => left,
            None => path,
        }
    }
}

#[tokio::main]
async fn main() {
    let config = Config::new();
    Server::new(config).run().await
}
