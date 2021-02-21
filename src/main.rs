extern crate clap;
extern crate hyper;
extern crate hyper_tls;

use clap::{App, Arg};
use hyper::{Client, HeaderMap, StatusCode};
use hyper_tls::HttpsConnector;

const DOMAIN_ARGUMENT: &'static str = "DOMAIN";
const VERBOSE_ARGUMENT: &'static str = "verbose";
const WWW_ARGUMENT: &'static str = "www";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let matches = App::new(clap::crate_name!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!("\n"))
        .about(clap::crate_description!())
        .arg(
            Arg::with_name(DOMAIN_ARGUMENT)
                .help("Sets the domain to check")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name(VERBOSE_ARGUMENT)
                .long("verbose")
                .help("Enable verbose output"),
        )
        .arg(
            Arg::with_name(WWW_ARGUMENT)
                .long("www")
                .help("Check redirection from www to root"),
        )
        .get_matches();

    let verbose = matches.is_present(VERBOSE_ARGUMENT);
    let www = matches.is_present(WWW_ARGUMENT);

    // Calling .unwrap() is safe.  Clap will require DOMAIN.
    let domain = matches.value_of(DOMAIN_ARGUMENT).unwrap();

    let http_ok = match check_http(domain, &verbose).await {
        Ok(result) => result,
        Err(error) => {
            eprintln!("Error:\t{}", error);
            false
        }
    };
    let https_ok = match check_https(domain, &verbose).await {
        Ok(result) => result,
        Err(error) => {
            eprintln!("Error:\t{}", error);
            false
        }
    };

    let mut www_http_ok = true;
    let mut www_https_ok = true;
    if www {
        www_http_ok = match check_www_http(domain, &verbose).await {
            Ok(result) => result,
            Err(error) => {
                eprintln!("Error:\t{}", error);
                false
            }
        };
        www_https_ok = match check_www_https(domain, &verbose).await {
            Ok(result) => result,
            Err(error) => {
                eprintln!("Error:\t{}", error);
                false
            }
        };
    }

    if http_ok && https_ok && www_http_ok && www_https_ok {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}

async fn check_http(
    domain: &str,
    verbose: &bool,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::new();
    let uri = domain_to_http(domain, false);
    let parsed = uri.parse()?;
    let response = client.get(parsed).await?;
    let status = response.status();
    if !check_status(&uri, &status, 301, verbose) {
        return Ok(false);
    }
    let headers = response.headers();
    let expected_location = domain_to_https(domain, false);
    if !check_location_header(&uri, headers, &expected_location, verbose) {
        return Ok(false);
    }
    Ok(true)
}

async fn check_www_http(
    domain: &str,
    verbose: &bool,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::new();
    let uri = domain_to_http(domain, true);
    let parsed = uri.parse()?;
    let response = client.get(parsed).await?;
    let status = response.status();
    if !check_status(&uri, &status, 301, verbose) {
        return Ok(false);
    }
    let headers = response.headers();
    let expected_location = domain_to_https(domain, false);
    if !check_location_header(&uri, headers, &expected_location, verbose) {
        return Ok(false);
    }
    Ok(true)
}

async fn check_www_https(
    domain: &str,
    verbose: &bool,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let mut uri = String::from("https://www.");
    uri.push_str(domain);
    uri.push_str("/");
    let parsed = uri.parse()?;
    let response = client.get(parsed).await?;
    let status = response.status();
    if !check_status(&uri, &status, 301, verbose) {
        return Ok(false);
    }
    let headers = response.headers();
    let expected_location = domain_to_https(domain, false);
    if !check_location_header(&uri, headers, &expected_location, verbose) {
        return Ok(false);
    }
    Ok(true)
}

async fn check_https(
    domain: &str,
    verbose: &bool,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let uri = domain_to_https(domain, false);
    let parsed = uri.parse()?;
    let response = client.get(parsed).await?;
    let status = response.status();
    if !check_status(&uri, &status, 200, verbose) {
        return Ok(false);
    }
    Ok(true)
}

fn check_status(uri: &str, received: &StatusCode, expected: u16, verbose: &bool) -> bool {
    if *received != expected {
        eprintln!(
            "Error:\t{} responded {}. Expected {}.",
            uri, received, expected
        );
        return false;
    } else if *verbose {
        println!("OK:\t{} responded {}.", uri, received);
    }
    return true;
}

fn check_location_header(uri: &str, headers: &HeaderMap, expected: &str, verbose: &bool) -> bool {
    if !headers.contains_key("location") {
        eprintln!("Error:\t{} responded without Location header.", uri);
        return false;
    } else if *verbose {
        println!("OK:\t{} responded with a Location header.", uri);
    }
    let location = headers.get("location").unwrap().to_str().unwrap();
    if location != expected {
        eprintln!(
            "Error:\t{} responded with Location header \"{}\". Expected {}.",
            uri, location, expected
        );
        return false;
    } else if *verbose {
        println!(
            "OK:\t{} responded with Location header \"{}\".",
            uri, location
        );
    }
    return true;
}

fn domain_to_http(domain: &str, www: bool) -> String {
    let mut returned = String::from("http://");
    if www {
        returned.push_str("www.");
    }
    returned.push_str(domain);
    returned.push_str("/");
    returned
}

fn domain_to_https(domain: &str, www: bool) -> String {
    let mut returned = String::from("https://");
    if www {
        returned.push_str("www.");
    }
    returned.push_str(domain);
    returned.push_str("/");
    returned
}
