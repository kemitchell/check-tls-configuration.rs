extern crate clap;
extern crate hyper;
extern crate hyper_tls;

use clap::{App, Arg};
use hyper::Client;
use hyper_tls::HttpsConnector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let matches = App::new("check-tls-configuration")
        .version("0.0.0")
        .author("Kyle E. Mitchell <kyle@kemitchell.com>")
        .about("checks the TLS configuration for a WWW domain")
        .arg(
            Arg::with_name("DOMAIN")
                .help("Sets the domain to check")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .help("Enable verbose output"),
        )
        .get_matches();

    let verbose = matches.is_present("verbose");

    // Calling .unwrap() is safe.  Clap will require DOMAIN.
    let domain = matches.value_of("DOMAIN").unwrap();

    let http_ok = match check_http(domain, &verbose).await {
        Ok(result) => result,
        Err(error) => {
            eprintln!("Error: {}", error);
            false
        }
    };
    let https_ok = match check_https(domain, &verbose).await {
        Ok(result) => result,
        Err(error) => {
            eprintln!("Error: {}", error);
            false
        }
    };

    if http_ok && https_ok {
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
    let mut uri = String::from("http://");
    uri.push_str(domain);
    uri.push_str("/");
    let parsed = uri.parse()?;
    let response = client.get(parsed).await?;
    let status = response.status();
    if status != 301 {
        eprintln!("Error: {} responded {}. Expected 301.", uri, status);
        return Ok(false);
    } else if *verbose {
        println!("OK: {} responded {}.", uri, status);
    }
    let headers = response.headers();
    if !headers.contains_key("location") {
        eprintln!("Error: {} responded without Location header.", uri);
        return Ok(false);
    } else if *verbose {
        println!("OK: {} responded with a Location header.", uri);
    }
    let location = headers.get("location").unwrap().to_str().unwrap();
    let mut expected_location = String::from("https://");
    expected_location.push_str(domain);
    expected_location.push_str("/");
    if location != expected_location {
        eprintln!(
            "Error: {} responded with Location header \"{}\". Expected {}.",
            uri, location, expected_location
        );
        return Ok(false);
    } else if *verbose {
        println!(
            "OK: {} responded with Location header \"{}\".",
            uri, location
        );
    }
    Ok(true)
}

async fn check_https(
    domain: &str,
    verbose: &bool,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let mut uri = String::from("https://");
    uri.push_str(domain);
    uri.push_str("/");
    let parsed = uri.parse()?;
    let response = client.get(parsed).await?;
    let status = response.status();
    if status != 200 {
        eprintln!("Error: {} responded {}. Expected 200.", uri, status);
        Ok(false)
    } else {
        if *verbose {
            println!("OK: {} responded {}.", uri, status);
        }
        Ok(true)
    }
}
