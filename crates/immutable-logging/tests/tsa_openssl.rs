//! Real, locally issued RFC3161 tokens; requires the OpenSSL CLI and library.
//! CMS verification alone does not check the request imprint, nonce, or policy.
#![cfg(feature = "tsa-cms-openssl")]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use immutable_logging::publication::{TsaCmsVerifyError, TsaTimestamp};
use std::{fs, path::Path, process::Command};

fn openssl(dir: &Path, args: &[&str]) {
    let output = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("OpenSSL CLI is required for real TSA integration tests");
    assert!(
        output.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn issue_token(dir: &Path) -> (TsaTimestamp, Vec<u8>) {
    fs::write(dir.join("message"), b"real release timestamp evidence").unwrap();
    fs::write(dir.join("serial"), "01\n").unwrap();
    fs::write(
        dir.join("tsa.cnf"),
        "[tsa]\ndefault_tsa = local\n[local]\nserial = serial\n\
         signer_cert = tsa.pem\nsigner_key = tsa.key\nsigner_digest = sha256\n\
         default_policy = 1.2.3.4.1\ndigests = sha256\n\
         accuracy = secs:1\nordering = yes\ntsa_name = yes\ness_cert_id_chain = no\n",
    )
    .unwrap();
    openssl(
        dir,
        &[
            "req",
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "tsa.key",
            "-out",
            "tsa.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Local release test TSA",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature",
            "-addext",
            "extendedKeyUsage=critical,timeStamping",
        ],
    );
    openssl(
        dir,
        &[
            "ts",
            "-query",
            "-data",
            "message",
            "-sha256",
            "-cert",
            "-out",
            "query.der",
        ],
    );
    openssl(
        dir,
        &[
            "ts",
            "-reply",
            "-config",
            "tsa.cnf",
            "-queryfile",
            "query.der",
            "-out",
            "reply.der",
        ],
    );
    openssl(
        dir,
        &[
            "ts",
            "-reply",
            "-in",
            "reply.der",
            "-token_out",
            "-out",
            "token.der",
        ],
    );
    openssl(
        dir,
        &[
            "ts",
            "-verify",
            "-in",
            "reply.der",
            "-queryfile",
            "query.der",
            "-CAfile",
            "tsa.pem",
        ],
    );
    (
        TsaTimestamp {
            tsa_url: "https://local-test.invalid".into(),
            timestamp: String::new(),
            token: STANDARD.encode(fs::read(dir.join("token.der")).unwrap()),
        },
        fs::read(dir.join("tsa.pem")).unwrap(),
    )
}

#[test]
fn real_rfc3161_cms_accepts_trusted_token_and_rejects_tampering() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let (token, roots) = issue_token(dir.path());
    let verified = token.verify_cms_signature_with_pem_roots(&roots).unwrap();
    assert!(verified.verified);
    assert!(verified.extracted_timestamp.is_some());

    let mut tampered = token.clone();
    let mut der = STANDARD.decode(&tampered.token).unwrap();
    // The final octets belong to the RSA signature; retain valid ASN.1 encoding.
    *der.last_mut().unwrap() ^= 1;
    tampered.token = STANDARD.encode(der);
    assert!(matches!(
        tampered.verify_cms_signature_with_pem_roots(&roots),
        Err(TsaCmsVerifyError::Verify(_))
    ));
    assert!(token.verify_cms_signature_with_pem_roots(b"").is_err());
    assert!(token
        .verify_cms_signature_with_pem_roots(b"not a certificate")
        .is_err());

    openssl(
        dir.path(),
        &[
            "req",
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "untrusted.key",
            "-out",
            "untrusted.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Unrelated test root",
        ],
    );
    let untrusted = fs::read(dir.path().join("untrusted.pem")).unwrap();
    assert!(matches!(
        token.verify_cms_signature_with_pem_roots(&untrusted),
        Err(TsaCmsVerifyError::Verify(_))
    ));
}

#[cfg(feature = "tsa-http-client")]
#[test]
fn real_tsa_http_transport_success_and_failure() {
    use immutable_logging::publication::PublicationService;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        thread,
        time::{Duration, Instant},
    };

    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let (_, roots) = issue_token(dir.path());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    for case in ["success", "http-error", "malformed", "rejected"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/tsa", listener.local_addr().unwrap());
        let path = dir.path().to_path_buf();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let (stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "TSA request not received");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("TSA accept: {e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut reader = BufReader::new(stream);
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                headers.push_str(&line);
                assert!(headers.len() < 16_384);
            }
            let headers = headers.to_ascii_lowercase();
            assert!(headers.starts_with("post /tsa http/1.1\r\n"));
            assert!(headers.contains("content-type: application/timestamp-query"));
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length:")
                        .map(|value| value.trim().parse().unwrap())
                })
                .unwrap();
            assert!(length < 4096);
            let mut query = vec![0; length];
            reader.read_exact(&mut query).unwrap();
            let (status, body) = match case {
                "success" => {
                    fs::write(path.join("http-query.der"), query).unwrap();
                    openssl(
                        &path,
                        &[
                            "ts",
                            "-reply",
                            "-config",
                            "tsa.cnf",
                            "-queryfile",
                            "http-query.der",
                            "-out",
                            "http-reply.der",
                        ],
                    );
                    openssl(
                        &path,
                        &[
                            "ts",
                            "-verify",
                            "-in",
                            "http-reply.der",
                            "-queryfile",
                            "http-query.der",
                            "-CAfile",
                            "tsa.pem",
                        ],
                    );
                    ("200 OK", fs::read(path.join("http-reply.der")).unwrap())
                }
                "http-error" => ("503 Service Unavailable", Vec::new()),
                "malformed" => ("200 OK", b"not DER".to_vec()),
                "rejected" => ("200 OK", vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]),
                _ => unreachable!(),
            };
            let stream = reader.get_mut();
            write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
        });
        let mut service = PublicationService::new();
        let mut publication = service.create_daily_publication(&["a".repeat(64)], 1);
        let result = runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(15),
                service.add_tsa_timestamp(&mut publication, &url),
            )
            .await
            .expect("TSA transport timed out")
        });
        server.join().unwrap();
        if case == "success" {
            result.unwrap();
            assert!(
                publication
                    .tsa_timestamp
                    .unwrap()
                    .verify_cms_signature_with_pem_roots(&roots)
                    .unwrap()
                    .verified
            );
            openssl(
                dir.path(),
                &[
                    "ts",
                    "-verify",
                    "-in",
                    "http-reply.der",
                    "-digest",
                    &publication.root_hash,
                    "-CAfile",
                    "tsa.pem",
                ],
            );
        } else {
            assert!(result.is_err(), "{case} must fail closed");
            assert!(publication.tsa_timestamp.is_none());
        }
    }
}
