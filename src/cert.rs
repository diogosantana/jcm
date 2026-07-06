use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use url::Url;
use x509_parser::prelude::*;

use crate::cli::ChainTarget;

#[derive(Clone, Debug)]
pub struct FetchedCert {
    pub der: Vec<u8>,
    pub pem: String,
    pub fingerprint_sha256: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub is_self_signed: bool,
    pub index: usize,
}

#[derive(Clone, Debug)]
pub struct SelectedCert {
    pub keystore_alias: String,
    pub cert: FetchedCert,
    pub pem_path: Option<std::path::PathBuf>,
}

pub fn fetch_chain(url_str: &str, timeout_secs: u64) -> Result<Vec<FetchedCert>> {
    let url = Url::parse(url_str).with_context(|| format!("parse url {url_str}"))?;
    let host = url
        .host_str()
        .context("url missing host")?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let addr = format!("{host}:{port}");
    let socket_addr = resolve_socket(&addr)?;

    let config = permissive_tls_config()?;
    let server_name = ServerName::try_from(host.as_str())
        .map_err(|_| anyhow::anyhow!("invalid dns name for SNI: {host}"))?
        .to_owned();
    let mut connection = ClientConnection::new(Arc::new(config), server_name)?;
    let mut tcp = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(timeout_secs))
        .with_context(|| format!("connect to {addr}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(timeout_secs)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(timeout_secs)))?;

    let mut tls = rustls::Stream::new(&mut connection, &mut tcp);
    tls.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())?;
    tls.flush()?;
    let mut buf = [0u8; 1024];
    let _ = tls.read(&mut buf);

    let certs = connection
        .peer_certificates()
        .context("no peer certificates")?
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect::<Vec<_>>();

    certs
        .into_iter()
        .enumerate()
        .map(|(index, der)| parse_der_cert(&der, index))
        .collect()
}

fn resolve_socket(addr: &str) -> Result<SocketAddr> {
    let mut addrs = addr
        .to_socket_addrs()
        .with_context(|| format!("resolve {addr}"))?;
    addrs.next().context("no socket addresses resolved")
}

fn permissive_tls_config() -> Result<ClientConfig> {
    let verifier = Arc::new(NoVerifier);
    Ok(ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn parse_der_cert(der: &[u8], index: usize) -> Result<FetchedCert> {
    let (_, cert) = X509Certificate::from_der(der).context("parse x509 der")?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let is_self_signed = subject == issuer;
    let not_before = cert.validity().not_before.to_string();
    let not_after = cert.validity().not_after.to_string();
    let fingerprint_sha256 = fingerprint_hex(der);
    let pem = ::pem::encode(&::pem::Pem::new("CERTIFICATE", der.to_vec()));
    Ok(FetchedCert {
        der: der.to_vec(),
        pem,
        fingerprint_sha256,
        subject,
        issuer,
        not_before,
        not_after,
        is_self_signed,
        index,
    })
}

pub fn fingerprint_hex(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn select_certs(
    chain: &[FetchedCert],
    target: ChainTarget,
    alias: &str,
    prefix: &str,
) -> Result<Vec<SelectedCert>> {
    if chain.is_empty() {
        bail!("empty certificate chain");
    }
    let root_idx = chain
        .iter()
        .rposition(|c| c.is_self_signed)
        .unwrap_or(chain.len() - 1);

    let picks: Vec<(String, &FetchedCert)> = match target {
        ChainTarget::Root => {
            let cert = &chain[root_idx];
            if !cert.is_self_signed {
                tracing::warn!(
                    "no self-signed root in chain for alias {alias}; using last certificate"
                );
            }
            vec![(format!("{prefix}{alias}"), cert)]
        }
        ChainTarget::Leaf => vec![(format!("{prefix}{alias}"), &chain[0])],
        ChainTarget::Intermediate => {
            let mut out = Vec::new();
            for i in 1..root_idx {
                let n = out.len();
                out.push((format!("{prefix}{alias}-int-{n}"), &chain[i]));
            }
            out
        }
        ChainTarget::Full => chain
            .iter()
            .enumerate()
            .map(|(i, cert)| (format!("{prefix}{alias}-{i}"), cert))
            .collect(),
        idx => {
            let i = idx.index().context("chain index out of supported range")?;
            let cert = chain.get(i).with_context(|| format!("chain index {i} not available"))?;
            let alias_name = if i == 0 {
                format!("{prefix}{alias}")
            } else {
                format!("{prefix}{alias}-{i}")
            };
            vec![(alias_name, cert)]
        }
    };

    Ok(picks
        .into_iter()
        .map(|(keystore_alias, cert)| SelectedCert {
            keystore_alias,
            cert: cert.clone(),
            pem_path: None,
        })
        .collect())
}

/// Role label for a certificate in the TLS chain order (leaf first).
pub fn cert_role(cert: &FetchedCert, index: usize, chain_len: usize) -> &'static str {
    if index == 0 {
        "leaf"
    } else if cert.is_self_signed || index == chain_len - 1 {
        "root"
    } else {
        "intermediate"
    }
}

fn short_dn(dn: &str) -> String {
    for part in dn.split(',') {
        let part = part.trim();
        if let Some(cn) = part.strip_prefix("CN=") {
            return cn.to_string();
        }
    }
    dn.to_string()
}

/// Format the certificate chain as an indented tree (leaf → intermediates → root).
///
/// When `highlight` is set, indices marked with `*` match the current `--chain` selection.
pub fn format_chain_graph(
    url: &str,
    chain: &[FetchedCert],
    highlight: Option<&std::collections::HashSet<usize>>,
) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "url: {url}");
    let _ = writeln!(out, "chain ({} certificate{}):", chain.len(), if chain.len() == 1 { "" } else { "s" });
    if chain.is_empty() {
        let _ = writeln!(out, "(empty)");
        return out;
    }

    let root_idx = chain
        .iter()
        .rposition(|c| c.is_self_signed)
        .unwrap_or(chain.len().saturating_sub(1));

    for (i, cert) in chain.iter().enumerate() {
        let indent = "  ".repeat(i);
        let role = cert_role(cert, i, chain.len());
        let marker = highlight
            .filter(|h| h.contains(&i))
            .map(|_| " *")
            .unwrap_or("");
        let title = short_dn(&cert.subject);
        let _ = writeln!(
            out,
            "{indent}[{i}] {role}{marker} · {title}"
        );

        let field_indent = format!("{indent}  ");
        let _ = writeln!(out, "{field_indent}subject: {}", cert.subject);
        let _ = writeln!(out, "{field_indent}issuer:  {}", cert.issuer);
        let _ = writeln!(
            out,
            "{field_indent}valid:   {} .. {}",
            cert.not_before, cert.not_after
        );
        let _ = writeln!(out, "{field_indent}sha256: {}", cert.fingerprint_sha256);
        if cert.is_self_signed {
            let _ = writeln!(out, "{field_indent}self_signed: true");
        }

        if i < chain.len() - 1 {
            let next = &chain[i + 1];
            let issuer_matches_next = cert.issuer.trim() == next.subject.trim();
            let link_indent = format!("{indent}  ");
            if issuer_matches_next {
                let _ = writeln!(out, "{link_indent}└─ issued by →");
            } else if i + 1 == root_idx && !issuer_matches_next {
                let _ = writeln!(
                    out,
                    "{link_indent}└─ issued by → (issuer not present in chain; next cert shown)"
                );
            } else {
                let _ = writeln!(out, "{link_indent}└─ issued by →");
            }
        }
    }

    if highlight.is_some() {
        let _ = writeln!(out, "\n* = selected by --chain / entry chain setting");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_sha256_colon_separated() {
        let fp = fingerprint_hex(&[0u8; 32]);
        assert_eq!(fp.matches(':').count(), 31);
        assert_eq!(fp.len(), 32 * 3 - 1);
    }

    fn sample_cert(index: usize, subject: &str, issuer: &str, self_signed: bool) -> FetchedCert {
        FetchedCert {
            der: vec![],
            pem: String::new(),
            fingerprint_sha256: format!("FP{index}"),
            subject: subject.to_string(),
            issuer: issuer.to_string(),
            not_before: "Jan  1 00:00:00 2025 GMT".to_string(),
            not_after: "Jan  1 00:00:00 2026 GMT".to_string(),
            is_self_signed: self_signed,
            index,
        }
    }

    #[test]
    fn graph_shows_indented_chain() {
        let chain = vec![
            sample_cert(0, "CN=leaf.example.com", "CN=intermediate CA", false),
            sample_cert(1, "CN=intermediate CA", "CN=root CA", false),
            sample_cert(2, "CN=root CA", "CN=root CA", true),
        ];
        let graph = format_chain_graph("https://example.com", &chain, None);
        assert!(graph.contains("url: https://example.com"));
        assert!(graph.contains("[0] leaf"));
        assert!(graph.contains("[1] intermediate"));
        assert!(graph.contains("[2] root"));
        assert!(graph.contains("issued by"));
        assert!(graph.contains("  [1]"));
        assert!(graph.contains("    subject:"));
    }

    #[test]
    fn graph_marks_highlighted_indices() {
        let chain = vec![
            sample_cert(0, "CN=a", "CN=b", false),
            sample_cert(1, "CN=b", "CN=b", true),
        ];
        let mut h = std::collections::HashSet::new();
        h.insert(1);
        let graph = format_chain_graph("https://x.com", &chain, Some(&h));
        assert!(graph.contains("[1] root *"));
        assert!(graph.contains("* = selected"));
    }
}
