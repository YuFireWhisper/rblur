use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
};

use acme_lib::{order::Auth, persist::FilePersist, Directory, DirectoryUrl};
use chrono::{DateTime, Utc};
use openssl::{error::ErrorStack, x509::X509};

pub fn remaining_days_of(cert: &X509) -> Result<i64, ErrorStack> {
    let not_after: DateTime<Utc> = cert.not_after()?;
    let now = Utc::now();

    Ok((not_after - now).num_days())
}

pub fn load_cert_from(path: &str) -> Result<X509, ErrorStack> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    Ok(X509::stack_from_pem(&buf)?.pop().unwrap())
}

pub fn load_private_key_from(
    path: &str,
) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, ErrorStack> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    Ok(openssl::pkey::PKey::private_key_from_pem(&buf)?)
}

pub fn save_private_key_to(
    key: &openssl::pkey::PKey<openssl::pkey::Private>,
    path: &str,
) -> Result<(), ErrorStack> {
    let mut file = File::create(path)?;
    file.write_all(&key.private_key_to_pem_pkcs8()?)?;

    Ok(())
}

pub fn create_cert(
    domain: &str,
    store_path: &str,
    email: &str,
) -> Result<Option<Vec<Auth>>, Box<dyn Error>> {
    let url = DirectoryUrl::LetsEncryptStaging;
    let persist = FilePersist::new(store_path);
    let dir = Directory::from_url(persist, url)?;
    let acc = dir.account(email)?;
    let ord_new = acc.new_order(domain, &[])?;
    if let Ok(auths) = ord_new.authorizations() {
        Ok(Some(auths))
    } else {
        Ok(None)
    }
}
