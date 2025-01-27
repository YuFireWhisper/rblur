use std::{any::TypeId, error::Error, path::Path, sync::atomic::{AtomicPtr, Ordering}};

use acme_lib::order::Auth;
use openssl::{pkey::PKey, rsa::Rsa};

use crate::{
    core::{config::{command::Command, config_context::ConfigContext, config_file_parser::parse_context_of}, ssl_certificate::{create_cert, load_cert_from, remaining_days_of, save_private_key_to}}, http::http_server::{get_server_ctx, HttpServerContext}, register_commands
};

register_commands!(
    Command::new("ssl", vec![TypeId::of::<HttpServerContext>()], handle_create_ssl),
    Command::new(
        "ssl_email",
        vec![TypeId::of::<HttpSSLContext>()],
        handle_set_ssl_email
    ),
    Command::new(
        "ssl_store_path",
        vec![TypeId::of::<HttpSSLContext>()],
        handle_set_ssl_store_path
    ),
    Command::new(
        "ssl_cert_key_path",
        vec![TypeId::of::<HttpSSLContext>()],
        handle_set_ssl_cert_key_path
    ),
    Command::new(
        "ssl_cert_path",
        vec![TypeId::of::<HttpSSLContext>()],
        handle_set_ssl_cert_path
    ),
    Command::new(
        "ssl_auto_renew",
        vec![TypeId::of::<HttpSSLContext>()],
        handle_set_ssl_auto_renew
    ),
    Command::new("ssl_renew_day", vec![TypeId::of::<HttpSSLContext>()], handle_set_ssl_renew_day),
    Command::new("ssl_domain", vec![TypeId::of::<HttpSSLContext>()], handle_set_ssl_domain),
);

pub fn handle_create_ssl(ctx: &mut ConfigContext) {
    let enable = ctx.current_cmd_args.get(0).unwrap().to_lowercase();
    const ENABLE: [&str; 2] = ["on", "true"];
    const DISABLE: [&str; 1] = ["off"];

    if DISABLE.contains(&enable.as_str()) {
        return;
    }
    if ENABLE.contains(&enable.as_str()) {
        let prev_ctx = ctx.current_ctx.take();
        let prev_block_type_id = ctx.current_block_type_id.take();

        let ssl_ctx = Box::new(HttpSSLContext::new());
        
        ctx.current_ctx = Some(AtomicPtr::new(Box::into_raw(ssl_ctx) as *mut u8));
        ctx.current_block_type_id = Some(TypeId::of::<HttpSSLContext>());

        parse_context_of(ctx).expect("Error at handle_create_ssl");
        
        ctx.current_ctx = prev_ctx;
        ctx.current_block_type_id = prev_block_type_id;
    }

    panic!("Invalid value for ssl: {}", enable);
}

pub fn handle_set_ssl_email(ctx: &mut ConfigContext) {
    let email = ctx.current_cmd_args.get(0).unwrap();
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.email = email.to_string();
    }
}

pub fn handle_set_ssl_store_path(ctx: &mut ConfigContext) {
    let path = ctx.current_cmd_args.get(0).unwrap();
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.store_path = path.to_string();
    }
}

pub fn handle_set_ssl_cert_key_path(ctx: &mut ConfigContext) {
    let path = ctx.current_cmd_args.get(0).unwrap();
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.cert_key_path = path.to_string();
    }
}

pub fn handle_set_ssl_cert_path(ctx: &mut ConfigContext) {
    let path = ctx.current_cmd_args.get(0).unwrap();
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.cert_path = path.to_string();
    }
}

pub fn handle_set_ssl_auto_renew(ctx: &mut ConfigContext) {
    let enable = ctx.current_cmd_args.get(0).unwrap().to_lowercase();
    const ENABLE: [&str; 2] = ["on", "true"];
    const DISABLE: [&str; 1] = ["off"];

    if DISABLE.contains(&enable.as_str()) {
        return;
    }
    if ENABLE.contains(&enable.as_str()) {
        if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
            ssl_ctx.auto_renew = true;
        }
    }

    panic!("Invalid value for ssl_auto_renew: {}", enable);
}

pub fn handle_set_ssl_renew_day(ctx: &mut ConfigContext) {
    let days = ctx.current_cmd_args.get(0).unwrap().parse::<i64>().unwrap();
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.renew_days = days;
    }
}

pub fn handle_set_ssl_domain(ctx: &mut ConfigContext) {
    let domain = ctx.current_cmd_args.get(0).unwrap();
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.domain = domain.to_string();
    }
}

fn get_ssl_ctx(ctx: &ConfigContext) -> Option<&HttpSSLContext> {
    if let Some(ssl_ctx_ptr) = &ctx.current_ctx {
        let ssl_ptr = ssl_ctx_ptr.load(Ordering::SeqCst);
        return Some(unsafe { &*(ssl_ptr as *const HttpSSLContext) });
    }

    None
}

#[derive(Default)]
pub struct HttpSSLContext {
    ssl: bool,
    email: String,
    store_path: String,
    cert_key_path: String,
    cert_path: String,
    auto_renew: bool,
    renew_days: i64,
    domain: String,
}

impl HttpSSLContext {
    pub fn new() -> Self {
        Self::default()
    }
}

pub enum HttpSSLCertStatus {
    Valid,
    Expired,
    Revoked,
    NotExist,
    Unknown,
}

pub struct HttpSSL {
    ctx: HttpSSLContext,
}

impl HttpSSL {
    pub fn new(ctx: HttpSSLContext) -> Self {
        if ctx.ssl {
            if ctx.email.is_empty() {
                panic!("ssl_email is required");
            }
            if ctx.cert_key_path.is_empty() {
                panic!("ssl_cert_key_path is required");
            }
            if ctx.cert_path.is_empty() {
                panic!("ssl_cert_path is required");
            }
            if ctx.store_path.is_empty() {
                panic!("ssl_store_path is required");
            }
            if ctx.domain.is_empty() {
                panic!("ssl_domain is required");
            }
        }
        Self { ctx }
    }

    pub fn init(&self) -> Result<(), Box<dyn Error>> {
        if let Ok(cert) = load_cert_from(&self.ctx.cert_path) {
            let days = remaining_days_of(&cert).unwrap();
            if days < self.ctx.renew_days {
            }
        }

        if let Some(auth) = create_cert(self.ctx.domain.as_str(), self.ctx.store_path.as_str(), self.ctx.email.as_str())? {
            for auth in auth {
                self.show_http_challenge(&auth)?;
                self.show_dns_challenge(&auth)?;
            }
        }

        Ok(())
    }

    fn show_http_challenge(&self, challenge: &Auth) -> Result<(), Box<dyn Error>> {
        let challenge = challenge.http_challenge();
        let token = challenge.http_proof();

        println!("Please add the following HTTP header:");
        println!("Authorization: {}", token);

        Ok(())
    }

    fn show_dns_challenge(&self, challenge: &Auth) -> Result<(), Box<dyn Error>> {
        let challenge = challenge.dns_challenge();
        let token = challenge.dns_proof();

        println!("Please add the following DNS record:");
        println!("_acme-challenge.{} IN TXT \"{}\"", self.ctx.domain, token);

        Ok(())
    }
}
