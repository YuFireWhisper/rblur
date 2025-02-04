use std::{
    any::TypeId,
    ptr,
    str::FromStr,
    sync::atomic::{AtomicPtr, Ordering},
    time::Duration,
};

use racme::{
    account::{Account, AccountBuilder},
    certificate::{Certificate, CertificateError},
    key_pair::KeyPair,
    order::{DnsProvider, Order, OrderError},
};
use thiserror::Error;

use crate::{
    core::config::{
        command::Command, config_context::ConfigContext, config_file_parser::parse_context_of,
        config_manager::bool_str_to_bool,
    },
    http::http_server::HttpServerContext,
    register_commands,
};

#[derive(Debug, Error)]
pub enum HttpSSLError {
    #[error("SSL is not enabled")]
    SSLNotEnabled,
    #[error("Email empty")]
    EmailEmpty,
    #[error("Domain empty")]
    DomainEmpty,
    #[error("Order error: {0}")]
    OrderError(Box<OrderError>),
    #[error("Certificate error: {0}")]
    CertificateError(#[from] CertificateError),
}

impl From<OrderError> for HttpSSLError {
    fn from(error: OrderError) -> Self {
        HttpSSLError::OrderError(Box::new(error))
    }
}

type Result<T> = std::result::Result<T, HttpSSLError>;

register_commands!(
    Command::new(
        "ssl",
        vec![TypeId::of::<HttpServerContext>()],
        handle_create_ssl
    ),
    Command::new(
        "ssl_email",
        vec![TypeId::of::<HttpSSLContext>()],
        handle_set_ssl_email
    ),
    Command::new(
        "ssl_auto_renew",
        vec![TypeId::of::<HttpSSLContext>()],
        handle_set_ssl_auto_renew
    ),
    Command::new(
        "ssl_renew_day",
        vec![TypeId::of::<HttpSSLContext>()],
        handle_set_ssl_renew_day
    ),
    Command::new(
        "ssl_domain",
        vec![TypeId::of::<HttpSSLContext>()],
        handle_set_ssl_domain
    ),
    Command::new(
        "ssl_dns_provider",
        vec![TypeId::of::<HttpSSLContext>()],
        handle_set_ssl_dns_provider
    ),
    Command::new(
        "ssl_dns_instructions_lang",
        vec![TypeId::of::<HttpSSLContext>()],
        handler_set_ssl_dns_instructions_lang
    )
);

pub fn handle_create_ssl(ctx: &mut ConfigContext) {
    let enable = bool_str_to_bool(ctx.current_cmd_args.get(1).unwrap()).unwrap();

    if !enable {
        return;
    }

    let srv_ctx = ctx.current_ctx.take();
    let prev_block_type_id = ctx.current_block_type_id.take();

    let mut ssl_ctx = Box::new(HttpSSLContext::new());
    ssl_ctx.ssl = true;

    ctx.current_ctx = Some(AtomicPtr::new(Box::into_raw(ssl_ctx) as *mut u8));
    ctx.current_block_type_id = Some(TypeId::of::<HttpSSLContext>());

    parse_context_of(ctx).expect("Error at handle_create_ssl");

    if let Some(srv_ctx_ptr) = &srv_ctx {
        let srv_ptr = srv_ctx_ptr.load(Ordering::SeqCst);
        let srv_ctx = unsafe { &mut *(srv_ptr as *mut HttpServerContext) };

        if let Some(ssl_ctx_ptr) = ctx.current_ctx.take() {
            let ssl_ptr = ssl_ctx_ptr.load(Ordering::SeqCst);
            let ssl_ctx: HttpSSLContext = unsafe { ptr::read(ssl_ptr as *const HttpSSLContext) };
            srv_ctx.set_ssl(ssl_ctx);
        }
    }

    ctx.current_ctx = srv_ctx;
    ctx.current_block_type_id = prev_block_type_id;
}

pub fn handle_set_ssl_email(ctx: &mut ConfigContext) {
    let email = ctx.current_cmd_args.get(1).unwrap();
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.email = email.to_string();
    }
}

pub fn handle_set_ssl_domain(ctx: &mut ConfigContext) {
    let domain = ctx.current_cmd_args.get(1).unwrap();
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.domain = domain.to_string();
    }
}

pub fn handle_set_ssl_auto_renew(ctx: &mut ConfigContext) {
    let enable = bool_str_to_bool(ctx.current_cmd_args.get(1).unwrap()).unwrap();

    if !enable {
        return;
    }

    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.auto_renew = true;
    }
}

pub fn handle_set_ssl_renew_day(ctx: &mut ConfigContext) {
    let days = ctx.current_cmd_args.get(1).unwrap().parse::<u32>().unwrap();
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.renew_days = days;
    }
}

pub fn handle_set_ssl_dns_provider(ctx: &mut ConfigContext) {
    let provider = ctx.current_cmd_args.get(1).unwrap();
    let api_token = ctx.current_cmd_args.get(2).unwrap();
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.dns_provider = DnsProvider::from_str(provider).unwrap();
        ssl_ctx.dns_provider_api_token = api_token.to_string();
    }
}

pub fn handler_set_ssl_dns_instructions_lang(ctx: &mut ConfigContext) {
    let lang = ctx.current_cmd_args.get(1).unwrap();
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.dns_instructions_lang = lang.to_string();
    }
}

fn get_ssl_ctx(ctx: &ConfigContext) -> Option<&mut HttpSSLContext> {
    if let Some(ssl_ctx_ptr) = &ctx.current_ctx {
        let ssl_ptr = ssl_ctx_ptr.load(Ordering::SeqCst);
        return Some(unsafe { &mut *(ssl_ptr as *mut HttpSSLContext) });
    }

    None
}

pub struct HttpSSLContext {
    pub ssl: bool,
    pub email: String,
    pub domain: String,
    pub auto_renew: bool,
    pub renew_days: u32,
    pub dns_provider: DnsProvider,
    pub dns_provider_api_token: String,
    pub dns_instructions_lang: String,
}

impl Default for HttpSSLContext {
    fn default() -> Self {
        Self {
            ssl: false,
            email: String::new(),
            domain: String::new(),
            auto_renew: true,
            renew_days: 30,
            dns_provider: DnsProvider::Default,
            dns_provider_api_token: String::new(),
            dns_instructions_lang: String::new(),
        }
    }
}

impl HttpSSLContext {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct HttpSSL {
    pub cert_key: KeyPair,
    pub cert: Certificate,
}

impl HttpSSL {
    pub fn new(ctx: &HttpSSLContext) -> Result<Self> {
        if !ctx.ssl {
            return Err(HttpSSLError::SSLNotEnabled);
        }
        if ctx.email.is_empty() {
            return Err(HttpSSLError::EmailEmpty);
        }
        if ctx.domain.is_empty() {
            return Err(HttpSSLError::DomainEmpty);
        }

        let mut account = AccountBuilder::new(&ctx.email)
            .dir_url("https://acme-staging-v02.api.letsencrypt.org/directory")
            .build()
            .unwrap();

        Self::init(&mut account, ctx, false)?;

        let cert_key = account.get_cert_key(&ctx.domain).unwrap();
        let mut cert = account.get_certificate(&ctx.domain).unwrap();

        if ctx.auto_renew && cert.should_renew(ctx.renew_days)? {
            println!("Renewing SSL certificate for domain: {}", ctx.domain);
            Self::init(&mut account, ctx, true)?;
            cert = account.get_certificate(&ctx.domain).unwrap();
        }

        Ok(Self { cert_key, cert })
    }

    fn init(account: &mut Account, ctx: &HttpSSLContext, renew: bool) -> Result<()> {
        println!("Creating SSL certificate for domain: {}", ctx.domain);
        let mut order = match renew {
            true => Order::renew(account, &ctx.domain)?
                .dns_provider(ctx.dns_provider, &ctx.dns_provider_api_token)?,
            false => Order::new(account, &ctx.domain)?
                .dns_provider(ctx.dns_provider, &ctx.dns_provider_api_token)?,
        };

        let order = match order.validate_challenge(account) {
            Ok(order) => order,
            Err(_) => {
                order.display_challenges(&ctx.dns_instructions_lang);
                order.validation_with_retry(account, Duration::from_secs(3), 20)?
            }
        };

        order.finalize(account)?;
        order.download_certificate(account)?;

        Ok(())
    }
}
