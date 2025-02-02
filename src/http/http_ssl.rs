use std::{
    any::TypeId,
    str::FromStr,
    sync::atomic::{AtomicPtr, Ordering},
};

use racme::{
    account::Account,
    certificate::Certificate,
    challenge::ChallengeType,
    key_pair::KeyPair,
    order::{DnsProvider, Order, OrderStatus},
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
    #[error("Order is pending and DNS provider is not set")]
    OrderPending,
    #[error("Order is invalid, please restart the server")]
    OrderInvalid,
    #[error("SSL is not enabled")]
    SSLNotEnabled,
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

    let prev_ctx = ctx.current_ctx.take();
    let prev_block_type_id = ctx.current_block_type_id.take();

    let ssl_ctx = Box::new(HttpSSLContext::new());

    ctx.current_ctx = Some(AtomicPtr::new(Box::into_raw(ssl_ctx) as *mut u8));
    ctx.current_block_type_id = Some(TypeId::of::<HttpSSLContext>());

    parse_context_of(ctx).expect("Error at handle_create_ssl");

    ctx.current_ctx = prev_ctx;
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
        ssl_ctx.dns_provider = Some(DnsProvider::from_str(provider).unwrap());
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
    ssl: bool,
    email: String,
    domain: String,
    auto_renew: bool,
    renew_days: u32,
    dns_provider: Option<DnsProvider>,
    dns_provider_api_token: String,
    dns_instructions_lang: String,
}

impl Default for HttpSSLContext {
    fn default() -> Self {
        Self {
            ssl: false,
            email: String::new(),
            domain: String::new(),
            auto_renew: true,
            renew_days: 30,
            dns_provider: None,
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
    ctx: HttpSSLContext,
    account: Account,
}

impl HttpSSL {
    pub fn new(ctx: HttpSSLContext) -> Self {
        if ctx.ssl {
            if ctx.email.is_empty() {
                panic!("ssl_email is required");
            }
            if ctx.domain.is_empty() {
                panic!("ssl_domain is required");
            }
            if ctx.dns_provider.is_some() && ctx.dns_provider_api_token.is_empty() {
                panic!("ssl_dns_provider_api_token is required");
            }
        }

        let account = Account::new(&ctx.email).unwrap();
        Self { ctx, account }
    }

    pub fn init(&mut self) -> Result<()> {
        if !self.ctx.ssl {
            return Err(HttpSSLError::SSLNotEnabled);
        }

        let order = Order::new(&mut self.account, &self.ctx.domain).unwrap();

        if order.status == OrderStatus::Valid {
            return Ok(());
        }

        match order.status {
            OrderStatus::Valid => {}
            OrderStatus::Processing => self.handler_order_processing(order).unwrap(),
            OrderStatus::Pending => self.handle_order_pending(order).unwrap(),
            OrderStatus::Ready => self.handle_order_ready(order).unwrap(),
            OrderStatus::Invalid => return Err(HttpSSLError::OrderInvalid),
        }

        let cert = self.account.get_certificate(&self.ctx.domain).unwrap();
        if cert.should_renew(self.ctx.renew_days).unwrap() {
            self.init().unwrap();
        }

        Ok(())
    }

    pub fn get_cert_key(&self) -> KeyPair {
        self.account.get_cert_key(&self.ctx.domain).unwrap()
    }

    pub fn get_cert(&self) -> Certificate {
        self.account.get_certificate(&self.ctx.domain).unwrap()
    }

    fn handle_order_pending(&self, order: Order) -> Result<()> {
        if let Some(provider) = self.ctx.dns_provider {
            order
                .dns_provider(provider, &self.ctx.dns_provider_api_token)
                .unwrap()
                .validate_challenge(&self.account, ChallengeType::Dns01)
                .unwrap()
                .finalize(&self.account)
                .unwrap()
                .download_certificate(&self.account)
                .unwrap();

            return Ok(());
        }

        for challenge in order.challenges.values() {
            challenge.get_instructions(&self.ctx.dns_instructions_lang);
        }

        Err(HttpSSLError::OrderPending)
    }

    fn handle_order_ready(&self, mut order: Order) -> Result<()> {
        order
            .finalize(&self.account)
            .unwrap()
            .download_certificate(&self.account)
            .unwrap();
        Ok(())
    }

    fn handler_order_processing(&self, order: Order) -> Result<()> {
        order.download_certificate(&self.account).unwrap();
        Ok(())
    }
}
