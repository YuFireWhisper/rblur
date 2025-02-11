use std::{
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
use serde_json::Value;
use thiserror::Error;

use crate::{
    core::config::{
        command::{CommandBuilder, ParameterBuilder},
        config_context::ConfigContext,
        config_manager::{bool_str_to_bool, get_config_parame},
    },
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
    CommandBuilder::new("ssl")
        .is_block()
        .allowed_parents(vec!["server".to_string()])
        .display_name("en", "SSL")
        .display_name("zh-tw", "SSL")
        .desc("en", "Configures SSL/TLS security settings for the server")
        .desc("zh-tw", "配置伺服器的 SSL/TLS 安全設定")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Enable SSL")
            .display_name("zh-tw", "啟用 SSL")
            .type_name("bool")
            .is_required(true)
            .default("false")
            .desc("en", "Activates SSL/TLS encryption for the server")
            .desc("zh-tw", "為伺服器啟用 SSL/TLS 加密")
            .build()])
        .build(handle_create_ssl),
    CommandBuilder::new("ssl_email")
        .allowed_parents(vec!["ssl".to_string()])
        .display_name("en", "SSL Email")
        .display_name("zh-tw", "SSL 電子郵件")
        .desc(
            "en",
            "Specifies contact email for SSL certificate management"
        )
        .desc("zh-tw", "指定 SSL 憑證管理的聯絡電子郵件")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Email")
            .display_name("zh-tw", "電子郵件")
            .type_name("String")
            .is_required(true)
            .default("example@example.com")
            .desc(
                "en",
                "Email address used for SSL certificate registration and renewal notifications"
            )
            .desc("zh-tw", "用於 SSL 憑證註冊和更新通知的電子郵件地址")
            .build()])
        .build(handle_set_ssl_email),
    CommandBuilder::new("ssl_auto_renew")
        .allowed_parents(vec!["ssl".to_string()])
        .display_name("en", "SSL Auto Renew")
        .display_name("zh-tw", "SSL 自動更新")
        .desc("en", "Manages automatic SSL certificate renewal")
        .desc("zh-tw", "管理 SSL 憑證的自動更新")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Enable Auto Renew")
            .display_name("zh-tw", "啟用自動更新")
            .type_name("bool")
            .is_required(true)
            .default("false")
            .desc(
                "en",
                "Automatically renew SSL certificates before expiration"
            )
            .desc("zh-tw", "在憑證過期前自動續約 SSL 憑證")
            .build()])
        .build(handle_set_ssl_auto_renew),
    CommandBuilder::new("ssl_renew_day")
        .allowed_parents(vec!["ssl".to_string()])
        .display_name("en", "SSL Renew Day")
        .display_name("zh-tw", "SSL 更新天數")
        .desc("en", "Sets the timing for SSL certificate renewal")
        .desc("zh-tw", "設定 SSL 憑證更新的時間點")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Days")
            .display_name("zh-tw", "天數")
            .type_name("u32")
            .is_required(true)
            .default("30")
            .desc(
                "en",
                "Number of days before certificate expiration to initiate renewal"
            )
            .desc("zh-tw", "在憑證到期前幾天開始啟動更新程序")
            .build()])
        .build(handle_set_ssl_renew_day),
    CommandBuilder::new("ssl_domain")
        .allowed_parents(vec!["ssl".to_string()])
        .display_name("en", "SSL Domain")
        .display_name("zh-tw", "SSL 域名")
        .desc("en", "Specifies the domain for SSL certificate")
        .desc("zh-tw", "指定 SSL 憑證的網域")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Domain")
            .display_name("zh-tw", "域名")
            .type_name("String")
            .is_required(true)
            .default("example.com")
            .desc("en", "Primary domain name for the SSL certificate")
            .desc("zh-tw", "SSL 憑證的主要網域名稱")
            .build()])
        .build(handle_set_ssl_domain),
    CommandBuilder::new("ssl_dns_provider")
        .allowed_parents(vec!["ssl".to_string()])
        .display_name("en", "SSL DNS Provider")
        .display_name("zh-tw", "SSL DNS 供應商")
        .desc("en", "Configures DNS provider for domain validation")
        .desc("zh-tw", "配置用於網域驗證的 DNS 供應商")
        .params(vec![
            ParameterBuilder::new(0)
                .display_name("en", "Provider")
                .display_name("zh-tw", "供應商")
                .type_name("String")
                .is_required(true)
                .default("cloudflare")
                .desc(
                    "en",
                    "Name of the DNS service provider for domain validation"
                )
                .desc("zh-tw", "用於網域驗證的 DNS 服務供應商名稱")
                .build(),
            ParameterBuilder::new(1)
                .display_name("en", "API Token")
                .display_name("zh-tw", "API 令牌")
                .type_name("String")
                .is_required(true)
                .default("token")
                .desc("en", "Authentication token for the specified DNS provider")
                .desc("zh-tw", "指定 DNS 供應商的驗證令牌")
                .build()
        ])
        .build(handle_set_ssl_dns_provider),
    CommandBuilder::new("ssl_dns_instructions_lang")
        .allowed_parents(vec!["ssl".to_string()])
        .display_name("en", "SSL DNS Instructions Language")
        .display_name("zh-tw", "SSL DNS 指示語言")
        .desc("en", "Sets the language for DNS configuration instructions")
        .desc("zh-tw", "設定 DNS 配置指示的語言")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Language")
            .display_name("zh-tw", "語言")
            .type_name("String")
            .is_required(true)
            .default("en")
            .desc("en", "Language code for presenting DNS setup instructions")
            .desc("zh-tw", "用於呈現 DNS 設定說明的語言代碼")
            .build()])
        .build(handler_set_ssl_dns_instructions_lang),
);

pub fn handle_create_ssl(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let enable = get_config_parame(config, 0).expect("Missing SSL enable parameter");
    let enable = bool_str_to_bool(&enable).unwrap();
    if !enable {
        return;
    }
    let mut ssl_ctx = Box::new(HttpSSLContext::new());
    ssl_ctx.ssl = true;
    let ssl_raw = Box::into_raw(ssl_ctx) as *mut u8;
    ctx.current_ctx = Some(AtomicPtr::new(ssl_raw));
    ctx.current_block_type_id = Some(std::any::TypeId::of::<HttpSSLContext>());
}

pub fn handle_set_ssl_email(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let email = get_config_parame(config, 0).expect("Missing ssl_email parameter");
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.email = email.to_string();
    }
}

pub fn handle_set_ssl_domain(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let domain = get_config_parame(config, 0).expect("Missing ssl_domain parameter");
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.domain = domain.to_string();
    }
}

pub fn handle_set_ssl_auto_renew(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let enable_str = get_config_parame(config, 0).expect("Missing ssl_auto_renew parameter");
    let enable = bool_str_to_bool(&enable_str).unwrap();
    if !enable {
        return;
    }
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.auto_renew = true;
    }
}

pub fn handle_set_ssl_renew_day(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let days_str = get_config_parame(config, 0).expect("Missing ssl_renew_day parameter");
    let days = days_str
        .parse::<u32>()
        .expect("Invalid number for ssl_renew_day");
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.renew_days = days;
    }
}

pub fn handle_set_ssl_dns_provider(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let provider = get_config_parame(config, 0).expect("Missing ssl_dns_provider parameter");
    let api_token =
        get_config_parame(config, 1).expect("Missing ssl_dns_provider API token parameter");
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.dns_provider = DnsProvider::from_str(&provider).unwrap();
        ssl_ctx.dns_provider_api_token = api_token.to_string();
    }
}

pub fn handler_set_ssl_dns_instructions_lang(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let lang = get_config_parame(config, 0).expect("Missing ssl_dns_instructions_lang parameter");
    if let Some(ssl_ctx) = get_ssl_ctx(ctx) {
        ssl_ctx.dns_instructions_lang = lang.to_string();
    }
}

fn get_ssl_ctx(
    ctx: &crate::core::config::config_context::ConfigContext,
) -> Option<&mut HttpSSLContext> {
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

        println!("Creating account for email: {}", ctx.email);

        Self::init(&mut account, ctx, false)?;

        let cert_key = account
            .get_cert_key(&ctx.domain)
            .expect("Failed to get certificate key");
        let mut cert = account
            .get_certificate(&ctx.domain)
            .expect("Failed to get certificate");

        if ctx.auto_renew && cert.should_renew(ctx.renew_days)? {
            println!("Renewing SSL certificate for domain: {}", ctx.domain);
            Self::init(&mut account, ctx, true)?;
            cert = account.get_certificate(&ctx.domain).unwrap();
        }

        Ok(Self { cert_key, cert })
    }

    pub fn from_config(ctx: &ConfigContext) -> Result<Self> {
        if let Some(ssl_ctx_ptr) = &ctx.current_ctx {
            let ssl_raw = ssl_ctx_ptr.load(Ordering::SeqCst);
            let ssl_ctx: &HttpSSLContext = unsafe { &*(ssl_raw as *const HttpSSLContext) };
            Self::new(ssl_ctx)
        } else {
            Err(HttpSSLError::SSLNotEnabled)
        }
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
