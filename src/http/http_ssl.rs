use std::{
    path::Path,
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
        config_manager::{bool_str_to_bool, get_config_param},
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
            .default("")
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
            .default("")
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
                .default("")
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
                .default("")
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
        .build(handle_set_ssl_dns_instructions_lang),
    CommandBuilder::new("ssl_cert")
        .allowed_parents(vec!["ssl".to_string()])
        .display_name("en", "SSL Certificate Path")
        .display_name("zh-tw", "SSL 憑證路徑")
        .desc("en", "Specifies the path to the SSL certificate file")
        .desc("zh-tw", "指定 SSL 憑證檔案的路徑")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Path")
            .display_name("zh-tw", "路徑")
            .type_name("String")
            .is_required(true)
            .default("")
            .desc("en", "Path to the SSL certificate file")
            .desc("zh-tw", "SSL 憑證檔案的路徑")
            .build()])
        .build(handle_set_ssl_cert),
    CommandBuilder::new("ssl_key")
        .allowed_parents(vec!["ssl".to_string()])
        .display_name("en", "SSL Key Path")
        .display_name("zh-tw", "SSL 金鑰路徑")
        .desc("en", "Specifies the path to the SSL key file")
        .desc("zh-tw", "指定 SSL 金鑰檔案的路徑")
        .params(vec![ParameterBuilder::new(0)
            .display_name("en", "Path")
            .display_name("zh-tw", "路徑")
            .type_name("String")
            .is_required(true)
            .default("")
            .desc("en", "Path to the SSL key file")
            .desc("zh-tw", "SSL 金鑰檔案的路徑")
            .build()])
        .build(handle_set_ssl_key),
);

fn update_ssl_context<F>(ctx: &mut ConfigContext, update_fn: F)
where
    F: FnOnce(&mut HttpSSLContext),
{
    if let Some(ssl_ctx) = get_mut_ssl_ctx(ctx) {
        update_fn(ssl_ctx);
    }
}

fn get_mut_ssl_ctx(ctx: &ConfigContext) -> Option<&mut HttpSSLContext> {
    if let Some(ssl_ctx_ptr) = &ctx.current_ctx {
        let ssl_ptr = ssl_ctx_ptr.load(Ordering::SeqCst);
        return Some(unsafe { &mut *(ssl_ptr as *mut HttpSSLContext) });
    }
    None
}

pub fn handle_create_ssl(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let enable = get_config_param(config, 0).expect("Missing SSL enable parameter");
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
    let email = get_config_param(config, 0).expect("Missing ssl_email parameter");
    update_ssl_context(ctx, |ssl_ctx| {
        ssl_ctx.email = email.to_string();
    });
}

pub fn handle_set_ssl_domain(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let domain = get_config_param(config, 0).expect("Missing ssl_domain parameter");
    update_ssl_context(ctx, |ssl_ctx| {
        ssl_ctx.domain = domain.to_string();
    });
}

pub fn handle_set_ssl_auto_renew(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let enable_str = get_config_param(config, 0).expect("Missing ssl_auto_renew parameter");
    let enable = bool_str_to_bool(&enable_str).unwrap();
    if !enable {
        return;
    }
    update_ssl_context(ctx, |ssl_ctx| {
        ssl_ctx.auto_renew = true;
    });
}

pub fn handle_set_ssl_renew_day(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let days_str = get_config_param(config, 0).expect("Missing ssl_renew_day parameter");
    let days = days_str
        .parse::<u32>()
        .expect("Invalid number for ssl_renew_day");
    update_ssl_context(ctx, |ssl_ctx| {
        ssl_ctx.renew_days = days;
    });
}

pub fn handle_set_ssl_dns_provider(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let provider = get_config_param(config, 0).expect("Missing ssl_dns_provider parameter");
    let api_token =
        get_config_param(config, 1).expect("Missing ssl_dns_provider API token parameter");
    update_ssl_context(ctx, |ssl_ctx| {
        ssl_ctx.dns_provider = DnsProvider::from_str(&provider).unwrap();
        ssl_ctx.dns_provider_api_token = api_token.to_string();
    });
}

pub fn handle_set_ssl_dns_instructions_lang(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let lang = get_config_param(config, 0).expect("Missing ssl_dns_instructions_lang parameter");
    update_ssl_context(ctx, |ssl_ctx| {
        ssl_ctx.dns_instructions_lang = lang.to_string();
    });
}

pub fn handle_set_ssl_cert(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let cert_path = get_config_param(config, 0).expect("Missing ssl_cert parameter");
    update_ssl_context(ctx, |ssl_ctx| {
        ssl_ctx.cert_path = cert_path.to_string();
    });
}

pub fn handle_set_ssl_key(
    ctx: &mut crate::core::config::config_context::ConfigContext,
    config: &Value,
) {
    let key_path = get_config_param(config, 0).expect("Missing ssl_key parameter");
    update_ssl_context(ctx, |ssl_ctx| {
        ssl_ctx.key_path = key_path.to_string();
    });
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
    pub cert_path: String,
    pub key_path: String,
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
            cert_path: String::new(),
            key_path: String::new(),
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

        let (mut account, cert_key, mut cert) = if Self::is_custom(ctx) {
            println!("Using custom certificate");
            Self::use_custom(ctx)?
        } else {
            Self::use_default(ctx)?
        };

        if !ctx.auto_renew || !cert.should_renew(ctx.renew_days)? {
            println!("Certificate is up to date");
            println!("Certificate expires on: {}", String::from_utf8_lossy(&cert.cert.to_pem().unwrap()));
            println!("Certificate key: {}", String::from_utf8_lossy(&cert_key.pri_key.private_key_to_pem_pkcs8().unwrap()));
            return Ok(Self { cert_key, cert });
        }

        if account.is_none() {
            account = Some(Self::create_account(&ctx.email)?);
        }

        Self::new_order(account.as_mut().unwrap(), ctx, true)?;
        cert = account
            .as_ref()
            .unwrap()
            .get_certificate(&ctx.domain)
            .unwrap();

        Ok(Self { cert_key, cert })
    }

    fn is_custom(ctx: &HttpSSLContext) -> bool {
        let valid_file = |p: &Path| p.is_file();
        let key_exists = valid_file(Path::new(&ctx.key_path));
        let cert_exists = valid_file(Path::new(&ctx.cert_path));

        if key_exists ^ cert_exists {
            panic!("Key and certificate files must be both present or both absent");
        }

        key_exists && cert_exists
    }

    fn use_custom(ctx: &HttpSSLContext) -> Result<(Option<Account>, KeyPair, Certificate)> {
        let cert_key = KeyPair::from_file(&ctx.key_path).expect("Failed to load certificate key");
        let cert_pem =
            std::fs::read_to_string(&ctx.cert_path).expect("Failed to read certificate file");
        let cert = Certificate::new(&cert_pem)?;

        Ok((None, cert_key, cert))
    }

    fn use_default(ctx: &HttpSSLContext) -> Result<(Option<Account>, KeyPair, Certificate)> {
        let mut account = Self::create_account(&ctx.email)?;

        Self::new_order(&mut account, ctx, false)?;

        let cert_key = account
            .get_cert_key(&ctx.domain)
            .expect("Failed to get certificate key");

        let cert = account
            .get_certificate(&ctx.domain)
            .expect("Failed to get certificate");

        Ok((Some(account), cert_key, cert))
    }

    fn create_account(email: &str) -> Result<Account> {
        if email.is_empty() {
            return Err(HttpSSLError::EmailEmpty);
        }

        AccountBuilder::new(email)
            .dir_url("https://acme-staging-v02.api.letsencrypt.org/directory")
            .build()
            .map_err(|_| HttpSSLError::EmailEmpty)
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

    fn new_order(account: &mut Account, ctx: &HttpSSLContext, renew: bool) -> Result<()> {
        if ctx.domain.is_empty() {
            return Err(HttpSSLError::DomainEmpty);
        }

        let mut order = if renew {
            Order::renew(account, &ctx.domain)?
                .dns_provider(ctx.dns_provider, &ctx.dns_provider_api_token)?
        } else {
            Order::new(account, &ctx.domain)?
                .dns_provider(ctx.dns_provider, &ctx.dns_provider_api_token)?
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
