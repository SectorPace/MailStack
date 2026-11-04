pub mod arc;
pub mod cache;
pub mod dkim;
pub mod dmarc;
pub mod error;
pub mod keys;
pub mod policy;
pub mod spf;

pub use arc::{seal, seal_with, ArcStatus, ArcVerdict, SealContext, ARC_SIGNED_HEADERS};

pub use cache::{system_resolver, TxtCache};
pub use dkim::{
    from_domain, sign, sign_with_default_headers, DkimStatus, DkimVerdict, DEFAULT_SIGNED_HEADERS,
};
pub use dmarc::{DmarcCheck, DmarcPolicy, DmarcStatus};
pub use error::{AuthError, AuthResult};
pub use keys::{
    apply_key_permissions, dkim_key_dir, dkim_txt_value, generate_key_material,
    load_private_key_der, private_key_path, rotate, spki_from_pkcs1, txt_record_path,
    validate_domain, validate_selector, zone_txt_fragment, DkimKeyMaterial, DkimRotation,
    DEFAULT_DKIM_SELECTOR, DKIM_KEY_BITS, DKIM_KEY_GROUP, DKIM_KEY_MODE,
};
pub use mail_auth::MessageAuthenticator;
pub use policy::{signing_policy, DkimSigningPolicy, SigningPolicyOutcome};
pub use spf::{SpfCheck, SpfStatus};
