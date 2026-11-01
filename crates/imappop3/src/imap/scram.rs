//! SCRAM-SHA-256（RFC 5802 / RFC 7677）服务端消息处理。
//!
//! 只实现 `SCRAM-SHA-256`（不实现 `-PLUS` 通道绑定）；因此拒绝 `p=` 的 GS2
//! 头。凭据来自 [`ScramCredentials`]（由既有 PBKDF2 记录派生），不新增第二份
//! 口令存储。

use base64::Engine;

use crate::auth::{hmac_sha256, ScramCredentials};
use crate::error::{MailError, Result};

#[derive(Debug, Clone)]
pub struct ClientFirst {
    /// `n,,` / `y,,` 的原文，用于校验客户端的 `c=`。
    pub gs2_header: String,
    /// 不含 GS2 头的 client-first-bare。
    pub bare: String,
    pub username: String,
    pub nonce: String,
}

pub fn parse_client_first(input: &str) -> Result<ClientFirst> {
    let mut parts = input.splitn(3, ',');
    let flag = parts
        .next()
        .ok_or_else(|| MailError::invalid("invalid SCRAM client-first message"))?;
    let authzid = parts
        .next()
        .ok_or_else(|| MailError::invalid("invalid SCRAM client-first message"))?;
    let bare = parts
        .next()
        .ok_or_else(|| MailError::invalid("invalid SCRAM client-first message"))?;
    if !(flag == "n" || flag == "y") || !authzid.is_empty() {
        return Err(MailError::invalid(
            "channel binding and authorization identity are not supported",
        ));
    }
    let mut username = None;
    let mut nonce = None;
    for attribute in bare.split(',') {
        let Some((key, value)) = attribute.split_once('=') else {
            continue;
        };
        match key {
            "n" => username = Some(decode_saslname(value)?),
            "r" => nonce = Some(value.to_string()),
            _ => {}
        }
    }
    let username = username.ok_or_else(|| MailError::invalid("SCRAM username is missing"))?;
    let nonce = nonce.ok_or_else(|| MailError::invalid("SCRAM nonce is missing"))?;
    if username.is_empty() || nonce.is_empty() || nonce.contains(',') {
        return Err(MailError::invalid("invalid SCRAM username or nonce"));
    }
    Ok(ClientFirst {
        gs2_header: format!("{flag},{authzid},"),
        bare: bare.to_string(),
        username,
        nonce,
    })
}

fn decode_saslname(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'=' {
            if index + 2 >= bytes.len() {
                return Err(MailError::invalid("invalid SCRAM username escape"));
            }
            // =2C/=3D 都是 ASCII，按字节校验即可；不能对 &str 切片 ——
            // 多字节字符落在转义序列中间时 `&value[index + 1..index + 3]`
            // 会因不在 char boundary 上而 panic。
            let mut hex = [bytes[index + 1], bytes[index + 2]];
            hex.make_ascii_uppercase();
            match &hex {
                b"2C" => out.push(b','),
                b"3D" => out.push(b'='),
                _ => return Err(MailError::invalid("invalid SCRAM username escape")),
            }
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).map_err(|_| MailError::invalid("SCRAM username is not UTF-8"))
}

pub fn server_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 18];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn server_first(
    client: &ClientFirst,
    credentials: &ScramCredentials,
    server_nonce: &str,
) -> String {
    format!(
        "r={}{},s={},i={}",
        client.nonce,
        server_nonce,
        base64::engine::general_purpose::STANDARD.encode(&credentials.salt),
        credentials.iterations
    )
}

/// 校验 client-final，成功时返回服务端签名（`v=` 的值）。
pub fn verify_client_final(
    client: &ClientFirst,
    server_first: &str,
    server_nonce: &str,
    client_final: &str,
    credentials: &ScramCredentials,
) -> Result<[u8; 32]> {
    let Some((without_proof, proof)) = client_final.rsplit_once(",p=") else {
        return Err(MailError::invalid("SCRAM proof is missing"));
    };
    if proof.contains(',') {
        return Err(MailError::invalid(
            "SCRAM proof must be the final attribute",
        ));
    }
    let mut channel_binding = None;
    let mut nonce = None;
    for attribute in without_proof.split(',') {
        let Some((key, value)) = attribute.split_once('=') else {
            continue;
        };
        match key {
            "c" => channel_binding = Some(value.to_string()),
            "r" => nonce = Some(value.to_string()),
            // RFC 5802 §5.1：m= 是强制扩展协商，不支持就必须失败，不能静默忽略。
            "m" => {
                return Err(MailError::invalid(
                    "SCRAM mandatory extension is not supported",
                ))
            }
            _ => {}
        }
    }
    let expected_binding =
        base64::engine::general_purpose::STANDARD.encode(client.gs2_header.as_bytes());
    if channel_binding.as_deref() != Some(expected_binding.as_str()) {
        return Err(MailError::invalid("SCRAM channel binding mismatch"));
    }
    let expected_nonce = format!("{}{}", client.nonce, server_nonce);
    if nonce.as_deref() != Some(expected_nonce.as_str()) {
        return Err(MailError::invalid("SCRAM nonce mismatch"));
    }
    let proof = base64::engine::general_purpose::STANDARD
        .decode(proof)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(proof))
        .map_err(|_| MailError::invalid("SCRAM proof is not valid base64"))?;
    if proof.len() != 32 {
        return Err(MailError::invalid("SCRAM proof has the wrong length"));
    }

    let auth_message = format!("{},{},{}", client.bare, server_first, without_proof);
    let client_signature = hmac_sha256(&credentials.stored_key, auth_message.as_bytes());
    let mut client_key = [0u8; 32];
    for index in 0..32 {
        client_key[index] = proof[index] ^ client_signature[index];
    }
    use sha2::{Digest, Sha256};
    let stored_key: [u8; 32] = Sha256::digest(client_key).into();
    if !mailstack_core::password::constant_time_eq(&stored_key, &credentials.stored_key) {
        return Err(MailError::invalid("SCRAM proof does not verify"));
    }
    Ok(hmac_sha256(
        &credentials.server_key,
        auth_message.as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::scram_credentials_from_record;

    fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
        // 单块 PBKDF2-HMAC-SHA256（dkLen = 32）。
        let mut u = {
            let mut first = Vec::new();
            first.extend_from_slice(salt);
            first.extend_from_slice(&1u32.to_be_bytes());
            hmac_sha256(password, &first)
        };
        let mut result = u;
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for index in 0..32 {
                result[index] ^= u[index];
            }
        }
        result
    }

    #[test]
    fn client_first_escapes_are_decoded() {
        let client = parse_client_first("n,,n=a=2Cb=3Dc,r=abc").unwrap();
        assert_eq!(client.username, "a,b=c");
        assert_eq!(client.nonce, "abc");
        assert_eq!(client.gs2_header, "n,,");
        assert!(parse_client_first("p=tls-unique,,n=a,r=b").is_err());
        assert!(parse_client_first("n,,n=a=ZZ,r=b").is_err());
    }

    #[test]
    fn saslname_escape_over_a_multibyte_char_is_rejected_without_panicking() {
        // '=' 后面跟着多字节 UTF-8 字符：转义序列必须按字节校验。
        // 旧的 &str 切片写法会在 char boundary 上 panic。
        assert!(parse_client_first("n,,n=a=\u{4E2D}b,r=x").is_err());
        assert!(parse_client_first("n,,n==\u{4E2D},r=x").is_err());
    }

    #[test]
    fn client_final_rejects_the_mandatory_extension_attribute() {
        let mut record =
            mailstack_core::password::password_record("alice", "Tr0ubadour9x").unwrap();
        record.username = "alice@example.com".to_string();
        let credentials = scram_credentials_from_record(&record).unwrap();
        let client = parse_client_first("n,,n=alice@example.com,r=clientnonce").unwrap();
        // m= 出现在 client-final：RFC 5802 要求服务端失败，而不是忽略。
        let wrong = verify_client_final(
            &client,
            "s=AA==,i=1",
            "servernonce",
            "c=biws,m=,r=clientnonceservernonce,p=AAAA",
            &credentials,
        );
        assert!(wrong.is_err());
    }

    #[test]
    fn a_full_scram_exchange_verifies() {
        let mut record =
            mailstack_core::password::password_record("alice", "Tr0ubadour9x").unwrap();
        record.username = "alice@example.com".to_string();
        let credentials = scram_credentials_from_record(&record).unwrap();
        let client = parse_client_first("n,,n=alice@example.com,r=clientnonce").unwrap();
        let server_first = server_first(&client, &credentials, "servernonce");

        let salted = pbkdf2(b"Tr0ubadour9x", &credentials.salt, credentials.iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        use sha2::{Digest, Sha256};
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();
        assert_eq!(stored_key, credentials.stored_key);
        let auth_message = format!(
            "{},{},c=biws,r=clientnonceservernonce",
            client.bare, server_first
        );
        let signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let mut proof = [0u8; 32];
        for index in 0..32 {
            proof[index] = client_key[index] ^ signature[index];
        }
        let proof = base64::engine::general_purpose::STANDARD.encode(proof);
        let client_final = format!("c=biws,r=clientnonceservernonce,p={proof}");
        let server_signature = verify_client_final(
            &client,
            &server_first,
            "servernonce",
            &client_final,
            &credentials,
        )
        .unwrap();
        let expected = hmac_sha256(&credentials.server_key, auth_message.as_bytes());
        assert_eq!(server_signature, expected);

        let wrong = verify_client_final(
            &client,
            &server_first,
            "servernonce",
            "c=biws,r=clientnonceservernonce,p=AAAA",
            &credentials,
        );
        assert!(wrong.is_err());
    }
}

#[cfg(test)]
mod vector_tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_case_1() {
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn pbkdf2_matches_known_vector() {
        // password="password", salt="salt", iterations=1, dkLen=32
        let mut salt = Vec::new();
        salt.extend_from_slice(b"salt");
        salt.extend_from_slice(&1u32.to_be_bytes());
        let u = hmac_sha256(b"password", &salt);
        assert_eq!(
            hex::encode(u),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }
}
