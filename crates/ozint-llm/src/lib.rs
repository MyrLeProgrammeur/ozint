//! A minimal OpenAI-compatible chat-completion client — OZINT's only LLM dependency.
//!
//! OZINT uses an LLM in exactly two places, both optional and both degrading honestly
//! when no model is configured:
//!
//! - [`ozint::summary`] — the one-paragraph narration of a settled layer. Without a model
//!   the layer still settles and the tree is still complete; only the prose is missing.
//! - [`ozint::classify`] — the escalation tier for an ambiguous seed. Without a model the
//!   deterministic classifier answers instead, tagged `DeterministicFallback` so the UI
//!   never presents a guess as model-confirmed.
//!
//! **Nothing else in this project calls a model.** Every one of the 60+ OSINT tools is
//! deterministic: an HTTP call to a documented API and a parser. That is a deliberate
//! property, not an accident — findings must be reproducible and citable.
//!
//! ## Configuration
//!
//! Any OpenAI-compatible endpoint works: OpenAI, OpenRouter, Groq, Together, a local
//! Ollama or llama.cpp server, or a private gateway.
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `OZINT_LLM_API_KEY` | — | Bearer token. **Absent = the LLM tier is off**, which is a supported way to run. |
//! | `OZINT_LLM_BASE_URL` | `https://api.openai.com/v1` | The `/chat/completions` prefix. |
//! | `OZINT_LLM_MODEL` | `gpt-4o-mini` | Model id, as your provider spells it. |
//!
//! For a local Ollama: `OZINT_LLM_BASE_URL=http://localhost:11434/v1`,
//! `OZINT_LLM_API_KEY=ollama`, `OZINT_LLM_MODEL=llama3.1`.

use std::time::Duration;

use ozint_core::{OzintError, Result};
use serde::{Deserialize, Serialize};

/// Hard cap for one completion. A hung provider must surface, not stall a layer.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);

pub const DEFAULT_MODEL: &str = "gpt-4o-mini";
pub const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatRole {
    System,
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMsg {
    pub role: ChatRole,
    pub content: String,
}

impl ChatMsg {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::System,
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::User,
            content: content.into(),
        }
    }
}

/// Per-call knobs. `Default` is "no system prompt, prose out, provider's own temperature".
#[derive(Debug, Clone, Default)]
pub struct CallOpts {
    /// Override `OZINT_LLM_MODEL` for this call.
    pub model: Option<String>,
    pub system: Option<String>,
    /// Ask for `response_format: json_object`. Not every provider honours it.
    pub json_mode: bool,
    pub temperature: Option<f64>,
}

fn base_url() -> String {
    ozint_core::config::or_default("OZINT_LLM_BASE_URL", DEFAULT_BASE_URL)
}

/// Is an LLM configured at all?
///
/// Callers use this to decide between "we asked and it failed" and "we never asked" —
/// a distinction the UI shows, because an absent narration is not a broken one.
pub fn llm_configured() -> bool {
    ozint_core::config::optional("OZINT_LLM_API_KEY").is_some()
}

/// Build OpenAI-style messages, prepending a `system` message iff one is given. Pure.
pub fn build_messages(prompt: &str, system: Option<&str>) -> Vec<ChatMsg> {
    match system {
        Some(s) => vec![ChatMsg::system(s), ChatMsg::user(prompt)],
        None => vec![ChatMsg::user(prompt)],
    }
}

/// One non-streaming chat completion.
///
/// Returns `Err(MissingEnv)` when no key is set — callers treat that as "the tier is off"
/// and fall back, rather than surfacing it as a failure.
pub async fn call_llm(prompt: &str, opts: CallOpts) -> Result<String> {
    let api_key = ozint_core::config::required("OZINT_LLM_API_KEY")?;
    let model = opts
        .model
        .unwrap_or_else(|| ozint_core::config::or_default("OZINT_LLM_MODEL", DEFAULT_MODEL));

    let mut body = serde_json::json!({
        "model": model,
        "messages": build_messages(prompt, opts.system.as_deref()),
    });
    if opts.json_mode {
        body["response_format"] = serde_json::json!({ "type": "json_object" });
    }
    if let Some(t) = opts.temperature {
        body["temperature"] = serde_json::json!(t);
    }

    let client = ozint_core::http::client();
    let call = async {
        let response = client
            .post(format!("{}/chat/completions", base_url()))
            .bearer_auth(&api_key)
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(OzintError::Upstream {
                service: "llm",
                status: response.status().as_u16(),
            });
        }

        #[derive(Deserialize)]
        struct Message {
            content: Option<String>,
        }
        #[derive(Deserialize)]
        struct Choice {
            message: Option<Message>,
        }
        #[derive(Deserialize)]
        struct ChatResponse {
            choices: Option<Vec<Choice>>,
        }

        let parsed: ChatResponse = response.json().await?;
        Ok(parsed
            .choices
            .and_then(|c| c.into_iter().next())
            .and_then(|c| c.message)
            .and_then(|m| m.content)
            .map(|s| s.trim().to_string())
            .unwrap_or_default())
    };

    match tokio::time::timeout(CALL_TIMEOUT, call).await {
        Ok(result) => result,
        Err(_) => Err(OzintError::Other(anyhow::anyhow!("llm: call timed out"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_messages_prepends_system_when_given() {
        let msgs = build_messages("hi", Some("you are an analyst"));
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, "you are an analyst");
        assert_eq!(msgs[1].content, "hi");
    }

    #[test]
    fn build_messages_omits_system_when_absent() {
        let msgs = build_messages("hi", None);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "hi");
    }
}
