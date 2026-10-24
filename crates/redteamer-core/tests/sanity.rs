use redteamer_core::error::RedTeamerError;
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, TargetAdapter,
};
use redteamer_core::types::OwaspCategory;
use std::sync::Arc;

struct MockAdapter;

#[async_trait::async_trait]
impl TargetAdapter for MockAdapter {
    fn info(&self) -> &AdapterInfo {
        todo!()
    }
    async fn send_chat(
        &self,
        _messages: &[ChatMessage],
        _opts: &GenerationOptions,
    ) -> Result<AdapterResponse, RedTeamerError> {
        todo!()
    }
}

#[tokio::test]
async fn test_object_safety() {
    let adapter: Arc<dyn TargetAdapter> = Arc::new(MockAdapter);
    assert!(Arc::strong_count(&adapter) == 1);
}

#[test]
fn test_owasp_enums() {
    let cat = OwaspCategory::PromptInjection;
    assert_eq!(cat.name(), "Prompt Injection");
    assert!(cat.impact_score() > 0.0);
}
