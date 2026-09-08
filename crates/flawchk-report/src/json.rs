use flawchk_core::AssessmentResult;

pub fn render_json(result: &AssessmentResult) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(result)
}
