use flawchk_core::{CheckMetadata, Finding, Profile};
use flawchk_distro::PlatformAdapter;

pub trait Rule: Send + Sync {
    fn metadata(&self) -> CheckMetadata;
    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding;
}

pub struct RuleRegistry {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn register(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    pub fn register_all_builtin(&mut self) {
        crate::ssh::register_ssh_rules(self);
        crate::kernel::register_kernel_rules(self);
        crate::users::register_user_rules(self);
        crate::filesystem::register_filesystem_rules(self);
        crate::network::register_network_rules(self);
        crate::logging::register_logging_rules(self);
    }

    pub fn rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }

    pub fn get_rule(&self, id: &str) -> Option<&dyn Rule> {
        self.rules.iter().find(|r| r.metadata().id.eq_ignore_ascii_case(id)).map(|r| r.as_ref())
    }

    pub fn evaluate_profile(&self, profile: &Profile, platform: &dyn PlatformAdapter) -> Vec<Finding> {
        self.rules
            .iter()
            .filter(|rule| {
                let meta = rule.metadata();

                // Excluded rule filter
                if let Some(ref excluded) = profile.excluded_rules {
                    if excluded.iter().any(|e| e.eq_ignore_ascii_case(&meta.id)) {
                        return false;
                    }
                }

                // Included rule filter
                if let Some(ref included) = profile.included_rules {
                    return included.iter().any(|i| i.eq_ignore_ascii_case(&meta.id));
                }

                // Category filter
                if !profile.categories.is_empty() {
                    let cat_str = format!("{:?}", meta.category).to_lowercase();
                    if !profile.categories.iter().any(|c| c.to_lowercase() == cat_str) {
                        return false;
                    }
                }

                // Severity filter
                if let Some(ref min_sev_str) = profile.min_severity {
                    if let Ok(min_sev) = min_sev_str.parse::<flawchk_core::Severity>() {
                        if meta.severity < min_sev {
                            return false;
                        }
                    }
                }

                true
            })
            .map(|rule| rule.evaluate(platform))
            .collect()
    }
}
