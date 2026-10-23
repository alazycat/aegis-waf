use std::collections::BTreeMap;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TxStore {
    values: BTreeMap<String, String>,
}

impl TxStore {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn set(&mut self, name: &str, value: String) {
        self.values.insert(name.to_ascii_lowercase(), value);
    }

    pub fn remove(&mut self, name: &str) -> Option<String> {
        self.values.remove(&name.to_ascii_lowercase())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.values.values().map(String::as_str)
    }
}

pub fn expand_macros(template: &str, tx: &TxStore) -> String {
    let mut output = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("%{") {
        output.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find('}') {
            let name = after[..end].trim().to_ascii_lowercase();
            if let Some(tx_name) = name.strip_prefix("tx.") {
                if let Some(value) = tx.get(tx_name) {
                    output.push_str(value);
                }
            } else if name == "matched_var" || name == "matched_var_name" {
                if let Some(value) = tx.get(&name) {
                    output.push_str(value);
                }
            }
            rest = &after[end + 1..];
        } else {
            output.push_str(&rest[start..]);
            return output;
        }
    }
    output.push_str(rest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_names_case_insensitively() {
        let mut tx = TxStore::default();
        tx.set("Score", "5".to_string());
        assert_eq!(tx.get("score"), Some("5"));
        assert_eq!(tx.get("SCORE"), Some("5"));
    }

    #[test]
    fn removes_values() {
        let mut tx = TxStore::default();
        tx.set("a", "1".to_string());
        assert_eq!(tx.remove("A"), Some("1".to_string()));
        assert_eq!(tx.get("a"), None);
    }

    #[test]
    fn expands_tx_macros_and_unknown_values_to_empty() {
        let mut tx = TxStore::default();
        tx.set("name", "world".to_string());
        assert_eq!(expand_macros("hello %{tx.name}!", &tx), "hello world!");
        assert_eq!(expand_macros("x=%{tx.missing};", &tx), "x=;");
        assert_eq!(expand_macros("%{ip.remote}", &tx), "");
        assert_eq!(expand_macros("plain", &tx), "plain");
    }
}
