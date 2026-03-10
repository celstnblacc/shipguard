use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};

#[derive(Deserialize)]
struct Input {
    files: Vec<String>,
}

#[derive(Serialize)]
struct Finding {
    rule_id: &'static str,
    severity: &'static str,
    file_path: String,
    line_number: usize,
    line_content: String,
    message: &'static str,
    cwe_id: &'static str,
    fix_hint: &'static str,
}

#[derive(Serialize)]
struct Output {
    findings: Vec<Finding>,
}

fn skip_false_positive(line: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    let trimmed = line.trim_start();

    if trimmed.starts_with('#') {
        return true;
    }

    let placeholders = [
        "_NOT_REAL",
        "_PLACEHOLDER",
        "YOUR_",
        "CHANGE_ME",
        "REPLACE_ME",
    ];
    if placeholders.iter().any(|k| upper.contains(k)) {
        return true;
    }

    if line.contains('$') || line.contains("${") || line.contains("${{") {
        return true;
    }

    if line.contains('<') || line.contains('>') {
        return true;
    }

    false
}

fn main() {
    let mut stdin = String::new();
    if io::stdin().read_to_string(&mut stdin).is_err() {
        std::process::exit(2);
    }

    let input: Input = match serde_json::from_str(&stdin) {
        Ok(v) => v,
        Err(_) => std::process::exit(2),
    };

    let aws_re = Regex::new(r"AKIA[0-9A-Z]{16}").expect("aws regex");
    let gcp_re = Regex::new(r"AIza[0-9A-Za-z\-_]{35}").expect("gcp regex");
    let gh_re = Regex::new(r"(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36,}").expect("gh regex");

    let mut findings: Vec<Finding> = Vec::new();

    for file_path in input.files {
        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for (idx, raw_line) in content.lines().enumerate() {
            if skip_false_positive(raw_line) {
                continue;
            }
            let line_number = idx + 1;
            let line_content = raw_line.to_string();

            if aws_re.is_match(raw_line) {
                findings.push(Finding {
                    rule_id: "SEC-001",
                    severity: "critical",
                    file_path: file_path.clone(),
                    line_number,
                    line_content: line_content.clone(),
                    message: "AWS access key ID detected in file",
                    cwe_id: "CWE-798",
                    fix_hint: "Remove the key and rotate it in AWS IAM; use environment variables instead",
                });
            }
            if gcp_re.is_match(raw_line) {
                findings.push(Finding {
                    rule_id: "SEC-002",
                    severity: "critical",
                    file_path: file_path.clone(),
                    line_number,
                    line_content: line_content.clone(),
                    message: "GCP API key detected in file",
                    cwe_id: "CWE-798",
                    fix_hint: "Remove the key and rotate it in GCP Console; use environment variables instead",
                });
            }
            if gh_re.is_match(raw_line) {
                findings.push(Finding {
                    rule_id: "SEC-003",
                    severity: "critical",
                    file_path: file_path.clone(),
                    line_number,
                    line_content,
                    message: "GitHub personal access token detected in file",
                    cwe_id: "CWE-798",
                    fix_hint: "Revoke the token at github.com/settings/tokens; use GITHUB_TOKEN env var in CI",
                });
            }
        }
    }

    let output = Output { findings };
    match serde_json::to_string(&output) {
        Ok(s) => println!("{s}"),
        Err(_) => std::process::exit(2),
    }
}
