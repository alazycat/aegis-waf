use super::args::split_args;
use super::scanner::LogicalLine;
use crate::error::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    Rule(RuleAst),
    Action(ActionAst),
    DefaultAction(DefaultActionAst),
    Marker(String),
    Include(String),
    Unknown {
        name: String,
        line: usize,
        column: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleAst {
    pub variables: String,
    pub operator: String,
    pub actions: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionAst {
    pub actions: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultActionAst {
    pub actions: String,
    pub line: usize,
    pub column: usize,
}

pub fn parse_directive(line: &LogicalLine) -> Result<Directive, ParseError> {
    let text = line.text.trim();
    let name_end = text.find(char::is_whitespace).unwrap_or(text.len());
    let name = &text[..name_end];
    let rest = text[name_end..].trim();

    let fail = |column: usize, message: String| ParseError {
        line: line.line,
        column,
        message,
    };

    let lower_name = name.to_ascii_lowercase();
    match lower_name.as_str() {
        "secrule" => {
            let args = split_args(rest).map_err(|message| fail(1, message))?;
            if args.len() != 3 {
                return Err(fail(
                    args.first().map(|arg| arg.column).unwrap_or(1),
                    format!("SecRule expects 3 arguments, got {}", args.len()),
                ));
            }
            Ok(Directive::Rule(RuleAst {
                variables: args[0].value.clone(),
                operator: args[1].value.clone(),
                actions: args[2].value.clone(),
                line: line.line,
                column: args[0].column,
            }))
        }
        "secaction" | "secdefaultaction" => {
            let args = split_args(rest).map_err(|message| fail(1, message))?;
            if args.len() != 1 {
                return Err(fail(
                    args.first().map(|arg| arg.column).unwrap_or(1),
                    format!("{name} expects 1 argument, got {}", args.len()),
                ));
            }
            let actions = args[0].value.clone();
            let column = args[0].column;
            if name.eq_ignore_ascii_case("secaction") {
                Ok(Directive::Action(ActionAst {
                    actions,
                    line: line.line,
                    column,
                }))
            } else {
                Ok(Directive::DefaultAction(DefaultActionAst {
                    actions,
                    line: line.line,
                    column,
                }))
            }
        }
        "secmarker" | "include" => {
            let args = split_args(rest).map_err(|message| fail(1, message))?;
            if args.len() != 1 {
                return Err(fail(
                    args.first().map(|arg| arg.column).unwrap_or(1),
                    format!("{name} expects 1 argument, got {}", args.len()),
                ));
            }
            let value = args[0].value.clone();
            if name.eq_ignore_ascii_case("secmarker") {
                Ok(Directive::Marker(value))
            } else {
                Ok(Directive::Include(value))
            }
        }
        _ => Ok(Directive::Unknown {
            name: name.to_string(),
            line: line.line,
            column: 1,
        }),
    }
}
