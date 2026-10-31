//! Terminal output shared by all commands so they read alike: aligned rows with a mark, an
//! outcome line, then `→` hints naming the next command. Colour only on a terminal: anstream
//! strips it when piped and honours NO_COLOR.

use anstream::{eprintln, print, println};
use anstyle::{AnsiColor, Style};
use std::io::Write;
use std::time::Duration;

const BOLD: Style = Style::new().bold();
const DIM: Style = Style::new().dimmed();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Ok,
    Warn,
    Bad,
    Off,
    Unknown,
}

impl Mark {
    fn look(self) -> (&'static str, Style) {
        match self {
            Mark::Ok => ("✓", AnsiColor::Green.on_default().bold()),
            Mark::Warn => ("!", AnsiColor::Yellow.on_default().bold()),
            Mark::Bad => ("✗", AnsiColor::Red.on_default().bold()),
            Mark::Off => ("○", DIM),
            Mark::Unknown => ("?", DIM),
        }
    }
}

pub fn heading(text: &str) {
    println!("{BOLD}{text}{BOLD:#}");
}

/// `  Label       ✓ value  detail`
pub fn row(label: &str, mark: Mark, value: &str, detail: &str) {
    let (glyph, style) = mark.look();
    if detail.is_empty() {
        println!("  {label:<11} {style}{glyph} {value}{style:#}");
    } else {
        println!("  {label:<11} {style}{glyph} {value}{style:#}  {DIM}{detail}{DIM:#}");
    }
}

/// The outcome of a command, after a blank line.
pub fn outcome(mark: Mark, text: &str) {
    let (glyph, style) = mark.look();
    println!();
    println!("{style}{glyph}{style:#} {BOLD}{text}{BOLD:#}");
}

/// `→ what: command`; an empty `command` prints only `what`.
pub fn hint(what: &str, command: &str) {
    if command.is_empty() {
        println!("{DIM}→{DIM:#} {what}");
    } else {
        println!("{DIM}→{DIM:#} {what}: {BOLD}{command}{BOLD:#}");
    }
}

pub fn prompt(text: &str) {
    print!("{BOLD}{text}{BOLD:#} ");
    let _ = std::io::stdout().flush();
}

pub fn error(e: &anyhow::Error) {
    let (glyph, style) = Mark::Bad.look();
    eprintln!("{style}{glyph} error:{style:#} {e:#}");
}

/// `4m 05s`, `12s`.
pub fn duration(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 60 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn durations() {
        use std::time::Duration;
        assert_eq!(super::duration(Duration::from_secs(245)), "4m 05s");
        assert_eq!(super::duration(Duration::from_secs(12)), "12s");
    }
}
