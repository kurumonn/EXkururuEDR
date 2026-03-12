use std::env;
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone)]
struct Rule {
    enabled: bool,
    event_types: Vec<String>,
    categories: Vec<String>,
    severities: Vec<String>,
    labels_contains: Vec<String>,
    min_score: f64,
    action: String,
}

#[derive(Debug, Clone)]
struct Event {
    event_type: String,
    category: String,
    severity: String,
    score: f64,
    labels: Vec<String>,
}

#[derive(Debug)]
struct InputData {
    loops: usize,
    rules: Vec<Rule>,
    events: Vec<Event>,
}

fn parse_list(value: &str) -> Vec<String> {
    if value.is_empty() {
        return Vec::new();
    }
    value
        .split(',')
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

fn parse_input(content: &str) -> Result<InputData, String> {
    let mut loops = 0usize;
    let mut rules = Vec::<Rule>::new();
    let mut events = Vec::<Event>::new();
    for (line_no, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.is_empty() {
            continue;
        }
        match parts[0] {
            "CONFIG" => {
                if parts.len() != 2 {
                    return Err(format!("invalid CONFIG line {}", line_no + 1));
                }
                loops = parts[1]
                    .parse::<usize>()
                    .map_err(|_| format!("invalid loops line {}", line_no + 1))?;
            }
            "RULE" => {
                if parts.len() != 10 {
                    return Err(format!("invalid RULE line {}", line_no + 1));
                }
                rules.push(Rule {
                    enabled: parts[2] == "1",
                    event_types: parse_list(parts[3]),
                    categories: parse_list(parts[4]),
                    severities: parse_list(parts[5])
                        .into_iter()
                        .map(|v| v.to_lowercase())
                        .collect(),
                    labels_contains: parse_list(parts[6]),
                    min_score: parts[7]
                        .parse::<f64>()
                        .map_err(|_| format!("invalid min_score line {}", line_no + 1))?,
                    action: parts[8].to_string(),
                });
            }
            "EVENT" => {
                if parts.len() != 6 {
                    return Err(format!("invalid EVENT line {}", line_no + 1));
                }
                events.push(Event {
                    event_type: parts[1].to_string(),
                    category: parts[2].to_string(),
                    severity: parts[3].to_lowercase(),
                    score: parts[4]
                        .parse::<f64>()
                        .map_err(|_| format!("invalid event score line {}", line_no + 1))?,
                    labels: parse_list(parts[5]),
                });
            }
            _ => return Err(format!("unknown line type {}", line_no + 1)),
        }
    }
    if loops == 0 {
        return Err("missing loops".to_string());
    }
    Ok(InputData { loops, rules, events })
}

fn action_priority(action: &str) -> i32 {
    match action {
        "allow" => 0,
        "observe" => 1,
        "limit" => 2,
        "challenge" => 3,
        "block" => 4,
        _ => 0,
    }
}

fn matches(event: &Event, rule: &Rule) -> bool {
    if !rule.event_types.is_empty() && !rule.event_types.iter().any(|v| v == &event.event_type) {
        return false;
    }
    if !rule.categories.is_empty() && !rule.categories.iter().any(|v| v == &event.category) {
        return false;
    }
    if !rule.severities.is_empty() && !rule.severities.iter().any(|v| v == &event.severity) {
        return false;
    }
    if event.score < rule.min_score {
        return false;
    }
    if !rule.labels_contains.is_empty() {
        for required in &rule.labels_contains {
            if !event.labels.iter().any(|label| label == required) {
                return false;
            }
        }
    }
    true
}

fn evaluate_once(events: &[Event], rules: &[Rule]) -> usize {
    let mut blocked = 0usize;
    for event in events {
        let mut top_priority = -1i32;
        for rule in rules {
            if !rule.enabled {
                continue;
            }
            if matches(event, rule) {
                let p = action_priority(rule.action.as_str());
                if p > top_priority {
                    top_priority = p;
                }
            }
        }
        if top_priority >= action_priority("block") {
            blocked += 1;
        }
    }
    blocked
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(input_path) = args.next() else {
        eprintln!("usage: rust_rule_bench <input_path>");
        std::process::exit(2);
    };
    let content = match fs::read_to_string(&input_path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed_to_read_input: {error}");
            std::process::exit(2);
        }
    };
    let data = match parse_input(&content) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed_to_parse_input: {error}");
            std::process::exit(2);
        }
    };
    let started = Instant::now();
    let mut total_blocked = 0usize;
    for _ in 0..data.loops {
        total_blocked += evaluate_once(&data.events, &data.rules);
    }
    let elapsed_sec = started.elapsed().as_secs_f64();
    let loops_per_sec = if elapsed_sec > 0.0 {
        data.loops as f64 / elapsed_sec
    } else {
        0.0
    };
    println!(
        "{{\"loops\":{},\"rule_count\":{},\"event_count\":{},\"total_blocked\":{},\"elapsed_sec\":{},\"loops_per_sec\":{}}}",
        data.loops,
        data.rules.len(),
        data.events.len(),
        total_blocked,
        elapsed_sec,
        loops_per_sec
    );
}
