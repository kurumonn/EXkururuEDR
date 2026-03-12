use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::time::Instant;

#[derive(Clone)]
struct RawEvent {
    event_id: String,
    event_type: String,
    category: String,
    severity: String,
    hostname: String,
    user: String,
    src_ip: String,
    dst_ip: String,
}

fn main() {
    let events = arg_usize("--events", 1000);
    let loops = arg_usize("--loops", 20);
    let input_csv = arg_string("--input-csv", "");
    let out_jsonl = arg_string("--out-jsonl", "");

    let source_id = env::var("EDR_AGENT_SOURCE_ID").unwrap_or_else(|_| "edr-agent-01".to_string());
    let secret = env::var("EDR_AGENT_SHARED_SECRET").unwrap_or_else(|_| "replace-with-test-secret".to_string());
    let timestamp = "1700000000";
    let body = br#"{"probe":"auth"}"#;

    let signature = sign_payload(timestamp, body, &secret);

    let rss_start_kb = current_rss_kb();
    let t0 = Instant::now();
    let mut normalized_total = 0usize;
    let mut auth_ok_total = 0usize;

    let raw_pool = if input_csv.is_empty() {
        (0..events).map(make_raw_event).collect::<Vec<_>>()
    } else {
        load_events_csv(&input_csv)
    };
    let events_per_loop = raw_pool.len();
    let mut writer: Option<fs::File> = if out_jsonl.is_empty() {
        None
    } else {
        Some(fs::File::create(&out_jsonl).expect("failed to create out-jsonl file"))
    };

    for _ in 0..loops {
        let ok = verify_signature(timestamp, body, &signature, &secret);
        if ok {
            auth_ok_total += 1;
        }
        for raw in &raw_pool {
            let normalized = normalize_event(raw, &source_id);
            if let Some(w) = writer.as_mut() {
                let _ = writeln!(w, "{}", normalized);
            }
            normalized_total += 1;
        }
    }

    let elapsed = t0.elapsed();
    let rss_end_kb = current_rss_kb();
    let vmhwm_kb = vmhwm_kb();
    let elapsed_sec = elapsed.as_secs_f64();
    let throughput = if elapsed_sec > 0.0 {
        normalized_total as f64 / elapsed_sec
    } else {
        0.0
    };
    let delta_kb = rss_end_kb.saturating_sub(rss_start_kb);

    println!("{{");
    println!("  \"runtime\": \"rust-agent-lite\",");
    println!("  \"events_per_loop\": {},", events_per_loop);
    println!("  \"loops\": {},", loops);
    println!("  \"normalized_total\": {},", normalized_total);
    println!("  \"auth_total\": {},", loops);
    println!("  \"auth_ok_total\": {},", auth_ok_total);
    println!(
        "  \"auth_success_rate\": {:.6},",
        if loops > 0 {
            auth_ok_total as f64 / loops as f64
        } else {
            0.0
        }
    );
    println!("  \"elapsed_wall_sec\": {:.6},", elapsed_sec);
    println!("  \"throughput_events_per_sec\": {:.2},", throughput);
    println!("  \"rss_start_kb\": {},", rss_start_kb);
    println!("  \"rss_end_kb\": {},", rss_end_kb);
    println!("  \"rss_delta_kb\": {},", delta_kb);
    println!("  \"rss_start_mb\": {:.3},", rss_start_kb as f64 / 1024.0);
    println!("  \"rss_end_mb\": {:.3},", rss_end_kb as f64 / 1024.0);
    println!("  \"rss_delta_mb\": {:.3},", delta_kb as f64 / 1024.0);
    println!("  \"max_rss_kb\": {},", vmhwm_kb);
    println!("  \"max_rss_mb\": {:.3},", vmhwm_kb as f64 / 1024.0);
    println!(
        "  \"input_mode\": \"{}\"",
        if input_csv.is_empty() { "synthetic" } else { "csv" }
    );
    println!("}}");
}

fn arg_usize(flag: &str, default: usize) -> usize {
    let args: Vec<String> = env::args().collect();
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            if let Ok(v) = args[i + 1].parse::<usize>() {
                return v;
            }
        }
    }
    default
}

fn arg_string(flag: &str, default: &str) -> String {
    let args: Vec<String> = env::args().collect();
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return args[i + 1].clone();
        }
    }
    default.to_string()
}

fn make_raw_event(i: usize) -> RawEvent {
    RawEvent {
        event_id: format!("raw-{i}"),
        event_type: if i % 2 == 0 {
            "SUSPICIOUS_PROCESS".to_string()
        } else {
            "SUSPICIOUS_NETWORK".to_string()
        },
        category: if i % 5 == 0 {
            "file".to_string()
        } else if i % 2 == 0 {
            "process".to_string()
        } else {
            "network".to_string()
        },
        severity: if i % 3 == 0 {
            "medium".to_string()
        } else {
            "high".to_string()
        },
        hostname: format!("host-{}", i % 50),
        user: format!("user-{}", i % 20),
        src_ip: format!("10.10.{}.{}", (i / 255) % 255, i % 255),
        dst_ip: "198.51.100.10".to_string(),
    }
}

fn normalize_event(raw: &RawEvent, source_id: &str) -> String {
    let score = match raw.severity.as_str() {
        "critical" => 95.0,
        "high" => 80.0,
        "low" => 20.0,
        _ => 50.0,
    };
    format!(
        "{{\"schema_version\":\"common_security_event_v1\",\"event_id\":\"{}\",\"product\":\"exkururuedr\",\"category\":\"{}\",\"event_type\":\"{}\",\"severity\":\"{}\",\"score\":{},\"labels\":[\"edr\",\"endpoint\"],\"asset_id\":\"{}\",\"hostname\":\"{}\",\"user\":\"{}\",\"src_ip\":\"{}\",\"dst_ip\":\"{}\",\"source_id\":\"{}\"}}",
        raw.event_id,
        raw.category,
        raw.event_type,
        raw.severity,
        score,
        raw.hostname,
        raw.hostname,
        raw.user,
        raw.src_ip,
        raw.dst_ip,
        source_id
    )
}

fn load_events_csv(path: &str) -> Vec<RawEvent> {
    let mut out = Vec::new();
    let content = fs::read_to_string(path).unwrap_or_default();
    for (idx, line) in content.lines().enumerate() {
        if idx == 0 && line.contains("event_id") {
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 8 {
            continue;
        }
        out.push(RawEvent {
            event_id: cols[0].trim().to_string(),
            event_type: cols[1].trim().to_string(),
            category: cols[2].trim().to_string(),
            severity: cols[3].trim().to_string(),
            hostname: cols[4].trim().to_string(),
            user: cols[5].trim().to_string(),
            src_ip: cols[6].trim().to_string(),
            dst_ip: cols[7].trim().to_string(),
        });
    }
    out
}

fn sign_payload(timestamp: &str, body: &[u8], secret: &str) -> String {
    // Offline build friendly lightweight signature for benchmark-only flow.
    // Production auth must use HMAC-SHA256 (implemented in Python service side).
    let mut hasher = DefaultHasher::new();
    timestamp.hash(&mut hasher);
    ".".hash(&mut hasher);
    body.hash(&mut hasher);
    secret.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn verify_signature(timestamp: &str, body: &[u8], recv_sig: &str, secret: &str) -> bool {
    let expected = sign_payload(timestamp, body, secret);
    constant_time_eq(expected.as_bytes(), recv_sig.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut v = 0u8;
    for i in 0..a.len() {
        v |= a[i] ^ b[i];
    }
    v == 0
}

fn current_rss_kb() -> usize {
    parse_status_field_kb("VmRSS").unwrap_or(0)
}

fn vmhwm_kb() -> usize {
    parse_status_field_kb("VmHWM").unwrap_or(0)
}

fn parse_status_field_kb(key: &str) -> Option<usize> {
    let content = fs::read_to_string("/proc/self/status").ok()?;
    for line in content.lines() {
        if let Some((name, rest)) = line.split_once(':') {
            if name == key {
                let n = rest.trim().split_whitespace().next()?;
                return n.parse::<usize>().ok();
            }
        }
    }
    None
}
