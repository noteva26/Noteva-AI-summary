//! Noteva AI 摘要 WASM 插件
//!
//! 监听 article_after_create 和 plugin_activate 钩子，调用 AI API 生成文章摘要。
//! - article_after_create: 新文章创建时自动生成摘要
//! - plugin_activate: 插件启用时为所有存量文章批量生成摘要
//!
//! 需要 `network`、`storage`、`read_articles` 权限。

use std::alloc::{alloc, Layout};
use std::slice;

// ============================================================
// 宿主函数声明
// ============================================================

extern "C" {
    fn host_http_request(
        method_ptr: i32, method_len: i32,
        url_ptr: i32, url_len: i32,
        headers_ptr: i32, headers_len: i32,
        body_ptr: i32, body_len: i32,
    ) -> i32;

    fn host_storage_get(key_ptr: i32, key_len: i32) -> i32;

    fn host_storage_set(
        key_ptr: i32, key_len: i32,
        value_ptr: i32, value_len: i32,
    ) -> i32;

    fn host_storage_delete(key_ptr: i32, key_len: i32) -> i32;

    fn host_log(
        level_ptr: i32, level_len: i32,
        msg_ptr: i32, msg_len: i32,
    );

    fn host_query_articles(filter_ptr: i32, filter_len: i32) -> i32;
}

// ============================================================
// 内存分配器
// ============================================================

#[no_mangle]
pub extern "C" fn allocate(size: i32) -> i32 {
    if size <= 0 || size > 4 * 1024 * 1024 { return 0; }
    let layout = match Layout::from_size_align(size as usize, 1) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() { 0 } else { ptr as i32 }
}

// ============================================================
// 宿主函数封装
// ============================================================

fn log(level: &str, msg: &str) {
    unsafe {
        host_log(
            level.as_ptr() as i32, level.len() as i32,
            msg.as_ptr() as i32, msg.len() as i32,
        );
    }
}

fn storage_get(key: &str) -> Option<String> {
    let result_ptr = unsafe {
        host_storage_get(key.as_ptr() as i32, key.len() as i32)
    };
    if result_ptr <= 0 { return None; }
    let json = read_result(result_ptr)?;
    // Response: {"found":true,"value":"..."}
    let found = extract_json_string(&json, "found");
    if found.as_deref() != Some("true") {
        // Try checking as boolean
        if !json.contains("\"found\":true") { return None; }
    }
    extract_json_string(&json, "value")
}

fn storage_set(key: &str, value: &str) -> bool {
    let result = unsafe {
        host_storage_set(
            key.as_ptr() as i32, key.len() as i32,
            value.as_ptr() as i32, value.len() as i32,
        )
    };
    result > 0
}

fn storage_delete(key: &str) -> bool {
    let result = unsafe {
        host_storage_delete(key.as_ptr() as i32, key.len() as i32)
    };
    result > 0
}

fn http_post(url: &str, headers: &str, body: &[u8]) -> Option<String> {
    let method = "POST";
    let result_ptr = unsafe {
        host_http_request(
            method.as_ptr() as i32, method.len() as i32,
            url.as_ptr() as i32, url.len() as i32,
            headers.as_ptr() as i32, headers.len() as i32,
            body.as_ptr() as i32, body.len() as i32,
        )
    };
    if result_ptr <= 0 { return None; }
    read_result(result_ptr)
}

fn query_articles() -> Option<String> {
    let filter = "{}";
    let result_ptr = unsafe {
        host_query_articles(filter.as_ptr() as i32, filter.len() as i32)
    };
    if result_ptr <= 0 { return None; }
    read_result(result_ptr)
}

fn read_result(ptr: i32) -> Option<String> {
    unsafe {
        let rp = ptr as usize;
        let len_bytes = slice::from_raw_parts(rp as *const u8, 4);
        let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        if len == 0 { return None; }
        let data = slice::from_raw_parts((rp + 4) as *const u8, len);
        String::from_utf8(data.to_vec()).ok()
    }
}

// ============================================================
// JSON 工具
// ============================================================

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\"", key);
    let pos = json.find(&search)?;
    let rest = &json[pos + search.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    if !after.starts_with('"') { return None; }

    let bytes = after.as_bytes();
    let mut i = 1;
    let mut result_bytes: Vec<u8> = Vec::new();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => {
                match bytes[i + 1] {
                    b'"' => { result_bytes.push(b'"'); i += 2; }
                    b'\\' => { result_bytes.push(b'\\'); i += 2; }
                    b'n' => { result_bytes.push(b'\n'); i += 2; }
                    b'r' => { result_bytes.push(b'\r'); i += 2; }
                    b't' => { result_bytes.push(b'\t'); i += 2; }
                    b'/' => { result_bytes.push(b'/'); i += 2; }
                    b'u' if i + 5 < bytes.len() => {
                        // \uXXXX unicode escape
                        let hex = &bytes[i + 2..i + 6];
                        if let Some(cp) = parse_hex4(hex) {
                            // Check for surrogate pair \uD800-\uDBFF followed by \uDC00-\uDFFF
                            if cp >= 0xD800 && cp <= 0xDBFF && i + 11 < bytes.len()
                                && bytes[i + 6] == b'\\' && bytes[i + 7] == b'u'
                            {
                                if let Some(cp2) = parse_hex4(&bytes[i + 8..i + 12]) {
                                    if cp2 >= 0xDC00 && cp2 <= 0xDFFF {
                                        let full = 0x10000 + ((cp as u32 - 0xD800) << 10) + (cp2 as u32 - 0xDC00);
                                        if let Some(ch) = char::from_u32(full) {
                                            let mut buf = [0u8; 4];
                                            let s = ch.encode_utf8(&mut buf);
                                            result_bytes.extend_from_slice(s.as_bytes());
                                        }
                                        i += 12;
                                        continue;
                                    }
                                }
                            }
                            if let Some(ch) = char::from_u32(cp as u32) {
                                let mut buf = [0u8; 4];
                                let s = ch.encode_utf8(&mut buf);
                                result_bytes.extend_from_slice(s.as_bytes());
                            }
                            i += 6;
                        } else {
                            result_bytes.push(b'\\');
                            result_bytes.push(b'u');
                            i += 2;
                        }
                    }
                    _ => { result_bytes.push(b'\\'); result_bytes.push(bytes[i + 1]); i += 2; }
                }
            }
            b'"' => return String::from_utf8(result_bytes).ok(),
            b => { result_bytes.push(b); i += 1; }
        }
    }
    None
}

fn parse_hex4(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 4 { return None; }
    let mut val: u16 = 0;
    for &b in &bytes[..4] {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        val = val * 16 + digit as u16;
    }
    Some(val)
}

fn extract_json_number(json: &str, key: &str) -> Option<i64> {
    let search = format!("\"{}\"", key);
    let pos = json.find(&search)?;
    let rest = &json[pos + search.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    let mut num_str = String::new();
    for ch in after.chars() {
        if ch.is_ascii_digit() || ch == '-' { num_str.push(ch); }
        else if !num_str.is_empty() { break; }
    }
    num_str.parse().ok()
}

fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('"', "\\\"")
     .replace('\n', "\\n")
     .replace('\r', "\\r")
     .replace('\t', "\\t")
}

/// Extract content from OpenAI-compatible response: choices[0].message.content
/// Searches for "message" key first, then "content" within that scope,
/// avoiding false matches on other "content" fields in the response.
fn extract_message_content(json: &str) -> Option<String> {
    // Find "message" key position
    let msg_search = "\"message\"";
    let msg_pos = json.find(msg_search)?;
    let after_msg = &json[msg_pos + msg_search.len()..];

    // Skip to the colon and opening brace of the message object
    let colon = after_msg.find(':')?;
    let rest = after_msg[colon + 1..].trim_start();

    // Now extract "content" from within this message substring
    extract_json_string(rest, "content")
}

fn write_output(json: &str) -> i32 {
    let bytes = json.as_bytes();
    let total = 4 + bytes.len();
    let layout = match Layout::from_size_align(total, 1) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() { return 0; }
    let len_bytes = (bytes.len() as u32).to_le_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(len_bytes.as_ptr(), ptr, 4);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.add(4), bytes.len());
    }
    ptr as i32
}

/// Extract all JSON objects from a JSON array string.
/// Returns a list of (start, end) byte positions for each object.
fn extract_json_objects(json: &str) -> Vec<&str> {
    let mut objects = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let mut in_string = false;
    let mut escape = false;

    for (i, ch) in json.char_indices() {
        if escape { escape = false; continue; }
        if ch == '\\' && in_string { escape = true; continue; }
        if ch == '"' { in_string = !in_string; continue; }
        if in_string { continue; }

        match ch {
            '{' => {
                if depth == 0 { start = i; }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    objects.push(&json[start..=i]);
                }
            }
            _ => {}
        }
    }
    objects
}

// ============================================================
// AI 摘要生成（共用逻辑）
// ============================================================

fn generate_summary(
    article_id: i64,
    title: &str,
    content: &str,
    api_url: &str,
    api_key: &str,
    model: &str,
    system_prompt: &str,
    max_content_length: usize,
) -> Option<String> {
    let truncated = if content.len() > max_content_length {
        // Truncate at char boundary to avoid splitting UTF-8 sequences
        let mut end = max_content_length;
        while end > 0 && !content.is_char_boundary(end) {
            end -= 1;
        }
        &content[..end]
    } else {
        content
    };

    let user_msg = format!("标题：{}\n\n内容：{}", title, truncated);
    let request_body = format!(
        r#"{{"model":"{}","messages":[{{"role":"system","content":"{}"}},{{"role":"user","content":"{}"}}],"max_tokens":200,"temperature":0.3}}"#,
        escape_json_string(model),
        escape_json_string(system_prompt),
        escape_json_string(&user_msg)
    );
    let headers = format!(
        r#"{{"Content-Type":"application/json","Authorization":"Bearer {}"}}"#,
        escape_json_string(api_key)
    );

    let response = match http_post(api_url, &headers, request_body.as_bytes()) {
        Some(r) => r,
        None => { log("error", &format!("HTTP request failed for article {}", article_id)); return None; }
    };

    let resp_body = match extract_json_string(&response, "body") {
        Some(b) => b,
        None => { log("error", "No body in response"); return None; }
    };

    // OpenAI response: {"choices":[{"message":{"content":"..."}}]}
    // Strategy: find "message" first, then extract "content" from that substring
    // This avoids matching "content" in other parts of the response (e.g. content-type)
    let summary_text = extract_message_content(&resp_body);

    match summary_text {
        Some(s) if !s.is_empty() => Some(s),
        _ => {
            let preview_end = {
                let max = resp_body.len().min(200);
                let mut end = max;
                while end > 0 && !resp_body.is_char_boundary(end) { end -= 1; }
                end
            };
            log("error", &format!("Failed to extract summary: {}", &resp_body[..preview_end]));
            None
        }
    }
}

// ============================================================
// 钩子入口：新文章创建
// ============================================================

#[no_mangle]
pub extern "C" fn hook_article_after_create(ptr: i32, len: i32) -> i32 {
    if ptr <= 0 || len <= 0 || len > 1024 * 1024 { return 0; }

    let input = unsafe {
        let slice = slice::from_raw_parts(ptr as *const u8, len as usize);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    log("info", "AI summary hook triggered (article_after_create)");

    let content = match extract_json_string(input, "content") {
        Some(c) if !c.is_empty() => c,
        _ => { log("warn", "No content in hook data"); return 0; }
    };
    let title = extract_json_string(input, "title").unwrap_or_default();
    let api_url = match extract_json_string(input, "api_url") {
        Some(u) if !u.is_empty() => u,
        _ => { log("warn", "No api_url configured"); return 0; }
    };
    let api_key = match extract_json_string(input, "api_key") {
        Some(k) if !k.is_empty() => k,
        _ => { log("warn", "No api_key configured"); return 0; }
    };
    let model = extract_json_string(input, "model").unwrap_or_else(|| "gpt-4o-mini".to_string());
    let system_prompt = extract_json_string(input, "system_prompt")
        .unwrap_or_else(|| "你是一个文章摘要助手。请用简洁的中文为文章生成一段100字以内的摘要，突出核心观点。".to_string());
    let article_id = extract_json_number(input, "id").unwrap_or(0);
    let max_len = extract_json_number(input, "max_content_length").unwrap_or(3000) as usize;

    log("info", &format!("Calling AI API for article {}: {}", article_id, api_url));

    let summary = match generate_summary(article_id, &title, &content, &api_url, &api_key, &model, &system_prompt, max_len) {
        Some(s) => s,
        None => return 0,
    };

    // Truncate at char boundary to avoid panic on multi-byte UTF-8
    let preview_end = {
        let max = summary.len().min(50);
        let mut end = max;
        while end > 0 && !summary.is_char_boundary(end) {
            end -= 1;
        }
        end
    };
    log("info", &format!("Summary generated for article {}: {}", article_id, &summary[..preview_end]));

    let storage_key = format!("summary:{}", article_id);
    if storage_set(&storage_key, &summary) {
        log("info", &format!("Summary stored: {}", storage_key));
    } else {
        log("error", "Failed to store summary");
    }

    let output = format!(
        r#"{{"id":{},"summary":"{}"}}"#,
        article_id, escape_json_string(&summary)
    );
    write_output(&output)
}

// ============================================================
// 钩子入口：文章删除后清理摘要
// ============================================================

#[no_mangle]
pub extern "C" fn hook_article_after_delete(ptr: i32, len: i32) -> i32 {
    if ptr <= 0 || len <= 0 || len > 1024 * 1024 { return 0; }

    let input = unsafe {
        let slice = slice::from_raw_parts(ptr as *const u8, len as usize);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    let article_id = match extract_json_number(input, "id") {
        Some(id) if id > 0 => id,
        _ => return 0,
    };

    let storage_key = format!("summary:{}", article_id);
    if storage_delete(&storage_key) {
        log("info", &format!("Summary cleaned up for deleted article {}", article_id));
    }

    0
}

// ============================================================
// 钩子入口：插件启用（批量处理存量文章）
// ============================================================

#[no_mangle]
pub extern "C" fn hook_plugin_activate(ptr: i32, len: i32) -> i32 {
    if ptr <= 0 || len <= 0 || len > 1024 * 1024 { return 0; }

    let input = unsafe {
        let slice = slice::from_raw_parts(ptr as *const u8, len as usize);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    // Only process if this activation is for us
    let activated_id = extract_json_string(input, "plugin_id").unwrap_or_default();
    if activated_id != "ai-summary" { return 0; }

    log("info", "AI summary plugin activated, processing existing articles...");

    // Get settings from hook data
    let api_url = match extract_json_string(input, "api_url") {
        Some(u) if !u.is_empty() => u,
        _ => { log("warn", "No api_url configured, skipping batch"); return 0; }
    };
    let api_key = match extract_json_string(input, "api_key") {
        Some(k) if !k.is_empty() => k,
        _ => { log("warn", "No api_key configured, skipping batch"); return 0; }
    };
    let model = extract_json_string(input, "model").unwrap_or_else(|| "gpt-4o-mini".to_string());
    let system_prompt = extract_json_string(input, "system_prompt")
        .unwrap_or_else(|| "你是一个文章摘要助手。请用简洁的中文为文章生成一段100字以内的摘要，突出核心观点。".to_string());
    let max_len = extract_json_number(input, "max_content_length").unwrap_or(3000) as usize;

    // Query all articles
    let articles_json = match query_articles() {
        Some(a) => a,
        None => { log("warn", "Failed to query articles"); return 0; }
    };

    let article_objects = extract_json_objects(&articles_json);
    let total = article_objects.len();
    log("info", &format!("Found {} articles to process", total));

    let mut generated = 0;
    let mut skipped = 0;

    for obj_str in &article_objects {
        let article_id = match extract_json_number(obj_str, "id") {
            Some(id) => id,
            None => continue,
        };

        // Check if summary already exists
        let storage_key = format!("summary:{}", article_id);
        if let Some(existing) = storage_get(&storage_key) {
            if !existing.is_empty() {
                skipped += 1;
                continue;
            }
        }

        let title = extract_json_string(obj_str, "title").unwrap_or_default();
        let content = match extract_json_string(obj_str, "content") {
            Some(c) if !c.is_empty() => c,
            _ => { skipped += 1; continue; }
        };

        log("info", &format!("Generating summary for article {} ({}/{}): {}", article_id, generated + skipped + 1, total, title));

        match generate_summary(article_id, &title, &content, &api_url, &api_key, &model, &system_prompt, max_len) {
            Some(summary) => {
                if storage_set(&storage_key, &summary) {
                    generated += 1;
                    log("info", &format!("Summary stored for article {}", article_id));
                }
            }
            None => {
                log("warn", &format!("Failed to generate summary for article {}", article_id));
            }
        }
    }

    log("info", &format!("Batch complete: {} generated, {} skipped (already had summary)", generated, skipped));

    let output = format!(
        r#"{{"batch":true,"total":{},"generated":{},"skipped":{}}}"#,
        total, generated, skipped
    );
    write_output(&output)
}

// ============================================================
// 钩子入口：插件自定义 action（如重新生成摘要）
// ============================================================

#[no_mangle]
pub extern "C" fn hook_plugin_action(ptr: i32, len: i32) -> i32 {
    if ptr <= 0 || len <= 0 || len > 1024 * 1024 { return 0; }

    let input = unsafe {
        let slice = slice::from_raw_parts(ptr as *const u8, len as usize);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    // Only handle actions for this plugin
    let target_plugin = extract_json_string(input, "plugin_id").unwrap_or_default();
    if target_plugin != "ai-summary" { return 0; }

    let action = extract_json_string(input, "action").unwrap_or_default();

    match action.as_str() {
        "regenerate" => action_regenerate(input),
        _ => {
            log("warn", &format!("Unknown action: {}", action));
            0
        }
    }
}

fn action_regenerate(input: &str) -> i32 {
    let article_id = match extract_json_number(input, "article_id") {
        Some(id) if id > 0 => id,
        _ => { log("error", "regenerate: missing article_id"); return 0; }
    };

    let api_url = match extract_json_string(input, "api_url") {
        Some(u) if !u.is_empty() => u,
        _ => { log("error", "regenerate: no api_url"); return 0; }
    };
    let api_key = match extract_json_string(input, "api_key") {
        Some(k) if !k.is_empty() => k,
        _ => { log("error", "regenerate: no api_key"); return 0; }
    };
    let model = extract_json_string(input, "model").unwrap_or_else(|| "gpt-4o-mini".to_string());
    let system_prompt = extract_json_string(input, "system_prompt")
        .unwrap_or_else(|| "你是一个文章摘要助手。请用简洁的中文为文章生成一段100字以内的摘要，突出核心观点。".to_string());
    let max_len = extract_json_number(input, "max_content_length").unwrap_or(3000) as usize;

    // Get article content from articles list
    let articles_json = match query_articles() {
        Some(a) => a,
        None => { log("error", "regenerate: failed to query articles"); return 0; }
    };

    let article_objects = extract_json_objects(&articles_json);
    let mut found_title = String::new();
    let mut found_content = String::new();

    for obj_str in &article_objects {
        if let Some(id) = extract_json_number(obj_str, "id") {
            if id == article_id {
                found_title = extract_json_string(obj_str, "title").unwrap_or_default();
                found_content = extract_json_string(obj_str, "content").unwrap_or_default();
                break;
            }
        }
    }

    if found_content.is_empty() {
        log("error", &format!("regenerate: article {} not found or empty", article_id));
        return 0;
    }

    log("info", &format!("Regenerating summary for article {}: {}", article_id, found_title));

    match generate_summary(article_id, &found_title, &found_content, &api_url, &api_key, &model, &system_prompt, max_len) {
        Some(summary) => {
            let storage_key = format!("summary:{}", article_id);
            if storage_set(&storage_key, &summary) {
                log("info", &format!("Summary regenerated for article {}", article_id));
                let output = format!(
                    r#"{{"success":true,"article_id":{},"summary":"{}"}}"#,
                    article_id, escape_json_string(&summary)
                );
                write_output(&output)
            } else {
                log("error", "Failed to store regenerated summary");
                0
            }
        }
        None => {
            log("error", &format!("Failed to regenerate summary for article {}", article_id));
            0
        }
    }
}
