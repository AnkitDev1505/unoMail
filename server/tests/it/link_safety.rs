//! Link safety: the downloaded phishing domain list, the client's check of link hosts against
//! it, and the tracking-parameter rules the client applies, all set in Server settings.

use crate::common;

use axum::{Router, routing::get};
use common::{Api, TestEnv};
use serde_json::json;
use unomail::{auth::Role, security::phishing_list};

/// A feed serving `body` at `/list.txt`.
async fn feed(body: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/list.txt", get(move || async move { body })).route("/moved", get(|| async { axum::response::Redirect::temporary("/list.txt") }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn link_hosts_are_checked_against_the_phishing_list() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let admin = Api::logged_in(&env, "admin@example.org").await;

    let hosts = json!({ "hosts": ["login.evil.example", "fine.example", "www.evil.example", "spoof.trusted.example"] });
    assert_eq!(bob.post("/api/me/link-check", hosts.clone()).await.body["listed"], json!({}), "no list loaded yet");

    env.app.phishing.replace("# test\nevil.example\ntrusted.example\n", phishing_list::DEFAULT_URL).unwrap();
    let listed = bob.post("/api/me/link-check", hosts.clone()).await.body;
    assert_eq!(listed["listed"], json!({ "login.evil.example": "evil.example", "www.evil.example": "evil.example", "spoof.trusted.example": "trusted.example" }));

    // The administrator's exceptions win; warnings can be switched off without the list.
    assert!(admin.patch("/api/settings", json!({ "phishing_list_allow": ["trusted.example"] })).await.status.is_success());
    let listed = bob.post("/api/me/link-check", hosts.clone()).await.body;
    assert!(listed["listed"].get("spoof.trusted.example").is_none() && listed["listed"].get("login.evil.example").is_some());
    assert!(admin.patch("/api/settings", json!({ "phishing_list_warn": false })).await.status.is_success());
    assert_eq!(bob.post("/api/me/link-check", hosts).await.body["listed"], json!({}));
    assert_eq!(bob.get("/api/me/link-safety").await.body["phishing_warnings"], json!(false));

    assert!(!bob.post("/api/me/link-check", json!({ "hosts": vec!["a.example"; 1001] })).await.status.is_success(), "bounded");
    assert!(!bob.get("/api/admin/phishing-list").await.status.is_success(), "the list's state is for administrators");
    let status = admin.get("/api/admin/phishing-list").await.body;
    assert_eq!((status["entries"].as_u64(), status["source"].as_str()), (Some(2), Some(phishing_list::DEFAULT_URL)));
}

#[tokio::test]
async fn the_list_is_downloaded_kept_on_disk_and_never_replaced_by_a_broken_one() {
    let env = TestEnv::start().await;
    let ok = feed("# Phishing Army\nphish.example\n0.0.0.0 other.example\n").await;
    phishing_list::fetch(&env.app, &format!("{ok}/moved")).await;
    let status = env.app.phishing.status();
    assert_eq!((status.entries, status.error.as_deref()), (2, None), "redirects are followed");
    assert!(env.app.phishing.matching("x.phish.example", &[]).is_some());
    let cached = std::fs::read_to_string(env.app.cfg.data_dir.join("phishing-list.txt")).unwrap();
    assert!(cached.starts_with(&format!("# source: {ok}/moved\n# updated: ")) && cached.contains("other.example\n"));

    // An empty or failed download keeps the list in use.
    let empty = feed("# nothing today\n").await;
    phishing_list::fetch(&env.app, &format!("{empty}/list.txt")).await;
    phishing_list::fetch(&env.app, &format!("{empty}/missing")).await;
    let status = env.app.phishing.status();
    assert_eq!(status.entries, 2);
    assert!(status.error.is_some_and(|error| error.contains("404")));
    assert!(env.app.phishing.matching("phish.example", &[]).is_some());
}

#[tokio::test]
async fn tracking_rules_follow_the_server_settings() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let admin = Api::logged_in(&env, "admin@example.org").await;

    let rules = bob.get("/api/me/link-safety").await.body;
    assert_eq!(rules["phishing_warnings"], json!(true));
    let params: Vec<&str> = rules["clean_urls"]["params"].as_array().unwrap().iter().map(|p| p.as_str().unwrap()).collect();
    assert!(params.contains(&"fbclid") && params.contains(&"gclid") && params.contains(&"linkcode"), "clean-url's list by default");
    assert_eq!(rules["clean_urls"]["prefixes"], json!(["utm_"]));

    let changed = admin.patch("/api/settings", json!({ "clean_url_params": ["fbclid"], "clean_url_exempt_domains": ["shop.example"] })).await;
    assert!(changed.status.is_success(), "{}", changed.text);
    let rules = bob.get("/api/me/link-safety").await.body;
    assert_eq!((rules["clean_urls"]["params"].clone(), rules["clean_urls"]["exempt_domains"].clone()), (json!(["fbclid"]), json!(["shop.example"])));
    assert!(!admin.patch("/api/settings", json!({ "clean_url_params": ["Has Space"] })).await.status.is_success());

    assert!(admin.patch("/api/settings", json!({ "clean_urls_enabled": false })).await.status.is_success());
    assert_eq!(bob.get("/api/me/link-safety").await.body["clean_urls"], json!(null));
}
