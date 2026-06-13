// ============================================================================
//  AEGIS — Field Security Operations Suite · Desktop Edition (C++)
// ----------------------------------------------------------------------------
//  A self-contained native application. It hosts the AEGIS web UI (embedded in
//  the binary) and the full /api/* JSON backend from an HTTP server bound to
//  127.0.0.1, then opens that local server in a native window (when built with
//  -DAEGIS_WITH_WEBVIEW) or in the system default browser.
//
//  Single-user / local: the OS user account is the trust boundary, so there is
//  no login. Data persists to a JSON document in the per-user data directory:
//      Windows : %APPDATA%\AEGIS\aegis.json
//      macOS   : ~/Library/Application Support/AEGIS/aegis.json
//      Linux   : $XDG_DATA_HOME/AEGIS/aegis.json  (or ~/.local/share/AEGIS)
//  Override with the AEGIS_DATA_DIR environment variable.
//
//  Dependencies are header-only: cpp-httplib and nlohmann/json (both vendored
//  in third_party/). Networked RSS feeds are optional (-DAEGIS_WITH_CURL).
// ============================================================================
#include "httplib.h"
#include "json.hpp"
#include "assets_generated.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef AEGIS_WITH_WEBVIEW
#include "webview.h"
#endif
#ifdef AEGIS_WITH_CURL
#include <curl/curl.h>
#endif

using json = nlohmann::json;
namespace fs = std::filesystem;

static const std::set<std::string> COLLECTIONS = {
    "threats", "personnel", "regions", "osint", "tasks", "trips",
    "itinerary", "hotels", "budget",
    "iw_entries", "iw_entities", "iw_rels", "iw_ach"};

static std::string now_iso() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return buf;
}

static std::string data_dir() {
    if (const char* o = std::getenv("AEGIS_DATA_DIR"); o && *o) {
        std::error_code ec; fs::create_directories(o, ec); return o;
    }
    std::string d;
#if defined(_WIN32)
    const char* base = std::getenv("APPDATA");
    d = (base && *base ? std::string(base) : std::string(".")) + "\\AEGIS";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    d = (home && *home ? std::string(home) : std::string(".")) + "/Library/Application Support/AEGIS";
#else
    const char* xdg = std::getenv("XDG_DATA_HOME");
    if (xdg && *xdg) d = std::string(xdg) + "/AEGIS";
    else { const char* home = std::getenv("HOME"); d = (home && *home ? std::string(home) : std::string(".")) + "/.local/share/AEGIS"; }
#endif
    std::error_code ec; fs::create_directories(d, ec);
    return d;
}

static std::string gen_id(const std::string& coll) {
    using namespace std::chrono;
    auto ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    static std::mt19937_64 rng{std::random_device{}()};
    std::ostringstream os;
    os << (coll.empty() ? 'x' : coll[0]) << '_' << ms << '_'
       << std::hex << (rng() & 0xffffu);
    return os.str();
}

// ---------------------------------------------------------------------------
//  Persistent store (thread-safe, atomic writes)
// ---------------------------------------------------------------------------
struct Store {
    std::mutex m;
    std::string file;
    json db;

    static json default_config() {
        return json{
            {"suiteName", "AEGIS"},
            {"orgName", "Field Security Operations"},
            {"classification", "Unclassified // Internal Use"},
            {"operatorInitials", "OP"},
            {"homeRegion", ""}};
    }
    static json defaults() {
        return json{{"config", default_config()},
                    {"items", json::object()},
                    {"meta", {{"created", now_iso()}, {"app", "AEGIS Desktop"}}}};
    }

    void load() {
        std::lock_guard<std::mutex> lk(m);
        file = (fs::path(data_dir()) / "aegis.json").string();
        std::ifstream in(file, std::ios::binary);
        if (in) { try { db = json::parse(in); } catch (...) { db = defaults(); } }
        else db = defaults();
        if (!db.contains("config") || !db["config"].is_object()) db["config"] = default_config();
        if (!db.contains("items") || !db["items"].is_object()) db["items"] = json::object();
        for (const auto& c : COLLECTIONS)
            if (!db["items"].contains(c) || !db["items"][c].is_array())
                db["items"][c] = json::array();
        save_unlocked();
    }

    void save_unlocked() {
        std::string tmp = file + ".tmp";
        { std::ofstream out(tmp, std::ios::binary | std::ios::trunc); out << db.dump(2); }
        std::error_code ec; fs::rename(tmp, file, ec);
        if (ec) { std::ofstream out(file, std::ios::binary | std::ios::trunc); out << db.dump(2); }
    }

    json effective_config() {
        std::lock_guard<std::mutex> lk(m);
        json eff = default_config();
        for (auto it = db["config"].begin(); it != db["config"].end(); ++it) eff[it.key()] = it.value();
        return eff;
    }
    json merge_config(const json& patch) {
        { std::lock_guard<std::mutex> lk(m);
          if (patch.is_object())
              for (auto it = patch.begin(); it != patch.end(); ++it) db["config"][it.key()] = it.value();
          save_unlocked(); }
        return effective_config();
    }
    json items(const std::string& coll) {
        std::lock_guard<std::mutex> lk(m);
        return db["items"][coll];
    }
    json upsert(const std::string& coll, json rec) {
        std::lock_guard<std::mutex> lk(m);
        if (!rec.contains("id") || !rec["id"].is_string() || rec["id"].get<std::string>().empty())
            rec["id"] = gen_id(coll);
        std::string id = rec["id"];
        auto& arr = db["items"][coll];
        bool replaced = false;
        for (auto& e : arr) {
            if (e.contains("id") && e["id"] == id) { e = rec; replaced = true; break; }
        }
        if (!replaced) arr.push_back(rec);
        save_unlocked();
        return rec;
    }
    void replace(const std::string& coll, const json& arr) {
        std::lock_guard<std::mutex> lk(m);
        db["items"][coll] = arr.is_array() ? arr : json::array();
        save_unlocked();
    }
    bool remove(const std::string& coll, const std::string& id) {
        std::lock_guard<std::mutex> lk(m);
        auto& arr = db["items"][coll];
        for (auto it = arr.begin(); it != arr.end(); ++it) {
            if (it->contains("id") && (*it)["id"] == id) { arr.erase(it); save_unlocked(); return true; }
        }
        return false;
    }
};

static Store g_store;

static void send_json(httplib::Response& res, const json& j, int status = 200) {
    res.status = status;
    res.set_content(j.dump(), "application/json");
}
static bool parse_body(const httplib::Request& req, json& out) {
    try { out = json::parse(req.body.empty() ? "{}" : req.body); return true; }
    catch (...) { return false; }
}

// ---------------------------------------------------------------------------
//  Security feeds (optional; needs libcurl for HTTPS)
// ---------------------------------------------------------------------------
struct FeedSrc { const char* key; const char* name; const char* url; };
static const std::vector<FeedSrc> FEED_SOURCES = {
    {"reliefweb", "ReliefWeb", "https://reliefweb.int/updates/rss.xml"},
    {"gdacs", "GDACS Disasters", "https://www.gdacs.org/xml/rss.xml"},
    {"unhum", "UN Humanitarian", "https://news.un.org/feed/subscribe/en/news/topic/humanitarian-aid/feed/rss.xml"},
    {"state", "US Travel Advisories", "https://travel.state.gov/_res/rss/TAsTWs.xml"},
    {"who", "WHO Outbreaks", "https://www.who.int/feeds/entity/csr/don/en/rss.xml"},
    {"cisa", "CISA Cyber", "https://www.cisa.gov/cybersecurity-advisories/all.xml"}};

static json feed_sources_json() {
    json s = json::array();
    for (const auto& f : FEED_SOURCES) s.push_back({{"key", f.key}, {"name", f.name}, {"url", f.url}});
    return s;
}

#ifdef AEGIS_WITH_CURL
static size_t curl_sink(void* p, size_t sz, size_t n, void* ud) {
    static_cast<std::string*>(ud)->append(static_cast<char*>(p), sz * n);
    return sz * n;
}
static std::string http_get(const std::string& url) {
    CURL* c = curl_easy_init(); if (!c) return "";
    std::string body;
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 8L);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "AEGIS-FieldSecurity/1.0 (+duty-of-care)");
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_sink);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    CURLcode rc = curl_easy_perform(c);
    long code = 0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(c);
    return (rc == CURLE_OK && code >= 200 && code < 400) ? body : "";
}
static std::string strip_tags(std::string s) {
    std::string out; out.reserve(s.size()); bool in = false;
    for (char ch : s) { if (ch == '<') in = true; else if (ch == '>') in = false; else if (!in) out += ch; }
    // minimal entity unescape
    auto rep = [&](const std::string& a, const std::string& b) {
        size_t p = 0; while ((p = out.find(a, p)) != std::string::npos) { out.replace(p, a.size(), b); p += b.size(); } };
    rep("&amp;", "&"); rep("&lt;", "<"); rep("&gt;", ">"); rep("&quot;", "\""); rep("&#39;", "'");
    return out;
}
static std::string between(const std::string& b, const std::string& open, const std::string& close) {
    size_t i = b.find(open); if (i == std::string::npos) return "";
    i += open.size(); size_t j = b.find(close, i); if (j == std::string::npos) return "";
    return b.substr(i, j - i);
}
static json build_feeds() {
    json items = json::array();
    for (const auto& src : FEED_SOURCES) {
        std::string xml = http_get(src.url); if (xml.empty()) continue;
        bool atom = xml.find("<feed") != std::string::npos && xml.find("<rss") == std::string::npos;
        std::string itemTag = atom ? "<entry" : "<item";
        size_t pos = 0; int n = 0;
        while (n < 15) {
            size_t s = xml.find(itemTag, pos); if (s == std::string::npos) break;
            size_t e = xml.find(atom ? "</entry>" : "</item>", s); if (e == std::string::npos) break;
            std::string blk = xml.substr(s, e - s);
            std::string title = strip_tags(between(blk, "<title", "</title>"));
            if (!title.empty() && title[0] == '>') title.erase(0, 1);
            std::string link;
            if (atom) { std::string l = between(blk, "<link", ">"); size_t h = l.find("href=\""); if (h != std::string::npos) { h += 6; link = l.substr(h, l.find('"', h) - h); } }
            else link = strip_tags(between(blk, "<link", "</link>"));
            std::string date = strip_tags(between(blk, atom ? "<updated" : "<pubDate", atom ? "</updated>" : "</pubDate>"));
            std::string desc = strip_tags(between(blk, atom ? "<summary" : "<description", atom ? "</summary>" : "</description>"));
            if (desc.size() > 240) desc = desc.substr(0, 240);
            if (!title.empty())
                items.push_back({{"source", src.name}, {"sourceKey", src.key}, {"title", title}, {"link", link}, {"date", date}, {"summary", desc}});
            pos = e; ++n;
        }
    }
    return json{{"fetched", now_iso()}, {"sources", feed_sources_json()}, {"items", items}};
}
#else
static json build_feeds() {
    // No HTTPS client compiled in — return sources so the UI can show manual links.
    return json{{"fetched", now_iso()}, {"sources", feed_sources_json()}, {"items", json::array()}};
}
#endif

// ---------------------------------------------------------------------------
//  Routes
// ---------------------------------------------------------------------------
static void register_routes(httplib::Server& svr) {
    // --- status / identity (local single-user; no auth) ---
    svr.Get("/api/status", [](const httplib::Request&, httplib::Response& res) {
        send_json(res, {{"mode", "secure"}, {"driver", "json"}, {"configured", true},
                        {"user", "operator"}, {"edition", "desktop"},
                        {"config", g_store.effective_config()}});
    });
    svr.Get("/api/me", [](const httplib::Request&, httplib::Response& res) {
        send_json(res, {{"user", "operator"}});
    });
    // setup / login / logout are no-ops kept for frontend compatibility
    svr.Post("/api/setup", [](const httplib::Request& req, httplib::Response& res) {
        json b; if (parse_body(req, b) && b.contains("config") && b["config"].is_object()) g_store.merge_config(b["config"]);
        send_json(res, {{"ok", true}, {"user", "operator"}});
    });
    svr.Post("/api/login", [](const httplib::Request&, httplib::Response& res) {
        send_json(res, {{"ok", true}, {"user", "operator"}});
    });
    svr.Post("/api/logout", [](const httplib::Request&, httplib::Response& res) {
        send_json(res, {{"ok", true}});
    });

    // --- config ---
    svr.Get("/api/config", [](const httplib::Request&, httplib::Response& res) {
        send_json(res, g_store.effective_config());
    });
    svr.Put("/api/config", [](const httplib::Request& req, httplib::Response& res) {
        json b; if (!parse_body(req, b)) { send_json(res, {{"error", "Invalid JSON."}}, 400); return; }
        send_json(res, g_store.merge_config(b.contains("config") ? b["config"] : b));
    });

    // --- collections ---
    svr.Get(R"(/api/collections/([A-Za-z_]+))", [](const httplib::Request& req, httplib::Response& res) {
        std::string coll = req.matches[1];
        if (!COLLECTIONS.count(coll)) { send_json(res, {{"error", "Unknown collection."}}, 404); return; }
        send_json(res, {{"items", g_store.items(coll)}});
    });
    svr.Post(R"(/api/collections/([A-Za-z_]+))", [](const httplib::Request& req, httplib::Response& res) {
        std::string coll = req.matches[1];
        if (!COLLECTIONS.count(coll)) { send_json(res, {{"error", "Unknown collection."}}, 404); return; }
        json b; if (!parse_body(req, b) || !b.is_object()) { send_json(res, {{"error", "Invalid JSON."}}, 400); return; }
        send_json(res, {{"item", g_store.upsert(coll, b)}});
    });
    svr.Put(R"(/api/collections/([A-Za-z_]+))", [](const httplib::Request& req, httplib::Response& res) {
        std::string coll = req.matches[1];
        if (!COLLECTIONS.count(coll)) { send_json(res, {{"error", "Unknown collection."}}, 404); return; }
        json b; if (!parse_body(req, b)) { send_json(res, {{"error", "Invalid JSON."}}, 400); return; }
        json arr = (b.is_object() && b.contains("items")) ? b["items"] : b;
        g_store.replace(coll, arr);
        send_json(res, {{"ok", true}, {"count", arr.is_array() ? (int)arr.size() : 0}});
    });
    svr.Delete(R"(/api/collections/([A-Za-z_]+)/([^/]+))", [](const httplib::Request& req, httplib::Response& res) {
        std::string coll = req.matches[1], id = req.matches[2];
        if (!COLLECTIONS.count(coll)) { send_json(res, {{"error", "Unknown collection."}}, 404); return; }
        send_json(res, {{"ok", g_store.remove(coll, id)}});
    });

    // --- feeds ---
    svr.Get("/api/feeds", [](const httplib::Request&, httplib::Response& res) {
        static std::mutex fm; static json cache; static std::chrono::steady_clock::time_point at{};
        std::lock_guard<std::mutex> lk(fm);
        auto now = std::chrono::steady_clock::now();
        if (cache.is_null() || std::chrono::duration_cast<std::chrono::minutes>(now - at).count() >= 10) {
            cache = build_feeds(); at = now;
        }
        send_json(res, cache);
    });

    // --- unknown /api → JSON 404 (so the client never gets HTML where it wants JSON) ---
    svr.Get(R"(/api/.*)", [](const httplib::Request&, httplib::Response& res) { send_json(res, {{"error", "Not found."}}, 404); });

    // --- static assets (embedded). Registered last so /api/* wins. ---
    svr.Get(R"(/.*)", [](const httplib::Request& req, httplib::Response& res) {
        std::string p = req.path;
        if (p.empty() || p == "/") p = "/index.html";
        const auto& table = aegis_assets::table();
        auto it = table.find(p);
        if (it == table.end()) { res.status = 404; res.set_content("Not found", "text/plain"); return; }
        res.set_content(reinterpret_cast<const char*>(it->second.data), it->second.size, it->second.mime);
    });

    svr.set_post_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_header("Referrer-Policy", "no-referrer");
    });
}

static void open_in_browser(const std::string& url) {
#if defined(_WIN32)
    std::string cmd = "start \"\" \"" + url + "\"";
#elif defined(__APPLE__)
    std::string cmd = "open \"" + url + "\"";
#else
    std::string cmd = "xdg-open \"" + url + "\" >/dev/null 2>&1 &";
#endif
    if (std::system(cmd.c_str()) != 0) { /* best-effort; ignore */ }
}

int main(int argc, char** argv) {
    bool headless = false;          // run server only; don't open a window/browser
    int  want_port = 8787;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--headless" || a == "--no-window") headless = true;
        else if (a == "--port" && i + 1 < argc) want_port = std::atoi(argv[++i]);
    }

    g_store.load();

    httplib::Server svr;
    register_routes(svr);

    int port = want_port;
    if (!svr.bind_to_port("127.0.0.1", port)) {
        port = svr.bind_to_any_port("127.0.0.1");
        if (port <= 0) { std::cerr << "AEGIS: failed to bind a local port.\n"; return 1; }
    }
    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/";

    std::thread server_thread([&svr]() { svr.listen_after_bind(); });

    std::cout << "AEGIS Desktop — serving on " << url << "\n"
              << "Data file: " << (fs::path(data_dir()) / "aegis.json").string() << "\n";

#ifdef AEGIS_WITH_WEBVIEW
    if (!headless) {
        webview_t w = webview_create(0, nullptr);
        webview_set_title(w, "AEGIS — Field Security Operations");
        webview_set_size(w, 1320, 880, WEBVIEW_HINT_NONE);
        webview_navigate(w, url.c_str());
        webview_run(w);
        webview_destroy(w);
        svr.stop();
        if (server_thread.joinable()) server_thread.join();
        return 0;
    }
#endif
    if (!headless) { std::this_thread::sleep_for(std::chrono::milliseconds(350)); open_in_browser(url); }
    std::cout << (headless ? "Headless mode. " : "") << "Press Ctrl+C to quit.\n";
    if (server_thread.joinable()) server_thread.join();
    return 0;
}
