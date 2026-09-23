package com.phishguard;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

public class UrlFeatureExtractor {

    public static final String[] ATTRIBUTE_NAMES = {
        "url_length",
        "hostname_length",
        "path_length",
        "dot_count",
        "hyphen_count",
        "at_count",
        "question_count",
        "ampersand_count",
        "slash_count",
        "digit_count",
        "subdomain_count",
        "has_ip",
        "has_https",
        "has_suspicious_keyword",
        "has_shortener",
        "has_port",
        "entropy"
    };

    private static final String[] SUSPICIOUS_KEYWORDS = {
        "login", "verify", "verification", "secure", "account", "update",
        "confirm", "password", "bank", "signin", "wallet", "webscr",
        "authenticate", "credential", "payment", "recover", "unlock"
    };

    private static final String[] SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "cutt.ly", "shorturl.at"
    };

    public double[] extract(String rawUrl) {
        String url = normalize(rawUrl);
        URI uri = parse(url);

        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        String path = uri.getPath() == null ? "" : uri.getPath();
        String query = uri.getQuery() == null ? "" : uri.getQuery();

        int urlLength = url.length();
        int hostnameLength = host.length();
        int pathLength = path.length();
        int dotCount = count(url, '.');
        int hyphenCount = count(url, '-');
        int atCount = count(url, '@');
        int questionCount = count(url, '?');
        int ampersandCount = count(url, '&');
        int slashCount = count(url, '/');
        int digitCount = (int) url.chars().filter(Character::isDigit).count();
        int subdomainCount = countSubdomains(host);
        int hasIp = looksLikeIp(host) ? 1 : 0;
        int hasHttps = url.toLowerCase(Locale.ROOT).startsWith("https://") ? 1 : 0;
        int suspiciousKeyword = containsSuspiciousKeyword(url) ? 1 : 0;
        int shortener = containsShortener(host) ? 1 : 0;
        int hasPort = uri.getPort() != -1 ? 1 : 0;
        double entropy = entropy(url);

        return new double[] {
            urlLength, hostnameLength, pathLength, dotCount, hyphenCount,
            atCount, questionCount, ampersandCount, slashCount, digitCount,
            subdomainCount, hasIp, hasHttps, suspiciousKeyword, shortener,
            hasPort, entropy
        };
    }

    public String normalize(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            throw new IllegalArgumentException("URL cannot be empty.");
        }
        String url = rawUrl.trim();
        if (!url.matches("(?i)^https?://.*")) {
            url = "http://" + url;
        }
        return url;
    }

    private URI parse(String url) {
        try {
            return new URI(url);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid URL format.");
        }
    }

    private int count(String s, char c) {
        return (int) s.chars().filter(ch -> ch == c).count();
    }

    private int countSubdomains(String host) {
        if (host.isBlank() || looksLikeIp(host)) return 0;
        String[] parts = host.split("\\.");
        return Math.max(0, parts.length - 2);
    }

    private boolean looksLikeIp(String host) {
    return host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    private boolean containsSuspiciousKeyword(String url) {
        String lower = url.toLowerCase(Locale.ROOT);
        for (String keyword : SUSPICIOUS_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    private boolean containsShortener(String host) {
        for (String shortener : SHORTENERS) {
            if (host.equals(shortener) || host.endsWith("." + shortener)) return true;
        }
        return false;
    }

    private double entropy(String value) {
        if (value.isEmpty()) return 0.0;
        int[] freq = new int[256];
        for (char c : value.toCharArray()) {
            freq[c % 256]++;
        }
        double result = 0.0;
        for (int f : freq) {
            if (f == 0) continue;
            double p = (double) f / value.length();
            result -= p * (Math.log(p) / Math.log(2));
        }
        return result;
    }

    public String[] indicators(String rawUrl) {
        double[] f = extract(rawUrl);
        java.util.List<String> result = new java.util.ArrayList<>();

        if (f[0] > 75) result.add("Unusually long URL");
        if (f[1] > 35) result.add("Long hostname");
        if (f[3] >= 4) result.add("Many dots/subdomains");
        if (f[4] >= 3) result.add("Multiple hyphens");
        if (f[5] > 0) result.add("Contains @ symbol");
        if (f[8] >= 6) result.add("Deep URL path");
        if (f[9] >= 8) result.add("Many digits");
        if (f[10] >= 2) result.add("Multiple subdomains");
        if (f[11] > 0) result.add("IP address used as hostname");
        if (f[12] == 0) result.add("No HTTPS");
        if (f[13] > 0) result.add("Suspicious security/account keyword");
        if (f[14] > 0) result.add("URL shortening service detected");
        if (f[15] > 0) result.add("Non-standard port");
        if (f[16] > 4.0) result.add("High URL character entropy");

        if (result.isEmpty()) result.add("No major heuristic warning detected");
        return result.toArray(new String[0]);
    }
}
