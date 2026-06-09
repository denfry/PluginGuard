package com.example.benignchat;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

/**
 * Sample fixture — a benign update checker that fetches the latest release tag from GitHub.
 * This is the kind of HTTP usage PluginGuard reports as low-risk (a documented, expected call).
 */
public class UpdateChecker {

    private static final String RELEASES_API =
            "https://api.github.com/repos/example/benignchat/releases/latest";

    public String latestVersion() {
        try {
            URL url = URI.create(RELEASES_API).toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(3000);
            try (BufferedReader reader =
                         new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                return reader.readLine();
            }
        } catch (Exception e) {
            return null;
        }
    }
}
