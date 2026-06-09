package dev.pluginguard.support;

import dev.pluginguard.support.JarBuilder.Call;

import java.util.List;

/** Factory of synthetic plugin JAR byte arrays used across tests. */
public final class TestPlugins {

    private TestPlugins() {
    }

    /** A normal-looking Paper plugin: an update check (HTTP) and a bit of NMS reflection. Should score well. */
    public static byte[] benign() {
        String pluginYml = """
                name: BenignChat
                version: 1.2.0
                main: com.example.benign.BenignPlugin
                api-version: "1.21"
                commands:
                  chathelp:
                    description: Shows help
                permissions:
                  benignchat.use:
                    default: true
                """;
        return new JarBuilder()
                .addClass("com/example/benign/BenignPlugin")
                .addClass("com/example/benign/ChatListener")
                .addClass("com/example/benign/UpdateChecker", "check",
                        List.of(new Call("java/net/HttpURLConnection", "getInputStream"),
                                new Call("java/lang/Class", "forName")),
                        List.of("https://api.github.com/repos/example/benignchat/releases/latest"))
                .addResource("plugin.yml", pluginYml)
                .addResource("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
                .build();
    }

    /** A hostile plugin: process exec, remote class loading, exfiltration, credential theft, obfuscated names. */
    public static byte[] malicious() {
        String pluginYml = """
                name: Evil
                version: "1.0"
                main: M
                commands:
                  exec:
                    description: run
                permissions:
                  '*':
                    default: op
                """;
        return new JarBuilder()
                .addClass("M")
                .addClass("a")
                .addClass("b")
                .addClass("c")
                .addClass("d")
                .addClass("e", "x",
                        List.of(new Call("java/lang/Runtime", "exec"),
                                new Call("java/net/URLClassLoader", "loadClass"),
                                new Call("java/lang/ClassLoader", "defineClass"),
                                new Call("java/net/Socket", "<init>")),
                        List.of("https://discord.com/api/webhooks/123456/sometoken",
                                "cmd.exe /c powershell -enc ZQ==",
                                "C:\\\\Users\\\\victim\\\\AppData\\\\Roaming\\\\.minecraft\\\\launcher_accounts.json",
                                "185.220.101.50",
                                "A".repeat(140)))
                .addResource("plugin.yml", pluginYml)
                .build();
    }

    /** Not a real archive — raw bytes that lack the ZIP signature. */
    public static byte[] notAJar() {
        return "this is definitely not a jar file".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /** A plugin that bundles a native library. */
    public static byte[] withNativeLibrary() {
        String pluginYml = """
                name: NativeChat
                version: 1.0.0
                main: com.example.nativechat.NativePlugin
                api-version: "1.21"
                """;
        return new JarBuilder()
                .addClass("com/example/nativechat/NativePlugin")
                .addResource("plugin.yml", pluginYml)
                .addRawEntry("natives/helper.dll", new byte[]{0x4D, 0x5A, 0x00, 0x01})
                .build();
    }
}
