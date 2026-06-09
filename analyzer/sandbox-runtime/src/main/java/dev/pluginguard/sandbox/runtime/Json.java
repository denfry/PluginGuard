package dev.pluginguard.sandbox.runtime;

/**
 * Tiny JSON string helper. The sandbox runtime deliberately has no Jackson/Gson dependency (it runs
 * inside a locked-down container next to untrusted code), so it hand-writes the behavior log as
 * JSON Lines. The analyzer side parses it back with Jackson.
 */
final class Json {

    private Json() {
    }

    /** Serializes a string as a quoted JSON value, or the literal {@code null}. */
    static String quote(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
