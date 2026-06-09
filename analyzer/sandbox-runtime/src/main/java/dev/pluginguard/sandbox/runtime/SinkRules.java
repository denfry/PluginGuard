package dev.pluginguard.sandbox.runtime;

import java.util.Map;

/**
 * Pure decision table mapping a called method ({@code owner.name}, internal form) to the dynamic
 * behavior-event type recorded when the plugin reaches that call site. Only <em>method-call</em>
 * sinks are listed (never constructors), so the {@link GuardTransformer} can insert a stack-neutral
 * marker before the call without touching uninitialized objects on the operand stack.
 *
 * <p>This is the dynamic mirror of the static {@code BytecodeAnalyzer} rule table: here we record
 * what the plugin <em>actually invoked at runtime</em>, which catches reflectively-built or decoded
 * calls that no static pass could see.
 */
public final class SinkRules {

    private static final Map<String, String> SINKS = Map.ofEntries(
            // Process execution
            Map.entry("java/lang/Runtime#exec", "PROCESS_EXEC"),
            Map.entry("java/lang/ProcessBuilder#start", "PROCESS_EXEC"),
            Map.entry("java/lang/ProcessBuilder#startPipeline", "PROCESS_EXEC"),
            // Dynamic class definition / loading
            Map.entry("java/lang/ClassLoader#defineClass", "DEFINE_CLASS"),
            Map.entry("java/lang/invoke/MethodHandles$Lookup#defineClass", "DEFINE_CLASS"),
            Map.entry("java/lang/invoke/MethodHandles$Lookup#defineHiddenClass", "DEFINE_CLASS"),
            // Reflection
            Map.entry("java/lang/Class#forName", "REFLECTION"),
            Map.entry("java/lang/reflect/Method#invoke", "REFLECTION"),
            Map.entry("java/lang/reflect/AccessibleObject#setAccessible", "REFLECTION"),
            // Outbound network
            Map.entry("java/net/URL#openConnection", "NETWORK_CONNECT"),
            Map.entry("java/net/URL#openStream", "NETWORK_CONNECT"),
            Map.entry("java/net/Socket#connect", "NETWORK_CONNECT"),
            Map.entry("java/net/http/HttpClient#send", "NETWORK_CONNECT"),
            Map.entry("java/net/http/HttpClient#sendAsync", "NETWORK_CONNECT"),
            Map.entry("java/net/DatagramSocket#send", "NETWORK_CONNECT"),
            // DNS
            Map.entry("java/net/InetAddress#getByName", "DNS_RESOLVE"),
            Map.entry("java/net/InetAddress#getAllByName", "DNS_RESOLVE"),
            // Native libraries
            Map.entry("java/lang/System#load", "LOAD_LIBRARY"),
            Map.entry("java/lang/System#loadLibrary", "LOAD_LIBRARY"),
            Map.entry("java/lang/Runtime#load", "LOAD_LIBRARY"),
            Map.entry("java/lang/Runtime#loadLibrary", "LOAD_LIBRARY"),
            // Scripting engines
            Map.entry("javax/script/ScriptEngineManager#getEngineByName", "SCRIPTING"),
            Map.entry("javax/script/ScriptEngine#eval", "SCRIPTING"),
            // JNDI / LDAP (Log4Shell class)
            Map.entry("javax/naming/InitialContext#lookup", "JNDI_LOOKUP"),
            Map.entry("javax/naming/Context#lookup", "JNDI_LOOKUP"),
            // Deserialization
            Map.entry("java/io/ObjectInputStream#readObject", "DESERIALIZE"),
            // Static file operations (stream constructors are covered by the SecurityManager instead)
            Map.entry("java/nio/file/Files#write", "FILE_WRITE"),
            Map.entry("java/nio/file/Files#newOutputStream", "FILE_WRITE"),
            Map.entry("java/nio/file/Files#delete", "FILE_WRITE"),
            Map.entry("java/nio/file/Files#readAllBytes", "FILE_READ"),
            Map.entry("java/nio/file/Files#newInputStream", "FILE_READ"),
            // JVM control
            Map.entry("java/lang/System#exit", "JVM_EXIT"),
            Map.entry("java/lang/Runtime#exit", "JVM_EXIT"),
            Map.entry("java/lang/Runtime#halt", "JVM_EXIT"),
            Map.entry("java/lang/System#setProperty", "SET_PROPERTY"),
            Map.entry("java/lang/System#getenv", "ENV_READ"));

    private SinkRules() {
    }

    /**
     * Returns the behavior-event type for a call to {@code owner.name}, or {@code null} if the call
     * is not an instrumented sink. Constructors are never sinks here.
     */
    public static String typeFor(String owner, String name) {
        if (owner == null || name == null || name.charAt(0) == '<') {
            return null;
        }
        return SINKS.get(owner + "#" + name);
    }
}
