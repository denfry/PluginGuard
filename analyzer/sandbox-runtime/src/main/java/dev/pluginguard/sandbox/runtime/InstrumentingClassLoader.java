package dev.pluginguard.sandbox.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Loads the plugin's own classes and runs each through {@link GuardTransformer} before defining it,
 * so the behavior log is captured even without a {@code -javaagent} attached. Bukkit stubs, the
 * sandbox runtime and the JDK are delegated to the parent loader unchanged.
 *
 * <p>The whole plugin jar is read into memory at construction so no file handle lingers (a cached
 * {@code JarURLConnection} would otherwise keep the jar locked on Windows past {@code close()}).
 * This child-first-for-plugin-classes strategy makes the instrument→drive→capture chain exercisable
 * in-process; the JVM agent path remains for the production container, where it also reaches
 * dynamically generated classes this loader never sees.
 */
public final class InstrumentingClassLoader extends ClassLoader {

    private final Map<String, byte[]> entries = new HashMap<>();

    public InstrumentingClassLoader(Path pluginJar, ClassLoader parent) throws IOException {
        super(parent);
        try (JarFile jar = new JarFile(pluginJar.toFile())) {
            var en = jar.entries();
            while (en.hasMoreElements()) {
                JarEntry entry = en.nextElement();
                if (!entry.isDirectory()) {
                    try (InputStream in = jar.getInputStream(entry)) {
                        entries.put(entry.getName(), in.readAllBytes());
                    }
                }
            }
        }
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        synchronized (getClassLoadingLock(name)) {
            Class<?> c = findLoadedClass(name);
            if (c == null) {
                String internal = name.replace('.', '/');
                if (!GuardTransformer.isInfrastructure(internal) && entries.containsKey(internal + ".class")) {
                    c = findClass(name);
                } else {
                    c = super.loadClass(name, false);
                }
            }
            if (resolve) {
                resolveClass(c);
            }
            return c;
        }
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] original = entries.get(name.replace('.', '/') + ".class");
        if (original == null) {
            throw new ClassNotFoundException(name);
        }
        byte[] instrumented = GuardTransformer.instrument(original);
        return defineClass(name, instrumented, 0, instrumented.length);
    }
}
