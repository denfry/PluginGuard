package dev.pluginguard.sandbox.runtime;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the security manager's pure caller-attribution logic (whether a stack frame belongs to the
 * plugin's classloader) without ever installing a global {@link SecurityManager}.
 */
class SandboxSecurityManagerTest {

    @Test
    void nullPluginLoaderIsNeverPluginInitiated() {
        assertFalse(SandboxSecurityManager.isPluginInitiated(new Class<?>[]{String.class}, null));
    }

    @Test
    void bootstrapClassesAreNotAttributedToThePlugin() {
        ClassLoader pluginLoader = new BytesLoader(getClass().getClassLoader());
        assertFalse(SandboxSecurityManager.isPluginInitiated(
                new Class<?>[]{String.class, Integer.class}, pluginLoader));
    }

    @Test
    void classLoadedByThePluginLoaderIsAttributed() {
        BytesLoader pluginLoader = new BytesLoader(getClass().getClassLoader());
        Class<?> c = pluginLoader.define("p/Owned", emptyClass("p/Owned"));
        assertTrue(SandboxSecurityManager.isPluginInitiated(
                new Class<?>[]{String.class, c}, pluginLoader));
    }

    @Test
    void classLoadedByAChildOfThePluginLoaderIsAttributed() {
        BytesLoader pluginLoader = new BytesLoader(getClass().getClassLoader());
        BytesLoader child = new BytesLoader(pluginLoader);
        Class<?> c = child.define("p/Child", emptyClass("p/Child"));
        assertTrue(SandboxSecurityManager.isPluginInitiated(new Class<?>[]{c}, pluginLoader));
    }

    private static byte[] emptyClass(String internalName) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static final class BytesLoader extends ClassLoader {
        BytesLoader(ClassLoader parent) {
            super(parent);
        }

        Class<?> define(String name, byte[] bytes) {
            return defineClass(name.replace('/', '.'), bytes, 0, bytes.length);
        }
    }
}
