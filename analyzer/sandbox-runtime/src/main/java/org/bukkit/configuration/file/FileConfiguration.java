package org.bukkit.configuration.file;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Minimal, empty configuration. Returns defaults for everything so a plugin reading config in
 * {@code onEnable} does not crash; writes are ignored.
 */
public class FileConfiguration {

    public String getString(String path) { return null; }
    public String getString(String path, String def) { return def; }
    public int getInt(String path) { return 0; }
    public int getInt(String path, int def) { return def; }
    public boolean getBoolean(String path) { return false; }
    public boolean getBoolean(String path, boolean def) { return def; }
    public double getDouble(String path) { return 0.0; }
    public long getLong(String path) { return 0L; }
    public List<String> getStringList(String path) { return Collections.emptyList(); }
    public boolean contains(String path) { return false; }
    public boolean isSet(String path) { return false; }
    public void set(String path, Object value) { /* ignored */ }
    public Object get(String path) { return null; }
    public Set<String> getKeys(boolean deep) { return Collections.emptySet(); }
    public void addDefault(String path, Object value) { /* ignored */ }
}
