package dev.pluginguard.engine;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.Dependency;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.JarModel;
import dev.pluginguard.engine.model.PluginInfo;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/**
 * Mutable accumulator threaded through every {@link Analyzer}. It carries the immutable inputs
 * (the {@link JarModel} and the pre-computed per-class {@link ClassScan}s) and collects everything
 * analyzers produce: findings plus the aggregated network / filesystem / dependency views and a
 * few cross-analyzer signals (detected platform, parsed plugin descriptor, obfuscation score).
 */
public class AnalysisContext {

    private final JarModel jar;
    private final List<ClassScan> classScans;

    private final List<Finding> findings = new ArrayList<>();
    private final TreeSet<String> network = new TreeSet<>();
    private final TreeSet<String> filesystem = new TreeSet<>();
    private final List<Dependency> dependencies = new ArrayList<>();
    private final List<String> notes = new ArrayList<>();

    private String platform = "Unknown";
    private ArtifactType artifactType = ArtifactType.UNKNOWN;
    private PluginInfo pluginInfo;
    private int obfuscationScore;
    private int methodCount;

    public AnalysisContext(JarModel jar, List<ClassScan> classScans) {
        this.jar = jar;
        this.classScans = classScans;
        this.methodCount = classScans.stream().mapToInt(s -> s.methods().size()).sum();
        this.notes.addAll(jar.guardNotes());
    }

    public JarModel jar() { return jar; }
    public List<ClassScan> classScans() { return classScans; }

    public void add(Finding finding) { findings.add(finding); }
    public List<Finding> findings() { return findings; }

    public void addNetworkIndicator(String value) { if (value != null && !value.isBlank()) network.add(value.trim()); }
    public List<String> network() { return new ArrayList<>(network); }

    public void addFilesystemPath(String value) { if (value != null && !value.isBlank()) filesystem.add(value.trim()); }
    public List<String> filesystem() { return new ArrayList<>(filesystem); }

    public void addDependency(Dependency dependency) { dependencies.add(dependency); }
    public List<Dependency> dependencies() { return dependencies; }

    public void addNote(String note) { notes.add(note); }
    public List<String> notes() { return notes; }

    public String platform() { return platform; }
    public void setPlatform(String platform) { this.platform = platform; }

    public ArtifactType artifactType() { return artifactType; }
    public void setArtifactType(ArtifactType artifactType) { this.artifactType = artifactType; }

    public PluginInfo pluginInfo() { return pluginInfo; }
    public void setPluginInfo(PluginInfo pluginInfo) { this.pluginInfo = pluginInfo; }

    public int obfuscationScore() { return obfuscationScore; }
    public void setObfuscationScore(int obfuscationScore) { this.obfuscationScore = obfuscationScore; }

    public int methodCount() { return methodCount; }
}
