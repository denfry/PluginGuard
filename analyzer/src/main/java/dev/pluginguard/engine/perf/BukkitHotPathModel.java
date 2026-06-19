package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.Invocation;
import dev.pluginguard.engine.bytecode.MethodInfo;
import dev.pluginguard.engine.model.ArtifactType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Bukkit/Spigot/Paper hot paths: {@code @EventHandler} listener methods (heat by event type) and the
 * {@code run()} of {@link org.bukkit.scheduler.BukkitRunnable} subclasses registered via a *sync*
 * repeating scheduler. Registration via an async scheduler is intentionally NOT treated as hot.
 */
public class BukkitHotPathModel implements HotPathModel {

    private static final String LISTENER = "org/bukkit/event/Listener";
    private static final String EVENT_HANDLER = "Lorg/bukkit/event/EventHandler;";
    private static final String BUKKIT_RUNNABLE = "org/bukkit/scheduler/BukkitRunnable";

    /** Simple event class-name -> heat. Default for an unrecognized *Event is WARM. */
    private static final Map<String, Heat> EVENT_HEAT = Map.ofEntries(
            Map.entry("PlayerMoveEvent", Heat.HOT),
            Map.entry("EntityMoveEvent", Heat.HOT),
            Map.entry("VehicleMoveEvent", Heat.HOT),
            Map.entry("BlockPhysicsEvent", Heat.HOT),
            Map.entry("ProjectileHitEvent", Heat.HOT),
            Map.entry("EntityDamageEvent", Heat.HOT),
            Map.entry("EntityDamageByEntityEvent", Heat.HOT),
            Map.entry("FoodLevelChangeEvent", Heat.HOT),
            Map.entry("PlayerInteractEvent", Heat.HOT),
            Map.entry("AsyncPlayerChatEvent", Heat.WARM),
            Map.entry("InventoryClickEvent", Heat.WARM),
            Map.entry("BlockBreakEvent", Heat.WARM),
            Map.entry("BlockPlaceEvent", Heat.WARM),
            Map.entry("PlayerJoinEvent", Heat.COOL),
            Map.entry("PlayerQuitEvent", Heat.COOL),
            Map.entry("WorldLoadEvent", Heat.COOL));

    private static final List<String> SYNC_SCHEDULER_METHODS = List.of(
            "runTaskTimer", "scheduleSyncRepeatingTask", "runTask", "runTaskLater");

    @Override
    public boolean supports(ArtifactType type) {
        return type == ArtifactType.PLUGIN_BUKKIT;
    }

    @Override
    public List<HotEntrypoint> entrypoints(List<ClassScan> classes) {
        List<HotEntrypoint> out = new ArrayList<>();
        boolean hasSyncScheduler = classes.stream()
                .flatMap(c -> c.invocations().stream())
                .anyMatch(i -> SYNC_SCHEDULER_METHODS.contains(i.name()));

        for (ClassScan c : classes) {
            boolean isListener = c.interfaces().contains(LISTENER);
            boolean isRunnable = BUKKIT_RUNNABLE.equals(c.superName());

            for (MethodInfo m : c.methods()) {
                if (isListener && m.annotations().contains(EVENT_HANDLER) && hasEventParam(m.descriptor())) {
                    out.add(new HotEntrypoint(c.internalName(), m.name(), eventHeat(m.descriptor())));
                }
                if (isRunnable && m.name().equals("run") && m.descriptor().equals("()V") && hasSyncScheduler) {
                    out.add(new HotEntrypoint(c.internalName(), "run", Heat.WARM));
                }
            }
        }
        return out;
    }

    /**
     * Returns true when the method descriptor contains a single object parameter whose simple class
     * name ends with {@code "Event"}, e.g. {@code (Lorg/bukkit/event/player/PlayerMoveEvent;)V}.
     */
    private static boolean hasEventParam(String methodDescriptor) {
        int start = methodDescriptor.indexOf('L');
        int end = methodDescriptor.indexOf(';');
        if (start < 0 || end < 0 || end < start) {
            return false;
        }
        String internal = methodDescriptor.substring(start + 1, end);
        String simple = internal.substring(internal.lastIndexOf('/') + 1);
        return simple.endsWith("Event");
    }

    /** Heat from the (single) event parameter's simple class name; unknown *Event -> WARM, else COOL. */
    private static Heat eventHeat(String methodDescriptor) {
        int start = methodDescriptor.indexOf('L');
        int end = methodDescriptor.indexOf(';');
        if (start < 0 || end < 0 || end < start) {
            return Heat.COOL;
        }
        String internal = methodDescriptor.substring(start + 1, end);
        String simple = internal.substring(internal.lastIndexOf('/') + 1);
        Heat known = EVENT_HEAT.get(simple);
        if (known != null) {
            return known;
        }
        return simple.endsWith("Event") ? Heat.WARM : Heat.COOL;
    }
}
