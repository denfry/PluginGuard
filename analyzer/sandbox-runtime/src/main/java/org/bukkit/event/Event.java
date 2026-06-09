package org.bukkit.event;

/** Minimal base event so plugins that reference {@code org.bukkit.event.Event} link. */
public abstract class Event {

    public String getEventName() {
        return getClass().getSimpleName();
    }
}
