package org.bukkit.command;

/** A registered command. Only the name-bearing subset the harness needs is modelled. */
public class Command {

    private final String name;

    public Command(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
