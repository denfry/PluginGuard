package dev.pluginguard.engine.bytecode;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.analysis.Interpreter;
import org.objectweb.asm.tree.analysis.Value;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * An ASM {@link Interpreter} that performs intraprocedural <em>taint tracking</em>. A value becomes
 * "tainted" when it originates from an external/attacker-influenced source (data read from the
 * network, or the output of a decode/decrypt step) and the taint propagates through local-variable
 * copies, casts and method calls (a call on, or with, a tainted value yields a tainted result).
 *
 * <p>The carried payload is just a short <em>source label</em> ("the network" / "a decoded or
 * decrypted blob") so a downstream finding can name where the data came from; everything else is
 * modelled only precisely enough to keep slot sizes correct for the surrounding
 * {@link org.objectweb.asm.tree.analysis.Analyzer}. The {@code Analyzer} handles control flow and
 * merging, so a value tainted on any path into a point is treated as tainted there (a safe
 * over-approximation for "could carry external data").
 *
 * <p>This never executes anything; it only reasons about how values flow between instructions.
 */
public final class TaintInterpreter extends Interpreter<TaintInterpreter.TaintValue> {

    public static final String SOURCE_NETWORK = "the network";
    public static final String SOURCE_DECODED = "a decoded or decrypted blob";
    private static final String SOURCE_MIXED = "external data";

    /** A dataflow value: {@code source} is the taint label, or null when the value is untainted. */
    public static final class TaintValue implements Value {
        static final TaintValue CLEAN_1 = new TaintValue(1, null);
        static final TaintValue CLEAN_2 = new TaintValue(2, null);

        final int size;
        final String source;

        TaintValue(int size, String source) {
            this.size = size;
            this.source = source;
        }

        boolean tainted() {
            return source != null;
        }

        @Override
        public int getSize() {
            return size;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            return o instanceof TaintValue v && v.size == size && Objects.equals(v.source, source);
        }

        @Override
        public int hashCode() {
            return Objects.hash(size, source);
        }
    }

    /** Source methods that return externally-influenced data, keyed by {@code owner.name}. */
    private static final Map<String, String> SOURCES = Map.ofEntries(
            Map.entry("java/net/URL.openStream", SOURCE_NETWORK),
            Map.entry("java/net/URLConnection.getInputStream", SOURCE_NETWORK),
            Map.entry("java/net/HttpURLConnection.getInputStream", SOURCE_NETWORK),
            Map.entry("java/net/Socket.getInputStream", SOURCE_NETWORK),
            Map.entry("java/net/http/HttpResponse.body", SOURCE_NETWORK),
            Map.entry("java/util/Base64$Decoder.decode", SOURCE_DECODED),
            Map.entry("javax/crypto/Cipher.doFinal", SOURCE_DECODED));

    /** Owners whose every method is treated as a decode/decrypt source (e.g. Apache Commons codecs). */
    private static final Set<String> DECODE_OWNER_PREFIXES = Set.of(
            "org/apache/commons/codec/binary/");

    private static TaintValue clean(int size) {
        return size == 2 ? TaintValue.CLEAN_2 : TaintValue.CLEAN_1;
    }

    private static TaintValue of(int size, String source) {
        return source == null ? clean(size) : new TaintValue(size, source);
    }

    public TaintInterpreter() {
        super(Opcodes.ASM9);
    }

    @Override
    public TaintValue newValue(Type type) {
        if (type == null) {
            return TaintValue.CLEAN_1;
        }
        if (type == Type.VOID_TYPE) {
            return null;
        }
        return clean(type.getSize());
    }

    @Override
    public TaintValue newOperation(AbstractInsnNode insn) {
        switch (insn.getOpcode()) {
            case Opcodes.LCONST_0:
            case Opcodes.LCONST_1:
            case Opcodes.DCONST_0:
            case Opcodes.DCONST_1:
                return TaintValue.CLEAN_2;
            case Opcodes.LDC: {
                Object cst = ((org.objectweb.asm.tree.LdcInsnNode) insn).cst;
                return (cst instanceof Long || cst instanceof Double) ? TaintValue.CLEAN_2 : TaintValue.CLEAN_1;
            }
            case Opcodes.GETSTATIC:
                return clean(Type.getType(((FieldInsnNode) insn).desc).getSize());
            default:
                return TaintValue.CLEAN_1;
        }
    }

    @Override
    public TaintValue copyOperation(AbstractInsnNode insn, TaintValue value) {
        return value; // LOAD/STORE/DUP/SWAP preserve taint — local-variable tracking
    }

    @Override
    public TaintValue unaryOperation(AbstractInsnNode insn, TaintValue value) {
        switch (insn.getOpcode()) {
            case Opcodes.CHECKCAST:
                return value; // a cast keeps the taint
            case Opcodes.LNEG:
            case Opcodes.I2L:
            case Opcodes.F2L:
            case Opcodes.D2L:
            case Opcodes.DNEG:
            case Opcodes.I2D:
            case Opcodes.L2D:
            case Opcodes.F2D:
                return of(2, value.source);
            case Opcodes.GETFIELD:
                return clean(Type.getType(((FieldInsnNode) insn).desc).getSize());
            case Opcodes.PUTSTATIC:
            case Opcodes.IFEQ:
            case Opcodes.IFNE:
            case Opcodes.IFLT:
            case Opcodes.IFGE:
            case Opcodes.IFGT:
            case Opcodes.IFLE:
            case Opcodes.IFNULL:
            case Opcodes.IFNONNULL:
            case Opcodes.TABLESWITCH:
            case Opcodes.LOOKUPSWITCH:
            case Opcodes.ATHROW:
            case Opcodes.MONITORENTER:
            case Opcodes.MONITOREXIT:
                return null; // consume one value, push nothing
            default:
                return of(1, value.source); // INEG, conversions to int/float, ARRAYLENGTH, INSTANCEOF, …
        }
    }

    @Override
    public TaintValue binaryOperation(AbstractInsnNode insn, TaintValue v1, TaintValue v2) {
        switch (insn.getOpcode()) {
            case Opcodes.LALOAD:
            case Opcodes.DALOAD:
            case Opcodes.LADD:
            case Opcodes.DADD:
            case Opcodes.LSUB:
            case Opcodes.DSUB:
            case Opcodes.LMUL:
            case Opcodes.DMUL:
            case Opcodes.LDIV:
            case Opcodes.DDIV:
            case Opcodes.LREM:
            case Opcodes.DREM:
            case Opcodes.LSHL:
            case Opcodes.LSHR:
            case Opcodes.LUSHR:
            case Opcodes.LAND:
            case Opcodes.LOR:
            case Opcodes.LXOR:
                return of(2, join(v1, v2));
            case Opcodes.IF_ICMPEQ:
            case Opcodes.IF_ICMPNE:
            case Opcodes.IF_ICMPLT:
            case Opcodes.IF_ICMPGE:
            case Opcodes.IF_ICMPGT:
            case Opcodes.IF_ICMPLE:
            case Opcodes.IF_ACMPEQ:
            case Opcodes.IF_ACMPNE:
            case Opcodes.PUTFIELD:
                return null; // consume two values, push nothing
            default:
                // arithmetic / comparisons / AALOAD (e.g. reading from a tainted array stays tainted)
                return of(1, join(v1, v2));
        }
    }

    @Override
    public TaintValue ternaryOperation(AbstractInsnNode insn, TaintValue v1, TaintValue v2, TaintValue v3) {
        return null; // array stores consume three values, push nothing
    }

    @Override
    public TaintValue naryOperation(AbstractInsnNode insn, List<? extends TaintValue> values) {
        if (insn instanceof InvokeDynamicInsnNode indy) {
            Type ret = Type.getReturnType(indy.desc);
            return ret == Type.VOID_TYPE ? null : of(ret.getSize(), joinAll(values));
        }
        MethodInsnNode m = (MethodInsnNode) insn;
        Type ret = Type.getReturnType(m.desc);
        if (ret == Type.VOID_TYPE) {
            return null;
        }
        String source = sourceLabel(m);
        if (source != null) {
            return new TaintValue(ret.getSize(), source); // an external-data source
        }
        // Otherwise propagate: a call on, or with, tainted data yields a tainted result.
        return of(ret.getSize(), joinAll(values));
    }

    @Override
    public void returnOperation(AbstractInsnNode insn, TaintValue value, TaintValue expected) {
        // no-op: taint is not tracked across method returns
    }

    @Override
    public TaintValue merge(TaintValue a, TaintValue b) {
        if (a.equals(b)) {
            return a;
        }
        String source = join(a, b);
        TaintValue merged = of(a.size, source);
        if (merged.equals(a)) {
            return a;
        }
        return merged.equals(b) ? b : merged;
    }

    /** The taint label for a source method, or null if it is not a source. */
    private static String sourceLabel(MethodInsnNode m) {
        String exact = SOURCES.get(m.owner + "." + m.name);
        if (exact != null) {
            return exact;
        }
        for (String prefix : DECODE_OWNER_PREFIXES) {
            if (m.owner.startsWith(prefix)) {
                return SOURCE_DECODED;
            }
        }
        return null;
    }

    private static String join(TaintValue a, TaintValue b) {
        return join(a == null ? null : a.source, b == null ? null : b.source);
    }

    private static String join(String a, String b) {
        if (a == null) {
            return b;
        }
        if (b == null || a.equals(b)) {
            return a;
        }
        return SOURCE_MIXED;
    }

    private static String joinAll(List<? extends TaintValue> values) {
        String source = null;
        for (TaintValue v : values) {
            if (v != null && v.tainted()) {
                source = join(source, v.source);
            }
        }
        return source;
    }
}
