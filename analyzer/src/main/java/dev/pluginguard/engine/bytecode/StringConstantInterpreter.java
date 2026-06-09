package dev.pluginguard.engine.bytecode;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.analysis.Interpreter;
import org.objectweb.asm.tree.analysis.Value;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * An ASM {@link Interpreter} that performs intraprocedural <em>String constant folding</em>. It
 * tracks the concrete String value of stack/local slots through the operations that obfuscators use
 * to assemble a class or method name from more than one piece — local-variable copies, single-byte
 * {@code ldc}s, {@link StringBuilder}/{@link StringBuffer} chains, {@code String.concat}, and the
 * Java&nbsp;9+ {@code invokedynamic} string concatenation ({@code StringConcatFactory}).
 *
 * <p>It carries <em>only</em> a String payload (or "unknown"); everything else is modelled just
 * precisely enough to keep slot sizes correct so the surrounding {@link org.objectweb.asm.tree.analysis.Analyzer}
 * can compute frames without error. The {@code Analyzer} itself handles control flow, local-variable
 * frames and merging across branches, so a value assembled along a straight path is resolved while a
 * value that depends on a runtime branch correctly degrades to "unknown".
 *
 * <p>This never executes anything; it only reasons about constants already present in the bytecode.
 */
public final class StringConstantInterpreter extends Interpreter<StringConstantInterpreter.StrValue> {

    private static final String STRING_BUILDER = "java/lang/StringBuilder";
    private static final String STRING_BUFFER = "java/lang/StringBuffer";
    private static final String STRING_CONCAT_FACTORY = "java/lang/invoke/StringConcatFactory";

    /** A folded value: {@code text} is the known String (for String/StringBuilder slots), or null. */
    public static final class StrValue implements Value {
        static final StrValue UNKNOWN_1 = new StrValue(1, null);
        static final StrValue UNKNOWN_2 = new StrValue(2, null);

        final int size;
        final String text;

        StrValue(int size, String text) {
            this.size = size;
            this.text = text;
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
            return o instanceof StrValue s && s.size == size && Objects.equals(s.text, text);
        }

        @Override
        public int hashCode() {
            return Objects.hash(size, text);
        }
    }

    /** Known constant values of static String fields, keyed by {@code owner.name}. */
    private final Map<String, String> constStringFields;

    public StringConstantInterpreter(Map<String, String> constStringFields) {
        super(Opcodes.ASM9);
        this.constStringFields = constStringFields;
    }

    private static StrValue unknown(int size) {
        return size == 2 ? StrValue.UNKNOWN_2 : StrValue.UNKNOWN_1;
    }

    @Override
    public StrValue newValue(Type type) {
        if (type == null) {
            return StrValue.UNKNOWN_1; // uninitialized slot
        }
        if (type == Type.VOID_TYPE) {
            return null;
        }
        return unknown(type.getSize());
    }

    @Override
    public StrValue newOperation(AbstractInsnNode insn) {
        switch (insn.getOpcode()) {
            case Opcodes.LCONST_0:
            case Opcodes.LCONST_1:
            case Opcodes.DCONST_0:
            case Opcodes.DCONST_1:
                return StrValue.UNKNOWN_2;
            case Opcodes.LDC: {
                Object cst = ((LdcInsnNode) insn).cst;
                if (cst instanceof String s) {
                    return new StrValue(1, s);
                }
                if (cst instanceof Long || cst instanceof Double) {
                    return StrValue.UNKNOWN_2;
                }
                return StrValue.UNKNOWN_1;
            }
            case Opcodes.GETSTATIC: {
                FieldInsnNode f = (FieldInsnNode) insn;
                int size = Type.getType(f.desc).getSize();
                String value = constStringFields.get(f.owner + "." + f.name);
                return new StrValue(size, value);
            }
            case Opcodes.NEW: {
                String desc = ((TypeInsnNode) insn).desc;
                if (STRING_BUILDER.equals(desc) || STRING_BUFFER.equals(desc)) {
                    return new StrValue(1, ""); // a fresh builder accumulates from the empty string
                }
                return StrValue.UNKNOWN_1;
            }
            default:
                return StrValue.UNKNOWN_1;
        }
    }

    @Override
    public StrValue copyOperation(AbstractInsnNode insn, StrValue value) {
        return value; // LOAD/STORE/DUP/SWAP preserve the payload — this is local-variable tracking
    }

    @Override
    public StrValue unaryOperation(AbstractInsnNode insn, StrValue value) {
        switch (insn.getOpcode()) {
            case Opcodes.CHECKCAST:
                return value; // a cast does not change the String payload
            case Opcodes.LNEG:
            case Opcodes.I2L:
            case Opcodes.F2L:
            case Opcodes.D2L:
            case Opcodes.DNEG:
            case Opcodes.I2D:
            case Opcodes.L2D:
            case Opcodes.F2D:
                return StrValue.UNKNOWN_2;
            case Opcodes.GETFIELD:
                return unknown(Type.getType(((FieldInsnNode) insn).desc).getSize());
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
                return StrValue.UNKNOWN_1;
        }
    }

    @Override
    public StrValue binaryOperation(AbstractInsnNode insn, StrValue v1, StrValue v2) {
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
                return StrValue.UNKNOWN_2;
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
                return StrValue.UNKNOWN_1;
        }
    }

    @Override
    public StrValue ternaryOperation(AbstractInsnNode insn, StrValue v1, StrValue v2, StrValue v3) {
        return null; // array stores consume three values, push nothing
    }

    @Override
    public StrValue naryOperation(AbstractInsnNode insn, List<? extends StrValue> values) {
        if (insn instanceof InvokeDynamicInsnNode indy) {
            return foldIndyConcat(indy, values);
        }
        if (insn instanceof MethodInsnNode m) {
            StrValue folded = foldStringCall(m, values);
            if (folded != null) {
                return folded;
            }
            Type ret = Type.getReturnType(m.desc);
            return ret == Type.VOID_TYPE ? null : unknown(ret.getSize());
        }
        // MULTIANEWARRAY
        return StrValue.UNKNOWN_1;
    }

    /** Folds {@code StringBuilder.append/toString}, {@code StringBuffer.*} and {@code String.concat}. */
    private StrValue foldStringCall(MethodInsnNode m, List<? extends StrValue> values) {
        boolean builder = STRING_BUILDER.equals(m.owner) || STRING_BUFFER.equals(m.owner);
        if (builder && "append".equals(m.name) && values.size() == 2) {
            StrValue receiver = values.get(0);
            String appended = asString(values.get(1), Type.getArgumentTypes(m.desc)[0]);
            if (receiver != null && receiver.text != null && appended != null) {
                return new StrValue(1, receiver.text + appended);
            }
            return StrValue.UNKNOWN_1; // builder content is no longer fully known
        }
        if (builder && "toString".equals(m.name) && values.size() == 1) {
            StrValue receiver = values.get(0);
            return new StrValue(1, receiver == null ? null : receiver.text);
        }
        if ("java/lang/String".equals(m.owner) && "concat".equals(m.name) && values.size() == 2) {
            StrValue a = values.get(0);
            StrValue b = values.get(1);
            if (a != null && a.text != null && b != null && b.text != null) {
                return new StrValue(1, a.text + b.text);
            }
            return StrValue.UNKNOWN_1;
        }
        return null;
    }

    /** Folds {@code invokedynamic} string concatenation produced by {@code StringConcatFactory}. */
    private StrValue foldIndyConcat(InvokeDynamicInsnNode indy, List<? extends StrValue> values) {
        Type ret = Type.getReturnType(indy.desc);
        if (!STRING_CONCAT_FACTORY.equals(indy.bsm.getOwner())) {
            return ret == Type.VOID_TYPE ? null : unknown(ret.getSize());
        }
        StringBuilder out = new StringBuilder();
        if ("makeConcat".equals(indy.bsm.getName())) {
            for (StrValue v : values) {
                if (v == null || v.text == null) {
                    return StrValue.UNKNOWN_1;
                }
                out.append(v.text);
            }
            return new StrValue(1, out.toString());
        }
        if ("makeConcatWithConstants".equals(indy.bsm.getName()) && indy.bsmArgs.length >= 1
                && indy.bsmArgs[0] instanceof String recipe) {
            int dynIndex = 0;
            int constIndex = 1;
            for (int i = 0; i < recipe.length(); i++) {
                char c = recipe.charAt(i);
                if (c == '') { // a dynamic argument from the stack
                    if (dynIndex >= values.size()) {
                        return StrValue.UNKNOWN_1;
                    }
                    StrValue v = values.get(dynIndex++);
                    if (v == null || v.text == null) {
                        return StrValue.UNKNOWN_1;
                    }
                    out.append(v.text);
                } else if (c == '') { // a constant from the bootstrap arguments
                    if (constIndex >= indy.bsmArgs.length || !(indy.bsmArgs[constIndex++] instanceof String s)) {
                        return StrValue.UNKNOWN_1;
                    }
                    out.append(s);
                } else {
                    out.append(c);
                }
            }
            return new StrValue(1, out.toString());
        }
        return unknown(ret.getSize());
    }

    @Override
    public void returnOperation(AbstractInsnNode insn, StrValue value, StrValue expected) {
        // no-op: we do not track return values across methods
    }

    @Override
    public StrValue merge(StrValue a, StrValue b) {
        if (a.equals(b)) {
            return a;
        }
        return unknown(a.size); // both occupy the same slot, so sizes match; the value is now ambiguous
    }

    /** The String value an argument contributes to concatenation, when the parameter is a String. */
    private static String asString(StrValue value, Type paramType) {
        if (value != null && value.text != null && "Ljava/lang/String;".equals(paramType.getDescriptor())) {
            return value.text;
        }
        return null;
    }
}
