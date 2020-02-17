package name.funny.ber;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.List;

public class BerValue {
    public enum TagClass {
        Universal,
        Application,
        Context,
        Private
    }

    public final TagClass tagClass;
    public final int tag;

    public final boolean primitive;
    public final List<BerValue> children;
    public final ByteBuffer elementBuffer;
    public final ByteBuffer valueBuffer;

    public static BerValue fromBytes(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        BerValue berValue = new BerValue(buffer);
        if (buffer.hasRemaining()) {
            throw new IllegalArgumentException(buffer.position() + ": remaining length is " + buffer.remaining());
        }
        return berValue;
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public boolean matchConstructed(TagClass tagClass, int tag) {
        return !primitive && matchTag(tagClass, tag);
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public boolean matchPrimitive(TagClass tagClass, int tag) {
        return primitive && matchTag(tagClass, tag);
    }

    private boolean matchTag(TagClass tagClass, int tag) {
        return this.tagClass == tagClass && this.tag == tag;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(tagClass);
        builder.append(' ');
        builder.append(tag);
        if (primitive) {
            if (valueBuffer.limit() > 0) {
                builder.append(' ');
                Formatter fmt = new Formatter(builder);
                for (int i = 0; i < valueBuffer.limit(); i++) {
                    fmt.format("%02x", valueBuffer.get(i));
                }
            }
        } else {
            builder.append(' ');
            builder.append(children);
        }
        return builder.toString();
    }

    private static ByteBuffer subBuffer(ByteBuffer buffer, int start, int end) {
        int originalPosition = buffer.position();
        int originalLimit = buffer.limit();
        buffer.limit(end);
        buffer.position(start);
        ByteBuffer sub = buffer.slice();
        buffer.limit(originalLimit);
        buffer.position(originalPosition);
        return sub;
    }

    private BerValue(ByteBuffer buffer) {
        int elementStart = buffer.position();
        byte currentByte;
        currentByte = buffer.get();
        tagClass = TagClass.values()[(currentByte >> 6) & 0x03];
        primitive = (currentByte & 0x20) == 0;
        currentByte &= 0x1f;
        if (currentByte != 0x1f) {
            tag = currentByte;
        } else {
            int longTag = 0;
            do {
                if (longTag > Integer.MAX_VALUE >> 7) {
                    throw new IllegalArgumentException("long tag value is too big");
                }
                currentByte = buffer.get();
                longTag = (longTag << 7) | (currentByte & 0x7f);
            } while ((currentByte & 0x80) != 0);
            tag = longTag;
        }
        currentByte = buffer.get();
        if (currentByte == (byte) 0x80) {
            if (primitive) {
                throw new IllegalArgumentException("indefinite length of primitive value");
            }
            int valueStart = buffer.position();
            children = new ArrayList<>();
            for (; ; ) {
                buffer.mark();
                // test for an end-of-contents marker:
                // current buffer order does not matter,
                // since both bytes should be zero
                if (buffer.getShort() == 0) {
                    elementBuffer = subBuffer(buffer, elementStart, buffer.position());
                    valueBuffer = subBuffer(buffer, valueStart, buffer.position() - 2);
                    break;
                }
                buffer.reset();
                children.add(new BerValue(buffer));
            }
        } else {
            int valueLength;
            if ((currentByte & 0x80) == 0) {
                valueLength = currentByte;
            } else {
                valueLength = 0;
                int lengthSize = currentByte & 0x7f;
                while (lengthSize-- > 0) {
                    if (valueLength > Integer.MAX_VALUE >> 8) {
                        throw new IllegalArgumentException("tag length is too big");
                    }
                    currentByte = buffer.get();
                    valueLength = (valueLength << 8) | (currentByte & 0xff);
                }
            }
            int elementEnd = buffer.position() + valueLength;
            elementBuffer = subBuffer(buffer, elementStart, elementEnd);
            valueBuffer = subBuffer(buffer, buffer.position(), elementEnd);
            buffer.position(elementEnd);
            if (primitive) {
                children = null;
            } else {
                children = new ArrayList<>();
                while (valueBuffer.hasRemaining()) {
                    children.add(new BerValue(valueBuffer));
                }
                valueBuffer.rewind();
            }
        }
    }
}
