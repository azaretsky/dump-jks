package name.funny.ber;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Formatter;
import java.util.List;
import java.util.Objects;

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
    public final byte[] primitiveValue;

    public static BerValue fromBytes(byte[] bytes) {
        Cursor cursor = new Cursor();
        cursor.offset = 0;
        cursor.length = bytes.length;
        BerValue berValue = new BerValue(bytes, cursor);
        if (cursor.length > 0) {
            throw new IllegalArgumentException(cursor.offset + ": remaining length is " + cursor.length);
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
            if (primitiveValue.length > 0) {
                builder.append(' ');
                Formatter fmt = new Formatter(builder);
                for (byte b : primitiveValue) {
                    fmt.format("%02x", b);
                }
            }
        } else {
            builder.append(' ');
            builder.append(children);
        }
        return builder.toString();
    }

    private static class Cursor {
        int offset;
        int length;

        byte[] copyBytes(byte[] bytes) {
            return Arrays.copyOfRange(bytes, offset, offset + length);
        }
    }

    private BerValue(byte[] bytes, Cursor cursor) {
        int offset = cursor.offset;
        int length = cursor.length;
        Objects.checkFromIndexSize(offset, length, bytes.length);
        byte currentByte;
        if (length-- == 0) {
            throw new IllegalArgumentException(offset + ": end of input at tag");
        }
        currentByte = bytes[offset++];
        tagClass = TagClass.values()[(currentByte >> 6) & 0x03];
        primitive = (currentByte & 0x20) == 0;
        currentByte &= 0x1f;
        if (currentByte != 0x1f) {
            tag = currentByte;
        } else {
            int longTag = 0;
            int i = 0;
            do {
                if (length-- == 0) {
                    throw new IllegalArgumentException(offset + ": end of input at long tag byte " + i);
                }
                currentByte = bytes[offset++];
                longTag = (longTag << 7) | (currentByte & 0x7f);
                ++i;
            } while (i < 4 && (currentByte & 0x80) != 0);
            if ((currentByte & 0x80) != 0) {
                throw new IllegalArgumentException(offset - i + ": tag value is to long");
            }
            tag = longTag;
        }
        if (length-- == 0) {
            throw new IllegalArgumentException(offset + ": end of input at value length");
        }
        currentByte = bytes[offset++];
        if (currentByte == (byte) 0x80) {
            if (primitive) {
                throw new IllegalArgumentException(offset + ": indefinite length of primitive value");
            }
            cursor.offset = offset;
            cursor.length = length;
            primitiveValue = null;
            children = new ArrayList<>();
            for (; ; ) {
                if (cursor.length < 2) {
                    throw new IllegalArgumentException(cursor.offset + ": end of input at indefinite-length content");
                }
                if (bytes[cursor.offset] == 0 && bytes[cursor.offset + 1] == 0) {
                    cursor.offset += 2;
                    cursor.length -= 2;
                    break;
                }
                children.add(new BerValue(bytes, cursor));
            }
        } else {
            Cursor contentsCursor = new Cursor();
            if ((currentByte & 0x80) == 0) {
                contentsCursor.length = currentByte;
            } else {
                currentByte &= 0x7f;
                if (currentByte > 4) {
                    throw new IllegalArgumentException(offset + ":  length size " + currentByte + " is too big");
                }
                int valueLength = 0;
                for (int i = currentByte; i > 0; --i) {
                    if (length-- == 0) {
                        throw new IllegalArgumentException(offset + ": end of input at long value length");
                    }
                    currentByte = bytes[offset++];
                    valueLength = (valueLength << 8) | (currentByte & 0xff);
                }
                if (valueLength < 0) {
                    throw new IllegalArgumentException(offset + ": value length " + (((long) valueLength) & 0xffffffffL) + " is too big");
                }
                contentsCursor.length = valueLength;
            }
            if (contentsCursor.length > length) {
                throw new IllegalArgumentException(
                        offset + ": value length is " + contentsCursor.length
                                + ", remaining length is " + length);
            }
            contentsCursor.offset = offset;
            cursor.offset = offset + contentsCursor.length;
            cursor.length = length - contentsCursor.length;
            if (primitive) {
                primitiveValue = contentsCursor.copyBytes(bytes);
                children = null;
            } else {
                primitiveValue = null;
                children = new ArrayList<>();
                while (contentsCursor.length > 0) {
                    children.add(new BerValue(bytes, contentsCursor));
                }
            }
        }
    }
}
