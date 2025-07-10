package com.github.rafalh.ghidra.dwarfone.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import ghidra.app.util.bin.BinaryReader;

public class DebugInfoEntry {
    
    private final long ref;
    private final long length; // Added field to store the length
    private final int rawTag;
    private final Tag tag;
    private final Map<AttributeName, AttributeValue> attributes = new HashMap<>();
    private final Map<Integer, AttributeValue> userAttributes = new HashMap<>();
    private DebugInfoEntry parent; // Not final, as it's set by the parser
    private final List<DebugInfoEntry> children = new ArrayList<>();
    
    public DebugInfoEntry(BinaryReader reader, DebugInfoEntry parent) throws IOException {
        ref = reader.getPointerIndex();
        long initialLengthRead = reader.readNextUnsignedInt(); // Read the length first
        
        // DWARF 1.1.0 terminator check: length < 8 (typically 0 or 4 for padding/terminator)
        if (initialLengthRead < 8) {
            this.length = initialLengthRead; // Store the short length
            rawTag = -1;
            tag = Tag.NULL;
            reader.setPointerIndex(ref + this.length); // Advance reader past this terminator DIE
        } else {
            this.length = initialLengthRead; // Store the full length
            rawTag = reader.readNextUnsignedShort();
            tag = Tag.decode(rawTag);

            // Calculate the end index for attributes (length includes 4-byte length + 2-byte tag)
            long attributesAndChildrenEndIndex = ref + this.length;
            
            // Read attributes until the end of this DIE's declared attribute block
            while (reader.getPointerIndex() < attributesAndChildrenEndIndex) {
                Map.Entry<Integer, AttributeValue> at = AttributeUtils.readAttribute(reader);
                AttributeName attributeName = AttributeName.decode(at.getKey());
                if (attributeName != AttributeName.USER) {
                    attributes.put(attributeName, at.getValue());
                } else {
                    userAttributes.put(at.getKey(), at.getValue());
                }
            }
        }
        
        this.parent = parent; 
        if (parent != null && tag != Tag.NULL) {
            parent.children.add(this); 
        }
    }
    
    @Override
    public String toString() {
        return Long.toHexString(ref) + ":" + Objects.toString(tag) + attributes.toString();
    }
    
    public long getRef() {
        return ref;
    }
    
    public long getLength() {
        return length;
    }
    
    public Tag getTag() {
        return tag;
    }
    
    @SuppressWarnings("unchecked")
    public <T extends AttributeValue> Optional<T> getAttribute(AttributeName name) {
        return Optional.ofNullable((T) attributes.get(name));
    }
    
    @SuppressWarnings("unchecked")
    public <T extends AttributeValue> Optional<T> getAttribute(int name) {
        return Optional.ofNullable(
                Optional.ofNullable((T) attributes.get(AttributeName.decode(name)))
                .orElseGet(() -> (T) userAttributes.get(name)));
    }
    
    public DebugInfoEntry getParent() {
        return parent;
    }
    
    // Method to set parent, useful if parent is determined after initial construction
    public void setParent(DebugInfoEntry parent) {
        this.parent = parent;
    }
    
    public List<DebugInfoEntry> getChildren() {
        return children;
    }
}