package com.github.rafalh.ghidra.dwarfone;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Locale;
import java.util.stream.Collectors;

import com.github.rafalh.ghidra.dwarfone.model.AttributeName;
import com.github.rafalh.ghidra.dwarfone.model.AttributeUtils;
import com.github.rafalh.ghidra.dwarfone.model.AttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.BlockAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.ConstAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.Format;
import com.github.rafalh.ghidra.dwarfone.model.FundamentalType;
import com.github.rafalh.ghidra.dwarfone.model.LocationAtomOp;
import com.github.rafalh.ghidra.dwarfone.model.LocationDescription;
import com.github.rafalh.ghidra.dwarfone.model.Tag;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.DataTypeComponent;

public class DWARF1TypeImporter {

    private final DWARF1Program program;
    private final MessageLog log;
    private final CategoryPath categoryPath;
    private final DWARF1TypeManager dwarfTypeManager;
    private final DWARF1TypeExtractor typeExtractor;

    private final Map<String, DataType> anonAggregateCache = new HashMap<>();

    public DWARF1TypeImporter(DWARF1Program program, MessageLog log,
            DWARF1TypeManager dwarfTypeManager,
            DWARF1TypeExtractor typeExtractor) {
        this.program = program;
        this.log = log;
        this.dwarfTypeManager = dwarfTypeManager;
        this.typeExtractor = typeExtractor;
        this.categoryPath = new CategoryPath("/DWARF");
    }

    DataType processTypeDebugInfoEntry(DebugInfoEntry die) {
        try {
            switch (die.getTag()) {
                case CLASS_TYPE:
                case STRUCTURE_TYPE:
                    return processClassType(die);
                case UNION_TYPE:
                    return processUnionType(die);
                case ENUMERATION_TYPE:
                    return processEnumType(die);
                case ARRAY_TYPE:
                    return processArrayType(die);
                case SUBROUTINE_TYPE:
                    return processSubroutineType(die);
                case TYPEDEF:
                case STRING_TYPE:
                case POINTER_TYPE:
                case PTR_TO_MEMBER_TYPE:
                case SET_TYPE:
                case SUBRANGE_TYPE:
                    // TODO
                    throw new IllegalArgumentException(
                        "Unsupported debug info entry tag: " + die.getTag());
                default:
                    // skip other tags
                    throw new IllegalArgumentException("Expected type tag, got " + die.getTag());
            }
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to process type debug info entry " + die, e);
        }
    }

    private DataType processSubroutineType(DebugInfoEntry die) {
        // Note: this is a function type, not a pointer to function type
        DataType returnDt = typeExtractor.extractDataType(die);
        List<ParameterDefinition> params = new ArrayList<>();
        for (DebugInfoEntry childDie : die.getChildren()) {
            if (childDie.getTag() == Tag.FORMAL_PARAMETER) {
                String paramName = DWARF1ImportUtils.extractName(childDie).orElse(null);
                DataType dt = typeExtractor.extractDataType(childDie);
                params.add(new ParameterDefinitionImpl(paramName, dt, null));
            }
        }
        var paramsStr = params.stream()
                .map(ParameterDefinition::toString)
                .collect(Collectors.joining(", "));
        if (paramsStr.isEmpty()) {
            paramsStr = "void";
        }
        var funDtName = returnDt.toString() + "(" + paramsStr + ")";
        // check if type already exists
        DataTypeManager dtMgr = program.getDataTypeManager();
        DataType funDt = dtMgr.getDataType(categoryPath, funDtName);
        if (funDt == null || !(funDt instanceof FunctionDefinition)) {
            FunctionDefinitionDataType funDefDt =
                new FunctionDefinitionDataType(categoryPath, funDtName, dtMgr);
            funDefDt.setReturnType(returnDt);
            funDefDt.setArguments(params.toArray(new ParameterDefinition[params.size()]));
            funDt = dtMgr.addDataType(funDefDt, DataTypeConflictHandler.DEFAULT_HANDLER);
        }
        dwarfTypeManager.registerType(die.getRef(), funDt);
        return funDt;
    }

    private DataType processArrayType(DebugInfoEntry die) throws IOException {
        byte[] subscrData = die.<BlockAttributeValue> getAttribute(AttributeName.SUBSCR_DATA)
                .map(av -> av.get())
                .orElseThrow(
                    () -> new IllegalArgumentException("array type without subscr_data " + die));
        var bp = new ByteArrayProvider(subscrData);
        List<Integer> dims = new ArrayList<>();
        DataType baseDt = null;
        BinaryReader br = new BinaryReader(bp, program.isLittleEndian());
        while (br.getPointerIndex() < bp.length()) {
            Format fmt = Format.decode(br.readNextByte());
            if (fmt == Format.ET) {
                Map.Entry<Integer, AttributeValue> attributeEntry =
                    AttributeUtils.readAttribute(br);
                var at = AttributeName.decode(attributeEntry.getKey());
                var av = attributeEntry.getValue();
                baseDt = typeExtractor.extractDataType(at, av);
            }
            else if (fmt == Format.FT_C_C) {
                // type of index - unused
                FundamentalType.fromValue(br.readNextUnsignedShort());
                int minIndex = br.readNextInt();
                int maxIndex = br.readNextInt();
                int numElements = maxIndex - minIndex + 1;
                dims.add(numElements);
            }
            else if (fmt == Format.FT_C_X) {
                // type of index - unused
                FundamentalType.fromValue(br.readNextUnsignedShort());
                int minIndex = br.readNextInt();
                int size = br.readNextUnsignedShort();
                if (size == 0) {
                    int location = 0;
                }
                else {
                    // TODO
                    long block = br.readNextValue(size);
                    //                    int location = processBlock(block);
                }
            }
            else {
                log.appendMsg("Unsupported format " + fmt + " in " + die);
                break;
            }
        }
        if (baseDt == null) {
            throw new IllegalArgumentException("Missing array element type information");
        }
        DataType dt = baseDt;
        Collections.reverse(dims);
        for (int dim : dims) {
            if (dim < 0) {
                throw new IllegalArgumentException("Bad array dimension: " + dim);
            }
            if (dim == 0) {
                // Ghidra does not support array data type with length 0 so return it as void type, which has zero size
                dt = VoidDataType.dataType;
                break;
            }
            dt = new ArrayDataType(dt, dim, -1, program.getDataTypeManager());
        }
        dwarfTypeManager.registerType(die.getRef(), dt);
        return dt;
    }

    private DataType processClassType(DebugInfoEntry die) {
        Optional<Number> byteSizeOpt =
            die.<ConstAttributeValue> getAttribute(AttributeName.BYTE_SIZE)
                    .map(ConstAttributeValue::get);

        String dwarfName = DWARF1ImportUtils.extractName(die).orElse(null);
        String ghidraTypeName;

        // Check for generic or missing DWARF name patterns for classes/structs
        if (isAnonName(dwarfName)) {
            ghidraTypeName = "@anon_" + Long.toHexString(die.getRef());
            // log.appendMsg("DEBUG: Renaming generic struct/class '" + (dwarfName != null ? dwarfName : "<no-name>") +
            //               "' to unique Ghidra name '" + ghidraTypeName + "' (DIE Ref: 0x" + Long.toHexString(die.getRef()) + ")");
        }
        else {
            ghidraTypeName = dwarfName;
        }

        DataTypeManager dataTypeManager = program.getDataTypeManager();
        DataType existingDt = dataTypeManager.getDataType(categoryPath, ghidraTypeName);
        if (existingDt != null) {
            dwarfTypeManager.registerType(die.getRef(), existingDt);
            return existingDt;
        }

        if (byteSizeOpt.isEmpty()) {
            throw new IllegalArgumentException("class type is missing byte size attribute");
        }
        int size = byteSizeOpt.get().intValue();

        StructureDataType tempDt =
            new StructureDataType(categoryPath, ghidraTypeName, size, dataTypeManager);
        dwarfTypeManager.registerType(die.getRef(), tempDt);

        for (DebugInfoEntry childDie : die.getChildren()) {
            switch (childDie.getTag()) {
                case MEMBER:
                    processClassTypeMember(tempDt, childDie);
                    break;
                case INHERITANCE:
                    processClassTypeInheritance(tempDt, childDie);
                    break;
                case GLOBAL_VARIABLE:
                case SUBROUTINE:
                case GLOBAL_SUBROUTINE:
                case TYPEDEF:
                case STRUCTURE_TYPE:
                case ARRAY_TYPE:
                case ENUMERATION_TYPE:
                case UNION_TYPE:
                case CLASS_TYPE:
                case SUBROUTINE_TYPE:
                case PTR_TO_MEMBER_TYPE:
                    break;
                default:
                    log.appendMsg("Unexpected child of class type: " + childDie.getTag());
            }
        }

        if (isAnonName(ghidraTypeName)) {
            DataType dedupDt = deduplicateAnonAggregate(tempDt);
            if (dedupDt != null) {
                dwarfTypeManager.unregisterType(die.getRef());
                dwarfTypeManager.registerType(die.getRef(), dedupDt);
                return dedupDt;
            }
        }

        Structure newDt = (Structure) dataTypeManager.addDataType(
            tempDt, DataTypeConflictHandler.DEFAULT_HANDLER);
        dwarfTypeManager.registerType(die.getRef(), newDt);
        return newDt;
    }

    private void processClassTypeInheritance(Structure sdt, DebugInfoEntry die) {
        DataType baseDt = typeExtractor.extractDataType(die);
        sdt.replaceAtOffset(0, baseDt, -1, "__base", null);
    }

    private void processClassTypeMember(Structure sdt, DebugInfoEntry die) {
        String memberName = DWARF1ImportUtils.extractName(die).orElse(null);
        DataType memberDt = typeExtractor.extractDataType(die);
        int memberOffset = extractMemberOffset(die);
        assert memberDt != null;
        if (memberOffset >= sdt.getLength()) {
            return;
        }
        sdt.replaceAtOffset(memberOffset, memberDt, -1, memberName, null);
    }

    private DataType processUnionType(DebugInfoEntry die) {
        String dwarfName = DWARF1ImportUtils.extractName(die).orElse(null);
        String ghidraTypeName;

        if (isAnonName(dwarfName)) {
            ghidraTypeName = "@union_" + Long.toHexString(die.getRef());
            // log.appendMsg("DEBUG: Renaming generic union '" + (dwarfName != null ? dwarfName : "<no-name>") +
            //               "' to unique Ghidra name '" + ghidraTypeName + "' (DIE Ref: 0x" + Long.toHexString(die.getRef()) + ")");
        }
        else {
            ghidraTypeName = dwarfName;
        }

        DataTypeManager dataTypeManager = program.getDataTypeManager();
        DataType existingDt = dataTypeManager.getDataType(categoryPath, ghidraTypeName);
        if (existingDt != null) {
            dwarfTypeManager.registerType(die.getRef(), existingDt);
            return existingDt;
        }

        UnionDataType tempUnionDt =
            new UnionDataType(categoryPath, ghidraTypeName, dataTypeManager);

        // populate the union before dedup
        for (DebugInfoEntry childDie : die.getChildren()) {
            switch (childDie.getTag()) {
                case MEMBER:
                    processUnionTypeMember(tempUnionDt, childDie);
                    break;
                default:
                    log.appendMsg("Unexpected child of union type: " + childDie.getTag());
            }
        }

        if (isAnonName(ghidraTypeName)) {
            DataType dedupDt = deduplicateAnonAggregate(tempUnionDt);
            if (dedupDt != null) {
                dwarfTypeManager.registerType(die.getRef(), dedupDt);
                return dedupDt;
            }
        }

        Union newUnionDt = (Union) dataTypeManager.addDataType(
            tempUnionDt, DataTypeConflictHandler.DEFAULT_HANDLER);
        dwarfTypeManager.registerType(die.getRef(), newUnionDt);
        return newUnionDt;

    }

    private void processUnionTypeMember(Union union, DebugInfoEntry die) {
        String memberName = DWARF1ImportUtils.extractName(die).orElse(null);
        DataType memberDt = typeExtractor.extractDataType(die);
        union.add(memberDt, memberName, null);
    }

    private DataType processEnumType(DebugInfoEntry die) throws IOException {
        Optional<Number> byteSizeOpt =
            die.<ConstAttributeValue> getAttribute(AttributeName.BYTE_SIZE).map(av -> av.get());
        Optional<byte[]> elementListOpt =
            die.<BlockAttributeValue> getAttribute(AttributeName.ELEMENT_LIST).map(av -> av.get());

        String dwarfName = DWARF1ImportUtils.extractName(die).orElse(null);
        String ghidraEnumName;

        if (isAnonName(dwarfName)) {
            ghidraEnumName = "@enum_" + Long.toHexString(die.getRef());
            // log.appendMsg("DEBUG: Renaming generic enum '" + (dwarfName != null ? dwarfName : "<no-name>") +
            //               "' to unique Ghidra name '" + ghidraEnumName + "' (DIE Ref: 0x" + Long.toHexString(die.getRef()) + ")");
        }
        else {
            ghidraEnumName = dwarfName;
        }

        DataTypeManager dataTypeManager = program.getDataTypeManager();

        int size = byteSizeOpt.orElse(4).intValue();
        var tempEnumDt = new EnumDataType(categoryPath, ghidraEnumName, size, dataTypeManager);
        if (elementListOpt.isPresent()) {
            processEnumElementList(tempEnumDt, elementListOpt.get(), size);
            String commonPrefix = getLargestCommonMemberPrefix(tempEnumDt);
            Boolean isBooleanEnum = isBooleanEnum(tempEnumDt);
            // Try to rename only if enum is anonymous
            if (commonPrefix != null && isAnonName(ghidraEnumName)) {
                try {
                    tempEnumDt.setName(commonPrefix);
                }
                catch (ghidra.util.InvalidNameException e) {
                    log.appendMsg("Failed to rename enum '" + tempEnumDt.getName() + "' to '" +
                        commonPrefix + "': " + e.getMessage());
                }
            }
            else if (isBooleanEnum && isAnonName(ghidraEnumName)) {
                try {
                    tempEnumDt.setName("bool");
                }
                catch (ghidra.util.InvalidNameException e) {
                    log.appendMsg(
                        "Failed to rename enum '" + tempEnumDt.getName() + "' to 'bool': " +
                            e.getMessage());
                }
            }
        }

        DataType existingDt = dataTypeManager.getDataType(categoryPath, ghidraEnumName);
        if (existingDt != null) {
            dwarfTypeManager.registerType(die.getRef(), existingDt);
            return existingDt;
        }

        DataType enumDt =
            dataTypeManager.addDataType(tempEnumDt, DataTypeConflictHandler.DEFAULT_HANDLER);
        dwarfTypeManager.registerType(die.getRef(), enumDt);
        return enumDt;
    }

    private void processEnumElementList(EnumDataType edt, byte[] encodedElementList, int size)
            throws IOException {
        var bp = new ByteArrayProvider(encodedElementList);
        BinaryReader br = new BinaryReader(bp, program.isLittleEndian());

        while (br.getPointerIndex() < bp.length()) {
            long value;
            switch (size) {
                case 1:
                    value = br.readNextByte() & 0xFF;
                    break;
                case 2:
                    value = br.readNextShort() & 0xFFFF;
                    break;
                case 4:
                    value = br.readNextInt() & 0xFFFFFFFFL;
                    break;
                case 8:
                    value = br.readNextLong();
                    break;
                default:
                    throw new IOException("Unsupported enum byte size: " + size);
            }

            String name = br.readNextAsciiString();
            edt.add(name, value);
        }
    }

    /**
     * Calculates the longest common prefix of all enum member names,
     * trimming leading underscores first and returning a natural prefix.
     */
    private String getLargestCommonMemberPrefix(EnumDataType edt) {
        String[] names = edt.getNames();
        if (names.length == 0) {
            return null;
        }

        // Collect valid, underscore-trimmed names
        List<String> validNames = new ArrayList<>();
        for (String name : names) {
            if (name != null && !name.isEmpty()) {
                // Trim leading underscores for prefix alignment
                validNames.add(name.replaceFirst("^_+", ""));
            }
        }
        if (validNames.isEmpty()) {
            return null;
        }

        // Start with the first name as reference
        String prefix = validNames.get(0);

        // Compute longest common prefix
        for (int i = 1; i < validNames.size(); i++) {
            String name = validNames.get(i);
            int j = 0;
            int max = Math.min(prefix.length(), name.length());
            while (j < max && prefix.charAt(j) == name.charAt(j)) {
                j++;
            }
            prefix = prefix.substring(0, j);
            if (prefix.isEmpty()) {
                return null;
            }
        }

        // Cut at the last underscore to keep the “semantic” prefix
        int lastSep = prefix.lastIndexOf('_');
        if (lastSep >= 0) {
            prefix = prefix.substring(0, lastSep);
        }

        // Reject trivial or too-short prefixes
        if (prefix.length() < 3) {
            return null;
        }

        return prefix;
    }

    /**
    * Detects whether the given EnumDataType semantically represents a boolean.
    * Recognizes patterns like FALSE=0/TRUE=1, NO=0/YES=1, OFF=0/ON=1, etc.
    */
    private boolean isBooleanEnum(EnumDataType edt) {
        String[] names = edt.getNames();
        if (names.length != 2) {
            return false; // must have exactly 2 entries
        }

        // Collect normalized (value, name) pairs
        Map<Long, String> norm = new HashMap<>();
        for (String name : names) {
            if (name == null) {
                continue;
            }
            long value;
            try {
                value = edt.getValue(name);
            }
            catch (Exception e) {
                continue;
            }

            // Normalize: remove underscores and punctuation, uppercase
            String normalized = name
                    .toUpperCase(Locale.ROOT)
                    .replaceFirst("^_+", "") // remove leading underscores
                    .replaceAll("[^A-Z0-9]", ""); // keep only alphanumerics

            norm.put(value, normalized);
        }

        if (!norm.containsKey(0L) || !norm.containsKey(1L)) {
            return false; // must have values 0 and 1
        }

        String zeroName = norm.get(0L);
        String oneName = norm.get(1L);

        // Known boolean-style pairs
        String[][] knownPairs = {
            { "FALSE", "TRUE" },
            { "NO", "YES" },
            { "OFF", "ON" },
            { "DISABLED", "ENABLED" },
            { "LOW", "HIGH" },
            { "ZERO", "ONE" },
            { "CLEAR", "SET" }
        };

        for (String[] pair : knownPairs) {
            if (zeroName.equals(pair[0]) && oneName.equals(pair[1])) {
                return true;
            }
        }

        return false;
    }

    private boolean isAnonName(String name) {
        return name == null ||
            name.isEmpty() ||
            name.startsWith("@class") ||
            name.startsWith("@union") ||
            name.startsWith("@anon") ||
            name.startsWith("@enum") ||
            name.matches("^@anon(\\d+)?$");
    }

    /**
     * Generate a hashable signature for a Structure or Union based on its layout.
     */
    private String computeAggregateSignature(DataType aggregate) {
        StringBuilder sb = new StringBuilder();

        if (aggregate instanceof StructureDataType sdt) {
            sb.append("struct:");
            for (DataTypeComponent c : sdt.getComponents()) {
                sb.append(c.getFieldName())
                        .append(':')
                        .append(c.getDataType().getName())
                        .append(':')
                        .append(c.getOffset())
                        .append(':')
                        .append(c.getLength())
                        .append(';');
            }
        }
        else if (aggregate instanceof UnionDataType udt) {
            sb.append("union:");
            for (DataTypeComponent c : udt.getComponents()) {
                sb.append(c.getFieldName())
                        .append(':')
                        .append(c.getDataType().getName())
                        .append(':')
                        .append(c.getLength())
                        .append(';');
            }
        }

        // More stable than String.hashCode(); optional to replace with SHA-1 if needed
        return Integer.toHexString(sb.toString().hashCode());
    }

    /**
     * Return an existing identical anonymous struct/union if any.
     */
    private DataType deduplicateAnonAggregate(DataType aggregate) {
        String signature = computeAggregateSignature(aggregate);
        DataType existing = anonAggregateCache.get(signature);
        if (existing != null) {
            return existing;
        }
        anonAggregateCache.put(signature, aggregate);
        return aggregate;
    }

    private int extractMemberOffset(DebugInfoEntry die) {
        LocationDescription location = DWARF1ImportUtils.extractLocation(die, program)
                .orElseThrow(() -> new IllegalArgumentException("expected location in " + die));
        var atoms = location.getAtoms();
        if (atoms.size() == 2 && atoms.get(0).getOp() == LocationAtomOp.CONST &&
            atoms.get(1).getOp() == LocationAtomOp.ADD) {
            return atoms.get(0).getArg().intValue();
        }
        throw new IllegalArgumentException("WARNING! Unparsable member location " + atoms);
    }
}