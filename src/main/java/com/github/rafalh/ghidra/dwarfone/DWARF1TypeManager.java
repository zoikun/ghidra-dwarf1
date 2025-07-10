package com.github.rafalh.ghidra.dwarfone;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.FundamentalType;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.*; // Import all necessary Ghidra data types

public class DWARF1TypeManager {

    private final DWARF1Program dwarfProgram; // Renamed for clarity with getProgram()
    private final MessageLog log;
    private DWARF1TypeImporter dwarfTypeImporter;

    private final Map<Long, DataType> userDataTypeMap = new HashMap<>();

    public DWARF1TypeManager(DWARF1Program program, MessageLog log) {
        this.dwarfProgram = program; // Assign to dwarfProgram
        this.log = log;
    }

    public DataType getUserDataType(long ref) {
        var cachedDtOpt = Optional.ofNullable(userDataTypeMap.get(ref));
        if (cachedDtOpt.isPresent()) {
            return cachedDtOpt.get();
        }
        try {
            DebugInfoEntry die = dwarfProgram.getDebugInfoEntry(ref) // Use dwarfProgram here
                    .orElseThrow(() -> new IllegalArgumentException("Cannot find DIE for reference " + ref));
            return dwarfTypeImporter.processTypeDebugInfoEntry(die);
        } catch (Exception e) {
            log.appendMsg("Failed to resolve type reference: " + ref);
            log.appendException(e);
            return DataType.DEFAULT;
        }
    }

    public DataType convertFundamentalTypeToDataType(FundamentalType ft) {
        // Use BuiltInDataTypeManager for retrieving core built-in types
        DataTypeManager builtInDataTypeManager = BuiltInDataTypeManager.getDataTypeManager();
        // Use the program's DataTypeManager for adding new, custom types
        DataTypeManager programDataTypeManager = dwarfProgram.getProgram().getDataTypeManager();
        
        // Define a custom category path for MWCC-specific types if needed
        CategoryPath mwccCategoryPath = new CategoryPath("/MWCC_Types");

        switch (ft) {
            case CHAR:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "char");
            case SIGNED_CHAR:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "schar");
            case UNSIGNED_CHAR:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "uchar");
            case SHORT:
            case SIGNED_SHORT:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "short");
            case UNSIGNED_SHORT:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "ushort");
            case INTEGER:
            case SIGNED_INTEGER:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "int");
            case UNSIGNED_INTEGER:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "uint");
            case LONG:
            case SIGNED_LONG:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "long");
            case UNSIGNED_LONG:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "ulong");
            case LONG_LONG:
            case SIGNED_LONG_LONG:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "longlong");
            case UNSIGNED_LONG_LONG:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "ulonglong");
            case POINTER:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "pointer");
            case FLOAT:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "float");
            case DBL_PREC_FLOAT:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "double");
            case EXT_PREC_FLOAT:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "longdouble");
            case VOID:
                return VoidDataType.dataType;
            case BOOLEAN:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "bool");

            // --- MWCC Specific Fundamental Types (Revised Mappings) ---
            case INT8:
            case SIGNED_INT8:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "schar");
            case UNSIGNED_INT8:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "uchar");
            case INT16:
            case SIGNED_INT16:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "short");
            case UNSIGNED_INT16:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "ushort");
            case INT32:
            case SIGNED_INT32:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "int");
            case UNSIGNED_INT32:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "uint");
            case INT64:
            case SIGNED_INT64:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "longlong");
            case UNSIGNED_INT64:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "ulonglong");
            case REAL32:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "float");
            case REAL64:
                return builtInDataTypeManager.getDataType(CategoryPath.ROOT, "double");
            case REAL96:
                // log.appendMsg("Mapping MWCC REAL96 (12 bytes) to byte[12].");
                return programDataTypeManager.addDataType(new ArrayDataType(ByteDataType.dataType, 12, 1, builtInDataTypeManager), DataTypeConflictHandler.REPLACE_HANDLER);
            case REAL128:
                // log.appendMsg("Mapping MWCC REAL128 (16 bytes) to byte[16].");
                return programDataTypeManager.addDataType(new ArrayDataType(ByteDataType.dataType, 16, 1, builtInDataTypeManager), DataTypeConflictHandler.REPLACE_HANDLER);
            case FIXED_VECTOR_8x8:
                // log.appendMsg("Mapping MWCC FIXED_VECTOR_8x8 (8 bytes) to byte[8].");
                return programDataTypeManager.addDataType(new ArrayDataType(ByteDataType.dataType, 8, 1, builtInDataTypeManager), DataTypeConflictHandler.REPLACE_HANDLER);
            case LONG128:
                // log.appendMsg("Mapping MWCC LONG128 (16 bytes) to byte[16].");
                return programDataTypeManager.addDataType(new ArrayDataType(ByteDataType.dataType, 16, 1, builtInDataTypeManager), DataTypeConflictHandler.REPLACE_HANDLER);
            case SIGNED_INT_16x8:
                // log.appendMsg("Mapping MWCC SIGNED_INT_16x8 (16 bytes) to schar[16].");
                return programDataTypeManager.addDataType(new ArrayDataType(builtInDataTypeManager.getDataType(CategoryPath.ROOT, "schar"), 16, 1, builtInDataTypeManager), DataTypeConflictHandler.REPLACE_HANDLER);
            case SIGNED_INT_8x16:
                // log.appendMsg("Mapping MWCC SIGNED_INT_8x16 (16 bytes) to short[8].");
                return programDataTypeManager.addDataType(new ArrayDataType(builtInDataTypeManager.getDataType(CategoryPath.ROOT, "short"), 8, 2, builtInDataTypeManager), DataTypeConflictHandler.REPLACE_HANDLER);
            case SIGNED_INT_4x32:
                // log.appendMsg("Mapping MWCC SIGNED_INT_4x32 (16 bytes) to int[4].");
                return programDataTypeManager.addDataType(new ArrayDataType(builtInDataTypeManager.getDataType(CategoryPath.ROOT, "int"), 4, 4, builtInDataTypeManager), DataTypeConflictHandler.REPLACE_HANDLER);
            case UNSIGNED_INT_16x8:
                // log.appendMsg("Mapping MWCC UNSIGNED_INT_16x8 (16 bytes) to uchar[16].");
                return programDataTypeManager.addDataType(new ArrayDataType(builtInDataTypeManager.getDataType(CategoryPath.ROOT, "uchar"), 16, 1, builtInDataTypeManager), DataTypeConflictHandler.REPLACE_HANDLER);
            case UNSIGNED_INT_8x16:
                // log.appendMsg("Mapping MWCC UNSIGNED_INT_8x16 (16 bytes) to ushort[8].");
                return programDataTypeManager.addDataType(new ArrayDataType(builtInDataTypeManager.getDataType(CategoryPath.ROOT, "ushort"), 8, 2, builtInDataTypeManager), DataTypeConflictHandler.REPLACE_HANDLER);
            case UNSIGNED_INT_4x32:
                // log.appendMsg("Mapping MWCC UNSIGNED_INT_4x32 (16 bytes) to uint[4].");
                return programDataTypeManager.addDataType(new ArrayDataType(builtInDataTypeManager.getDataType(CategoryPath.ROOT, "uint"), 4, 4, builtInDataTypeManager), DataTypeConflictHandler.REPLACE_HANDLER);
            case GekkoPairedSingle:
                // log.appendMsg("Mapping MWCC GekkoPairedSingle (8 bytes) to custom struct.");
                StructureDataType gekkoPairedSingle = new StructureDataType(mwccCategoryPath, "GekkoPairedSingle", 0, builtInDataTypeManager);
                gekkoPairedSingle.add(builtInDataTypeManager.getDataType(CategoryPath.ROOT, "float"), "x", null);
                gekkoPairedSingle.add(builtInDataTypeManager.getDataType(CategoryPath.ROOT, "float"), "y", null);
                return programDataTypeManager.addDataType(gekkoPairedSingle, DataTypeConflictHandler.REPLACE_HANDLER);

            case USER:
                log.appendMsg("Unknown or unhandled fundamental type: " + ft + ")");
                return DataType.DEFAULT;
            default:
                log.appendMsg("Unknown or unhandled fundamental type: " + ft + ")");
                return DataType.DEFAULT;
        }
    }

    public void registerType(long ref, DataType dt) {
        userDataTypeMap.put(ref, dt);
    }

    public void setTypeImporter(DWARF1TypeImporter dwarfTypeImporter) {
        this.dwarfTypeImporter = dwarfTypeImporter;
    }
}