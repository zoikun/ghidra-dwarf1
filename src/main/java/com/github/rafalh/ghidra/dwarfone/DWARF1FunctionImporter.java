package com.github.rafalh.ghidra.dwarfone;

import java.util.*;

import com.github.rafalh.ghidra.dwarfone.model.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.util.bin.format.dwarf.DWARFRegisterMappings;
import ghidra.app.util.bin.format.dwarf.DWARFRegisterMappingsManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.Varnode; // Added import for Varnode
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.CommentType;

public class DWARF1FunctionImporter {

    private static final Map<String, String> OPERATORS = Map.ofEntries(
            Map.entry("__pl", "+"),
            Map.entry("__apl", "+="),
            Map.entry("__mi", "-"),
            Map.entry("__ami", "-="),
            Map.entry("__ml", "*"),
            Map.entry("__amu", "*="),
            Map.entry("__dv", "/"),
            Map.entry("__adv", "/="),
            Map.entry("__as", "="),
            Map.entry("__pp", "++"),
            Map.entry("__lt", "<"),
            Map.entry("__gt", ">"),
            Map.entry("__le", "<="),
            Map.entry("__ge", ">="),
            Map.entry("__eq", "=="),
            Map.entry("__ne", "!="),
            Map.entry("__ls", "<<"),
            Map.entry("__als", "<<="),
            Map.entry("__rs", ">>"),
            Map.entry("__ars", ">>="),
            Map.entry("__er", "^"),
            Map.entry("__aer", "^="),
            Map.entry("__vc", "[]"),
            Map.entry("__cl", "()"),
            Map.entry("__nw", "new"),
            Map.entry("__nwa", "new[]"),
            Map.entry("__dl", "delete"),
            Map.entry("__dla", "delete[]")
    );
    private static final String CONSTRUCTOR = "__ct";
    private static final String DESTRUCTOR = "__dt";

    private final DWARF1Program dwarfProgram;
    private final MessageLog log;
    private final DWARF1TypeManager dwarfTypeManager;
    private final DWARF1TypeExtractor typeExtractor;
    private final FunctionManager functionManager;
    private final TaskMonitor monitor;
    private final DecompInterface dif;
    private DWARFRegisterMappings dwarfRegisterMappings;

    DWARF1FunctionImporter(DWARF1Program dwarfProgram, MessageLog log, DWARF1TypeManager dwarfTypeManager,
                           DWARF1TypeExtractor typeExtractor, TaskMonitor monitor) {
        this.dwarfProgram = dwarfProgram;
        this.log = log;
        this.dwarfTypeManager = dwarfTypeManager;
        this.typeExtractor = typeExtractor;
        this.monitor = monitor;
        functionManager = dwarfProgram.getProgram().getFunctionManager();
        dif = new DecompInterface();
        dif.openProgram(dwarfProgram.getProgram());

        Language currentLanguage = dwarfProgram.getProgram().getLanguage();

        try {
            if (DWARFRegisterMappingsManager.hasDWARFRegisterMapping(currentLanguage)) {
                dwarfRegisterMappings = DWARFRegisterMappingsManager.getMappingForLang(currentLanguage);
                // log.appendMsg("Loaded DWARF register mappings for language: " + currentLanguage.getLanguageID().getIdAsString());
            } else {
                // log.appendMsg("WARNING: No DWARF register mappings found for language: " + currentLanguage.getLanguageID().getIdAsString() + ". Register names might not be correctly resolved.");
            }
        } catch (Exception e) {
            log.appendException(e);
            log.appendMsg("ERROR: Failed to load DWARF register mappings for language " +
                            currentLanguage.getLanguageID().getIdAsString() + ": " + e.getMessage());
        }
    }

    void processSubroutine(DebugInfoEntry die) {
        Optional<String> nameOptional = DWARF1ImportUtils.extractName(die);
        Optional<AddrAttributeValue> lowPcAttributeOptional = die.getAttribute(AttributeName.LOW_PC);
        Optional<AddrAttributeValue> highPcAttributeOptional = die.getAttribute(AttributeName.HIGH_PC);

        if (nameOptional.isEmpty() || lowPcAttributeOptional.isEmpty() || highPcAttributeOptional.isEmpty()) {
            return;
        }

        String name = nameOptional.get();
        long lowPc = lowPcAttributeOptional.get().get();
        if (lowPc == 0xFFFFFFFFL) {
            return;
        }
        long highPc = highPcAttributeOptional.get().get();
        DataType returnDt = typeExtractor.extractDataType(die);

        String op = OPERATORS.get(name);
        if (op != null) {
            String sep = Character.isLetter(op.charAt(0)) ? "_" : "";
            name = "operator" + sep + op;
        }
        if (name.startsWith("__op")) {
            name = "operator_" + returnDt.toString().replace(' ', '_');
        }

        Optional<DataType> classDtOpt = determineMemberClassType(die);
        if (classDtOpt.isPresent() && !name.contains(classDtOpt.get().getName())) {
            String className = classDtOpt.get().getName();
            if (name.equals(CONSTRUCTOR)) {
                name = className;
            } else if (name.equals(DESTRUCTOR)) {
                name = "~" + className;
            }
            name = className + "::" + name;
        }

        Address minAddr = dwarfProgram.toAddr(lowPc);
        Address maxAddr = dwarfProgram.toAddr(highPc - 1);
        AddressSetView funBody = dwarfProgram.getProgram().getAddressFactory().getAddressSet(minAddr, maxAddr);
        Iterator<Function> overlappingFunIt = functionManager.getFunctionsOverlapping(funBody);
        while (overlappingFunIt.hasNext()) {
            Function overlappingFun = overlappingFunIt.next();
            if (!overlappingFun.getEntryPoint().equals(minAddr)) {
                log.appendMsg("Removing overlapping function: " + overlappingFun.getName());
                functionManager.removeFunction(overlappingFun.getEntryPoint());
            }
        }
        Function fun = functionManager.getFunctionAt(minAddr);
        try {
            if (fun == null) {
                fun = functionManager.createFunction(name, minAddr, funBody, SourceType.IMPORTED);
            } else {
                fun.setName(name.replaceAll("\\s", ""), SourceType.IMPORTED);
                fun.setBody(funBody);
            }

            Variable returnParam = new ReturnParameterImpl(returnDt, dwarfProgram.getProgram());
            List<Variable> params = new ArrayList<>();
            Map<Register, Variable> regVariables = new HashMap<>();

            for (DebugInfoEntry childDie : die.getChildren()) {
                switch (childDie.getTag()) {
                    case FORMAL_PARAMETER:
                        String paramName = DWARF1ImportUtils.extractName(childDie).orElse(null);
                        DataType dt = typeExtractor.extractDataType(childDie);
                        params.add(new ParameterImpl(paramName, dt, dwarfProgram.getProgram()));
                        break;
                    case LOCAL_VARIABLE:
                        importLocalVariables(childDie, fun, regVariables, false);
                        break;
                    case LEXICAL_BLOCK:
                        addComment(childDie, "scope {", true);
                        handleNestedBlock(childDie, fun, regVariables, false);
                        addComment(childDie, "scope }", false);
                        break;
                    case INLINED_SUBROUTINE:
                        Optional<String> inlineNameOptional = extractInlineName(childDie);
                        inlineNameOptional.ifPresent(s -> addComment(childDie, s + " {", true));
                        handleNestedBlock(childDie, fun, regVariables, true);
                        inlineNameOptional.ifPresent(s -> addComment(childDie, s + " }", false));
                        break;
                    default:
                        // Ignore other tags
                        break;
                }
            }

            fun.updateFunction(null, returnParam, params, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true,
                    SourceType.IMPORTED);

            HighFunction highFunc = dif.decompileFunction(fun, 180, monitor).getHighFunction();

            if (highFunc == null) {
                log.appendMsg("WARNING: Decompilation failed for function " + fun.getName() + " at " + fun.getEntryPoint() + ". Skipping HighFunction symbol mapping for local variables.");
            } else {
                for (Iterator<HighSymbol> it = highFunc.getLocalSymbolMap().getSymbols(); it.hasNext(); ) {
                    HighSymbol sym = it.next();
                    VariableStorage storage = sym.getStorage();

                    if (storage.isRegisterStorage()) {
                        var v = regVariables.get(storage.getRegister());
                        if (v != null) {
                            try {
                                HighFunctionDBUtil.updateDBVariable(sym, v.getName(), v.getDataType(), SourceType.IMPORTED);
                            } catch (DuplicateNameException e) {
                                // log.appendMsg("Skipping HighFunction local variable remapping for '" + v.getName() +
                                //               "' in function '" + fun.getName() + "' at " + fun.getEntryPoint() +
                                //               " due to: " + e.getMessage());
                            } catch (InvalidInputException e) {
                                log.appendMsg("ERROR: Invalid input when remapping HighFunction local variable '" + v.getName() +
                                        "' in function '" + fun.getName() + "' at " + fun.getEntryPoint() +
                                        ": " + e.getMessage());
                            }
                        }
                    }
                }
            }

        } catch (DuplicateNameException | InvalidInputException | OverlappingFunctionException e) {
            log.appendException(e);
            log.appendMsg("Failed to import function " + name + " at " + minAddr + ": " + e.getMessage());
        }
    }

    private void handleNestedBlock(DebugInfoEntry die, Function fun, Map<Register, Variable> regVariables, boolean inlined)
            throws InvalidInputException, DuplicateNameException {
        for (DebugInfoEntry childDie : die.getChildren()) {
            switch (childDie.getTag()) {
                case LOCAL_VARIABLE:
                    importLocalVariables(childDie, fun, regVariables, inlined);
                    break;
                case LEXICAL_BLOCK:
                    addComment(childDie, "scope {", true);
                    handleNestedBlock(childDie, fun, regVariables, inlined);
                    addComment(childDie, "scope }", false);
                    break;
                case INLINED_SUBROUTINE:
                    Optional<String> inlineNameOptional = extractInlineName(childDie);
                    inlineNameOptional.ifPresent(s -> addComment(childDie, s + " {", true));
                    handleNestedBlock(childDie, fun, regVariables, true);
                    inlineNameOptional.ifPresent(s -> addComment(childDie, s + " }", false));
                    break;
                default:
                    // Ignore other tags
                    break;
            }
        }
    }

    private void importLocalVariables(DebugInfoEntry die, Function fun, Map<Register, Variable> regVariables,
                                      boolean inlined) {
        Optional<String> varNameOptional = DWARF1ImportUtils.extractName(die);
        Optional<LocationDescription> locationOptional =
                DWARF1ImportUtils.extractLocation(die, dwarfProgram);
        if (varNameOptional.isEmpty() || locationOptional.isEmpty()) {
            return;
        }
        String varName = varNameOptional.get();
        if (inlined) {
            varName = "inlined_" + varName;
        }
        LocationDescription varLocation = locationOptional.get();
        DataType varDt = typeExtractor.extractDataType(die);
        List<LocationAtom> atoms = varLocation.getAtoms();
        if (atoms.isEmpty()) {
            return;
        }

        try {
            switch (atoms.get(0).getOp()) {
                case REG, FPREG, FPDREG -> {
                    int dwarfRegNum = atoms.get(0).getArg().intValue();
                    Register reg = null;

                    if (dwarfRegisterMappings != null) {
                        reg = dwarfRegisterMappings.getGhidraReg(dwarfRegNum);
                    }

                    if (reg == null) {
                        log.appendMsg("WARNING: Could not find Ghidra register for DWARF register number " + dwarfRegNum + " for variable '" + varName + "' in function '" + fun.getName() + "'. Skipping variable.");
                        break;
                    }

                    // Use the data type's length directly for the Varnode
                    int dataTypeLength = varDt.getLength();

                    // Defensive check: Ensure the data type has a valid length
                    if (dataTypeLength <= 0) {
                        log.appendMsg("WARNING: Invalid data type length (" + dataTypeLength + ") for variable '" + varName + "' in function '" + fun.getName() + "'. Skipping variable.");
                        break;
                    }
                    
                    // Create the Varnode with the register's address and the data type's length.
                    // This is our primary attempt to match storage to data type.
                    Varnode varnode = new Varnode(reg.getAddress(), dataTypeLength);
                    VariableStorage storage = new VariableStorage(dwarfProgram.getProgram(), varnode);

                    try {
                        Variable var = new LocalVariableImpl(varName, 0, varDt, storage, false, dwarfProgram.getProgram(),
                            SourceType.IMPORTED);
                            regVariables.put(reg, var);
                    }
                    catch (InvalidInputException e) {
                        // log.appendMsg("Failed to create local variable '" + varName + "' for function '" + fun.getName() +
                        //         "' due to invalid input during construction: " + e.getMessage());
                        // break;
                    } 
                    catch (Exception e) { // Catch any other unexpected exceptions during variable creation
                        log.appendException(e);
                        log.appendMsg("ERROR: Unexpected error creating local variable '" + varName + "' for function '" + fun.getName() +
                            "': " + e.getMessage());
                        break;
                    }

                }
                case BASEREG -> {
                    if (atoms.size() == 3 && atoms.get(1).getOp() == LocationAtomOp.CONST &&
                            atoms.get(2).getOp() == LocationAtomOp.ADD) {
                        int stackOffset = atoms.get(1).getArg().intValue();
                        try {
                            Variable var =
                                    new LocalVariableImpl(varName, varDt, stackOffset,
                                            dwarfProgram.getProgram(),
                                            SourceType.IMPORTED);

                            fun.addLocalVariable(var, SourceType.IMPORTED);
                        } catch (DuplicateNameException e) {
                            // log.appendMsg("Skipping local variable (BASEREG)'" + varName + "' in function '" + fun.getName() +
                            //               "' at " + fun.getEntryPoint() + ": " + e.getMessage());
                        }
                    } else {
                        // log.appendMsg("WARNING: Unhandled complex BASEREG location for variable '" + varName +
                        //         "' in function '" + fun.getName() + "' at " + fun.getEntryPoint() + ": " + atoms);
                    }
                }
                case ADDR -> { // Case for absolute memory addresses
                    Address address = dwarfProgram.toAddr(atoms.get(0).getArg().longValue());
                    VariableStorage storage = new VariableStorage(dwarfProgram.getProgram(), address, varDt.getLength());

                    Variable var = new LocalVariableImpl(varName, 0, varDt, storage, false, dwarfProgram.getProgram(), SourceType.IMPORTED);
                    try {
                        fun.addLocalVariable(var, SourceType.IMPORTED);
                    } catch (DuplicateNameException e) {
                        // log.appendMsg("Skipping local variable (ADDR) '" + varName + "' in function '" + fun.getName() +
                        //               "' at " + fun.getEntryPoint() + ": " + e.getMessage());
                    }
                }
                default -> {
                    log.appendMsg("WARNING: Unhandled DWARF location operation '" + atoms.get(0).getOp() +
                                    "' for variable '" + varName + "' in function '" + fun.getName() +
                                    "' at " + fun.getEntryPoint() + ". Full location: " + atoms);
                    break;
                }
            }
        } catch (InvalidInputException e) {
            log.appendException(e);
            log.appendMsg("Failed to create local variable '" + varName + "' for function '" + fun.getName() +
                            "' due to invalid input during construction: " + e.getMessage());
        }
    }

    private Optional<String> extractInlineName(DebugInfoEntry die) {
        Optional<DebugInfoEntry> inline = die.<RefAttributeValue>getAttribute(AttributeName.ABSTRACT_ORIGIN)
                .map(RefAttributeValue::get).flatMap(dwarfProgram::getDebugInfoEntry);
        return inline.flatMap(DWARF1ImportUtils::extractName);
    }

    private Optional<DataType> determineMemberClassType(DebugInfoEntry die) {
        // Function defined in class body
        if (die.getParent().getTag() == Tag.CLASS_TYPE) {
            return Optional.of(dwarfTypeManager.getUserDataType(die.getParent().getRef()));
        }
        // Function defined outside of the class body should have AT_member attribute
        Optional<RefAttributeValue> memberAttributeOptional = die.getAttribute(AttributeName.MEMBER);
        if (memberAttributeOptional.isPresent()) {
            return Optional.of(dwarfTypeManager.getUserDataType(memberAttributeOptional.get().get()));
        }
        // Determine the class based on the "this" parameter because for some compilers (e.g. PS2) normal
        // ways does not work...
        for (DebugInfoEntry childDie : die.getChildren()) {
            if (childDie.getTag() == Tag.FORMAL_PARAMETER &&
                    Optional.of("this").equals(DWARF1ImportUtils.extractName(childDie))) {
                DataType dt = typeExtractor.extractDataType(childDie);
                if (dt instanceof Pointer) {
                    dt = ((Pointer) dt).getDataType();
                }
                return Optional.of(dt);
            }
        }
        return Optional.empty();
    }

    private void addComment(DebugInfoEntry die, String comment, boolean beginning) {
        if (beginning) {
            Optional<AddrAttributeValue> lowPcAttributeOptional = die.getAttribute(AttributeName.LOW_PC);
            if (lowPcAttributeOptional.isEmpty()) {
                return;
            }
            long lowPc = lowPcAttributeOptional.get().get();
            if (lowPc == 0xFFFFFFFFL) {
                return;
            }
            Address minAddr = dwarfProgram.toAddr(lowPc);
            addCommentAtAddress(minAddr, comment);
        } else {
            Optional<AddrAttributeValue> highPcAttributeOptional = die.getAttribute(AttributeName.HIGH_PC);

            if (highPcAttributeOptional.isEmpty()) {
                return;
            }
            long highPc = highPcAttributeOptional.get().get();
            Address maxAddr = dwarfProgram.toAddr(highPc - 4); // Substract 4 to set at last instruction
            addCommentAtAddress(maxAddr, comment);
        }
    }

    private void addCommentAtAddress(Address addr, String comment) {
        Listing listing = dwarfProgram.getProgram().getListing();
    String existing = listing.getComment(CommentType.PRE, addr);
        if (existing != null) {
            comment = existing + "\n" + comment;
        }
        listing.setComment(addr, CommentType.PRE, comment);
    }
}