package com.github.rafalh.ghidra.dwarfone;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.LocationAtomOp;
import com.github.rafalh.ghidra.dwarfone.model.LocationDescription;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace; // Import Namespace
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol; // Import Symbol
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;

public class DWARF1VariableImporter {
    private final DWARF1Program dwarfProgram;
    private final MessageLog log;
    private final DWARF1TypeExtractor typeExtractor;
    private final TaskMonitor monitor;

    // List to hold variables that couldn't be processed initially due to unresolved types
    private final List<DebugInfoEntry> deferredVariables = new ArrayList<>();

    DWARF1VariableImporter(DWARF1Program dwarfProgram, MessageLog log, DWARF1TypeExtractor typeExtractor, TaskMonitor monitor) {
        this.dwarfProgram = dwarfProgram;
        this.log = log;
        this.typeExtractor = typeExtractor;
        this.monitor = monitor;
    }

    /**
     * Processes a DWARF DIE representing a global or local variable.
     * If the variable's type cannot be resolved immediately, it's added to a
     * deferred list for a second pass.
     *
     * @param die The DebugInfoEntry for the variable.
     * @param isDeferredPass True if this is the second (deferred) pass, false otherwise.
     */
    void processVariable(DebugInfoEntry die, boolean isDeferredPass) {
        Optional<String> nameOptional = DWARF1ImportUtils.extractName(die);
        Optional<LocationDescription> locationOptional = DWARF1ImportUtils.extractLocation(die, dwarfProgram);

        if (nameOptional.isEmpty() || locationOptional.isEmpty()) {
            return;
        }

        String name = nameOptional.get();
        LocationDescription location = locationOptional.get();
        Optional<Long> offsetOpt = offsetFromLocation(location);

        if (offsetOpt.isEmpty()) {
            log.appendMsg("VarImport: Failed to extract offset from location for [" + nameOptional.get() +
                          "] with " + location.getAtoms() + (isDeferredPass ? " (deferred pass)" : ""));
            return;
        }

        long offset = offsetOpt.get();

        if (offset == 0 || offset == -1) {
            // Skip variables at offset 0 or -1 (often indicate special or invalid locations)
            return;
        }

        Address addr = dwarfProgram.toAddr(offset);
        Program program = dwarfProgram.getProgram();

        DataType dt = typeExtractor.extractDataType(die);

        // Check for unresolved types (null, default, or zero-length)
        if (dt == null || dt.getLength() <= 0 || dt == DataType.DEFAULT) {
            if (!isDeferredPass) {
                // If it's the first pass and type is not ready, defer it
                // log.appendMsg("Deferring variable " + name + " at 0x" + Long.toHexString(addr.getOffset()) +
                //               " due to unresolved or invalid data type (" + (dt == null ? "null" : dt.getName()) + ").");
                deferredVariables.add(die);
            } else {
                // If it's the deferred pass and type is STILL not ready, log as an error/warning
                // log.appendMsg("WARNING: Failed to import variable " + name + " at 0x" + Long.toHexString(addr.getOffset()) +
                //               " after deferred pass. Type remains invalid or unresolved (" + (dt == null ? "null" : dt.getName()) + ").");
            }
            return; // Always return if type is invalid/unresolved, whether deferred or not
        }
        
        int dataSize = dt.getLength();

        // Check if the address range is valid and exists in memory
        if (!program.getMemory().contains(addr, addr.add(dataSize - 1))) {
            // log.appendMsg("Skipping variable " + name + " at " + addr +
            //               " because the memory range [" + addr + " - " + addr.add(dataSize - 1) +
            //               "] is not defined in the program's memory map." + (isDeferredPass ? " (deferred pass)" : ""));
            return;
        }

        // Create symbol
        try {
            // For global variables, the namespace is typically the global namespace.
            Namespace globalNamespace = program.getGlobalNamespace(); 
            Symbol existingSymbol = program.getSymbolTable().getSymbol(name, addr, globalNamespace);

            if (existingSymbol == null) {
                program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
            } else {
                // log.appendMsg("VariableImporter: Symbol '" + name + "' already exists at " + addr + ". Skipping symbol creation.");
            }
        } catch (InvalidInputException e) {
            log.appendException(e);
            log.appendMsg("Failed to create symbol for " + name + " at " + addr + ": " + e.getMessage());
        }

        // Set data type
        try {
            // Always clear the area before trying to create data to avoid CodeUnitInsertionException
            program.getListing().clearCodeUnits(addr, addr.add(dataSize - 1), false);
            program.getListing().createData(addr, dt);
        } catch (CodeUnitInsertionException e) {
            log.appendException(e);
            log.appendMsg("Failed to create data for " + name + " at " + addr + " with type " + dt.getName() +
                          " (length: " + dataSize + " bytes): " + e.getMessage());
        }
    }
    
    // Public method to be called by DWARF1ProgramAnalyzer for the second pass
    public void processDeferredVariables() {
        if (deferredVariables.isEmpty()) {
            return;
        }
        monitor.setMessage("Processing deferred variables...");
        monitor.setMaximum(deferredVariables.size());
        log.appendMsg("Attempting to process " + deferredVariables.size() + " deferred variables...");
        for (DebugInfoEntry die : deferredVariables) {
            monitor.setProgress(deferredVariables.indexOf(die));
            processVariable(die, true); 
        }
        deferredVariables.clear(); // Clear the list after attempting to process all
    }


    private Optional<Long> offsetFromLocation(LocationDescription location) {
        var locationAtoms = location.getAtoms();
        if (locationAtoms.size() == 1 && locationAtoms.get(0).getOp() == LocationAtomOp.ADDR) {
            return Optional.of(locationAtoms.get(0).getArg());
        }
        if (!locationAtoms.isEmpty()) {
            log.appendMsg("WARNING! Unhandled DWARF1 location operation '" + locationAtoms.get(0).getOp() +
                          "' for variable. Full location: " + locationAtoms);
        }
        return Optional.empty();
    }
}