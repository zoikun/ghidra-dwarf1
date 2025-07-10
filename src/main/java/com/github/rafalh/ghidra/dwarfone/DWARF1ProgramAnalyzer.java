package com.github.rafalh.ghidra.dwarfone;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Stack;

import com.github.rafalh.ghidra.dwarfone.model.AttributeName;
import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.RefAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.Tag;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.dwarf.sectionprovider.BaseSectionProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class DWARF1ProgramAnalyzer {
    private final Program program;
    private final TaskMonitor monitor;
    private final MessageLog log;
    private final DWARF1Program dwarfProgram;
    private final DWARF1TypeManager dwarfTypeManager;
    private final DWARF1TypeExtractor typeExtractor;
    private final DWARF1TypeImporter dwarfTypeImporter;
    private final DWARF1FunctionImporter dwarfFunctionImporter;
    private final DWARF1VariableImporter dwarfVariableImporter;

    public DWARF1ProgramAnalyzer(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
        this.program = program;
        this.monitor = monitor;
        this.log = log;
        dwarfProgram = new DWARF1Program(program, set);
        dwarfTypeManager = new DWARF1TypeManager(dwarfProgram, log);
        typeExtractor = new DWARF1TypeExtractor(dwarfProgram, log, dwarfTypeManager);
        dwarfTypeImporter = new DWARF1TypeImporter(dwarfProgram, log, dwarfTypeManager, typeExtractor);
        dwarfFunctionImporter = new DWARF1FunctionImporter(dwarfProgram, log, dwarfTypeManager, typeExtractor, monitor);
        dwarfVariableImporter = new DWARF1VariableImporter(dwarfProgram, log, typeExtractor, monitor);
        dwarfTypeManager.setTypeImporter(dwarfTypeImporter); 
    }

    public boolean process() {
        try (var sectionProvider = BaseSectionProvider.createSectionProviderFor(program, monitor)) {
            var debug = sectionProvider.getSectionAsByteProvider(DWARF1SectionNames.DEBUG, monitor);
            if (debug == null) {
                log.appendMsg("No DWARF1 debug section found.");
                return false;
            }
            processDebugSection(debug);
            return true;
        } catch (IOException e) {
            log.appendException(e);
            return false;
        }
    }

    private boolean isLittleEndian() {
        return !program.getLanguage().isBigEndian();
    }

    private void processDebugSection(ByteProvider bp) throws IOException {
        BinaryReader br = new BinaryReader(bp, isLittleEndian());
        
        Stack<DebugInfoEntry> parentStack = new Stack<>(); 
        List<DebugInfoEntry> topLevelDies = new ArrayList<>(); 

        monitor.setMaximum(bp.length());
        monitor.setMessage("Parsing DWARF1 debug section (building tree)...");

        while (br.getPointerIndex() < bp.length() && !monitor.isCancelled()) {
            long offset = br.getPointerIndex();
            monitor.setProgress(offset);

            // Determine the *current* logical parent.
            DebugInfoEntry currentParent = parentStack.isEmpty() ? null : parentStack.peek();

            // Check if we've moved past the end of the current parent's children scope,
            // often indicated by AT_sibling pointing past the current DIE.
            // If a DIE has an AT_sibling attribute, all DIEs up to that offset are its children.
            // If the current offset is equal to or past the parent's sibling attribute, pop the parent.
            if (currentParent != null) {
                Optional<RefAttributeValue> parentSiblingOpt = currentParent.<RefAttributeValue>getAttribute(AttributeName.SIBLING);
                if (parentSiblingOpt.isPresent() && offset >= parentSiblingOpt.get().get()) {
                    parentStack.pop();
                    currentParent = parentStack.isEmpty() ? null : parentStack.peek(); // Update currentParent after pop
                }
            }
            
            // Now, parse the current DIE, passing the determined currentParent.
            DebugInfoEntry die = new DebugInfoEntry(br, currentParent); 
            
            // Add the DIE to the dwarfProgram's internal map for lookups by reference.
            if (die.getTag() != Tag.NULL)  {
                dwarfProgram.addEntry(die);
            }

            // If this DIE can be a parent itself, push it onto the stack.
            // This is determined by its tag or the presence of AT_sibling, which implies it's a compound DIE.
            boolean canHaveChildren = die.getTag() == Tag.COMPILE_UNIT ||
                                      die.getTag() == Tag.GLOBAL_SUBROUTINE ||
                                      die.getTag() == Tag.SUBROUTINE ||
                                      die.getTag() == Tag.LEXICAL_BLOCK ||
                                      die.getTag() == Tag.INLINED_SUBROUTINE ||
                                      die.getTag() == Tag.CLASS_TYPE ||
                                      die.getTag() == Tag.ENUMERATION_TYPE || 
                                      die.getTag() == Tag.STRUCTURE_TYPE ||
                                      // AT_sibling indicates it's a "compound" DIE that groups others.
                                      // For DWARF1, this is a strong indicator it can have children.
                                      die.getAttribute(AttributeName.SIBLING).isPresent(); 
                                      
            if (canHaveChildren) { 
                parentStack.push(die);
            }

            // Only collect true top-level DIEs (those with no parent on the stack at creation).
            if (currentParent == null && die.getTag() != Tag.NULL) {
                topLevelDies.add(die);
            }
            
            // Safety check: if the reader didn't advance, break to prevent infinite loop.
            if (br.getPointerIndex() == offset) {
                log.appendMsg(String.format("[ERROR] DWARF parser stuck at offset 0x%X. Possible malformed data or internal error. Stopping.", offset));
                // Attempt to advance past the problematic DIE's declared length if available to recover
                long declaredEndOffset = die.getRef() + die.getLength(); 
                if (br.getPointerIndex() < declaredEndOffset) {
                    br.setPointerIndex(declaredEndOffset);
                } else {
                     break; // Cannot recover, stuck
                }
            }
        }

        // Second pass: Process only the top-level DIEs.
        monitor.setMaximum(topLevelDies.size());
        monitor.setMessage("Processing DWARF1 Top-Level Debug Info Entries...");
        for (DebugInfoEntry die : topLevelDies) {
            monitor.setProgress(topLevelDies.indexOf(die));
            processTopLevelDebugInfoEntry(die); 
        }

        dwarfVariableImporter.processDeferredVariables();   

    }
    /**
     * Processes a DebugInfoEntry, dispatching to appropriate importers or
     * recursively processing its children if it's a structural tag like
     * COMPILATION_UNIT. This method is called for top-level DIEs and
     * then recursively for their children until a specialized importer
     * takes over (e.g., DWARF1FunctionImporter for SUBROUTINEs).
     * * @param die The DebugInfoEntry to process.
     */
    private void processTopLevelDebugInfoEntry(DebugInfoEntry die) {
        try {
            switch (die.getTag()) {
                case COMPILE_UNIT:
                    for (DebugInfoEntry childDie : die.getChildren()) {
                        processTopLevelDebugInfoEntry(childDie); 
                    }
                    break;
                case GLOBAL_VARIABLE:
                    // Pass 'false' for isDeferredPass in the first call
                    dwarfVariableImporter.processVariable(die, false); 
                    break;
                case LOCAL_VARIABLE:
                    // This case is for LOCAL_VARIABLEs that are direct children of a COMPILATION_UNIT.
                    // (i.e., file-scope static variables). Function-local LOCAL_VARIABLEs are handled
                    // by DWARF1FunctionImporter.
                    if (die.getParent() == null || die.getParent().getTag() == Tag.COMPILE_UNIT) {
                        dwarfVariableImporter.processVariable(die, false);
                    }
                    break;
                case GLOBAL_SUBROUTINE:
                case SUBROUTINE:
                    dwarfFunctionImporter.processSubroutine(die); // Function importer handles its own subtree recursively
                    break;
                case CLASS_TYPE:
                case ENUMERATION_TYPE:
                case TYPEDEF:
                    dwarfTypeImporter.processTypeDebugInfoEntry(die);
                    break;
                case INLINED_SUBROUTINE:
                case LEXICAL_BLOCK:
                case FORMAL_PARAMETER: 
                    log.appendMsg("WARNING: Encountered unexpected DWARF DIE with tag " + die.getTag() + " at 0x" + Long.toHexString(die.getRef()) + " at top-level or as direct child of CU. Skipping.");
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            log.appendException(e);
            log.appendMsg("ERROR: Failed to process debug info entry " + die.getTag() + " at 0x" + Long.toHexString(die.getRef()) + ": " + e.getMessage());
        }
    }
}