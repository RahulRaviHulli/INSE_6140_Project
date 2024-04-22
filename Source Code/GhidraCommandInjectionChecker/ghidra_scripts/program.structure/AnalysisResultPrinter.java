package program.structure;

import java.math.BigInteger;
import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.VarnodeContext;


/**
 * Provides utility functions for printing traces and analysis results related to function calls,
 * parameter locations, and potential vulnerabilities identified during static analysis.
 */
public class AnalysisResultPrinter {

	 /**
     * Prints the mappings of functions to the addresses from which they are called.
     */
	public static void printSymbols() {
		if(!ProgramGraphBuilder.callerToSystemFunctionMap.isEmpty()) {
			for(Function func : ProgramGraphBuilder.callerToSystemFunctionMap.keySet()) {
				for(Address caller : ProgramGraphBuilder.callerToSystemFunctionMap.get(func)) {
					System.out.printf("[System Function]: %s at %s called from %s\n", func.getName(), func.getEntryPoint(), caller.toString());
				}
			}
		}
	}
	
	/**
     * Prints details about a specific call within the tracked storage context.
     *
     * @param context The Varnode context for interpreting register names.
     * @param storage The storage tracking the analysis state.
     */
	public static void printTrackedCallDetails(VarnodeContext context, AnalysisTrackStorage storage) {
		System.out.printf("[TRACKED]: Called function %s @ %s\n\n", storage.getFunc().getName(), storage.getCall().toString());
			for(String called : storage.getCalledFuncs()) {
				System.out.printf("|---[VULNERABLE FUNCTION CALL]: %s\n", called);
			}
			System.out.println();
			for(String origin : storage.getOriginFuncs()) {
				System.out.printf("|---[POSSIBLE ORIGIN FUNCTION]: %s()\n", origin);
			}
			for(Varnode node : storage.getNodes()) {
				if(node.isRegister()) {
					System.out.printf("|---[PARAMETER LOCATION]: %s\n", context.getRegister(node).getName());
				} else {
					System.out.printf("|---[PARAMETER LOCATION]: %s\n", node.getAddress().toString());
				}
			}
			for(MemoryPosition pos : storage.getMemoryPosition()) {
				String offset = pos.getOffset().getAddress().toString().replaceFirst("^const:", "");
				long off = new BigInteger(offset, 16).longValue();
				System.out.printf("|---[MEMORY LOCATION]: %s + %s\n", context.getRegister(pos.getRegister()).getName(), off);
			}
			System.out.println();
	}
	
	/**
     * Prints a trace of the analysis, highlighting the depth level and tracked nodes and memory positions.
     *
     * @param storage The storage tracking the analysis state.
     * @param context The Varnode context for interpreting register names.
     * @param depthLevel The current depth level in the trace.
     * @param groups The groups of instructions being analyzed.
     * @param index The current instruction index within the groups.
     */
	public static void printAnalysisTrace(AnalysisTrackStorage storage, VarnodeContext context, int depthLevel, ArrayList<EnhancedInstructionDetails> groups, int i) {
		System.out.printf("Depthlevel: %d, Compound: %d\n\n", depthLevel, groups.size() - (i + 1));
		for(Varnode node : storage.getNodes()) {
			if(node.isRegister()) {
				System.out.printf("Tracked Node: %s\n", context.getRegister(node).getName());
			} else {
				System.out.printf("Tracked Node: %s\n", node.toString());
			}
		}
		for(MemoryPosition pos : storage.getMemoryPosition()) {
			String offset = pos.getOffset().getAddress().toString().replaceFirst("^const:", "");
			System.out.printf("Tracked MemoryPosition: %s + %s\n", context.getRegister(pos.getRegister()).getName(), new BigInteger(offset, 16).longValue());
		}
		System.out.println();
	}


	/**
     * Prints the final analysis results, indicating potential vulnerabilities or safety based on the tracking storage.
     *
     * @param finalResultscomes The list of final tracking storages from the analysis.
     * @param context The Varnode context for interpreting register names.
     */
	public static void printFinalAnalysisResults(ArrayList<AnalysisTrackStorage> finalResults, VarnodeContext context) {
		if (finalResults.isEmpty()) {
		System.out.println("#########################################################################");
        System.out.println("No vulnerable functions found. Manual checks recommended.");
		System.out.println("#########################################################################");
        return;
    	}
		for(AnalysisTrackStorage storage : finalResults) {
			System.out.println("#########################################################################");
			printTrackedCallDetails(context, storage);
			if(!ProgramAnalysisUtilities.trackerIsConstant(storage)) {
				System.out.println("\n[RESULT]: System call is possibly vulnerable. Manual checks recommended.\n");
			} else {
				System.out.println("\n[RESULT]: System call is possibly safe. Manual checks recommended.\n");
			}
		}
		System.out.println("#########################################################################");
	}
}
