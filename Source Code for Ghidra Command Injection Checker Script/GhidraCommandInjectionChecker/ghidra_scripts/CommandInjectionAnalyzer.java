//
//@author Rakshith Raj Gurupura Puttaraju, Rahul Ravi Hulli and Mustafa Talha Ucar
//@category 
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.VarnodeContext;

import program.structure.*;

public class CommandInjectionAnalyzer extends GhidraScript {
	
	// Functions that may imply vulnerable input to the system calls
	private HashMap<String, Integer> vulnerableFunctions = new HashMap<String, Integer>() {{
        put("strcat", 1);
        put("strncat", 1);
        put("sprintf", 2);
        put("snprintf", 3);
        put("memcpy", 1);
    }};
	
	// Functions that check for characters and may imply a safe system call
	private List<String> checkCharFunctions = new ArrayList<String> () {{
		add("strchr");
		add("strrchr");
		add("regcomp");
		add("regexec");
	}};	


	private List<String> inputFunctions = List.of("scanf", "__isoc99_scanf");
    private List<String> characterCheckFunctions = List.of("strchr", "strrchr", "regcomp", "regexec");
    private List<String> binaryOperations = List.of(
        "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL",
        "INT_SLESSEQUAL", "INT_ADD", "INT_SUB", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
        "INT_XOR", "INT_AND", "INT_OR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
        "INT_MULT", "INT_DIV", "INT_REM", "INT_SDIV", "INT_SREM");
    private List<String> casts = List.of(
        "INT_NEGATE", "INT_ZEXT", "INT_SEXT", "TRUNC", "INT2FLOAT", "CAST");
    private List<String> stackOperations = List.of("PUSH", "POP");
	
	
	ArrayList<AnalysisTrackStorage> traceResults= new ArrayList<AnalysisTrackStorage>();
	ArrayList<AnalysisTrackStorage> finalResults = new ArrayList<AnalysisTrackStorage>();
	ArrayList<Register> parameterRegister = new ArrayList<Register>();

	private String cpuArchitecture;
    private Register stackPointer, framePointer, returnRegister;
    private AddressFactory addressFactory;
    private Program program;
    private FunctionManager funcMan;
    private VarnodeContext context;
	
	@Override
	protected void run() throws Exception {
		program = currentProgram;
		funcMan = program.getFunctionManager();
		SimpleBlockModel simpleBm = new SimpleBlockModel(program);
		SymbolTable symTab = program.getSymbolTable();
		Listing listing = program.getListing();
		context = new VarnodeContext(program, program.getProgramContext(), program.getProgramContext());
		ProgramGraphBuilder.callerToSystemFunctionMap = new HashMap<Function, ArrayList<Address>>();
		
		
		cpuArchitecture = ProgramAnalysisUtilities.getcpuArchitecture(program);
		stackPointer = program.getCompilerSpec().getStackPointer();
		framePointer = ProgramAnalysisUtilities.getFramePointer(cpuArchitecture, context);
		returnRegister = ProgramAnalysisUtilities.getReturnRegister(cpuArchitecture, context);
		parameterRegister = ProgramAnalysisUtilities.getParameterRegister(cpuArchitecture, context);
		addressFactory = program.getAddressFactory();

		BasicBlockGraph graph = ProgramGraphBuilder.buildBlockGraph(funcMan, simpleBm, listing, context, getMonitor());
		ProgramGraphBuilder.mapCallerToSystemFunctions(symTab, funcMan);
		finalResults = findSourceOfSystemCallInput(graph);
		AnalysisResultPrinter.printFinalAnalysisResults(finalResults, context);
	}

	
	
	
	/** 
	 * @param blockGraph
	 * @return ArrayList<AnalysisTrackStorage>
	 * 
	 * Iterates over each system call and address at which it the function was called.
	 * In each iteration, a trace to the origin is generated and the tracked values are returned.
	 * 
	 */
	protected ArrayList<AnalysisTrackStorage> findSourceOfSystemCallInput(BasicBlockGraph blockGraph) {
		ArrayList<AnalysisTrackStorage> output = new ArrayList<AnalysisTrackStorage>();
		for(Function sysFunc : ProgramGraphBuilder.callerToSystemFunctionMap.keySet()) {
			for(Address callAddr : ProgramGraphBuilder.callerToSystemFunctionMap.get(sysFunc)) {
				ArrayList<Varnode> params = ProgramAnalysisUtilities.getFunctionParameters(sysFunc, context);
				ArrayList<MemoryPosition> stackArgs = ProgramAnalysisUtilities.getStackArgs(stackPointer, addressFactory, params, context);
				// params contains stack arguments as Stack Varnodes which are removed in favour of using stackpointer + offset notation
			    params = ProgramAnalysisUtilities.removeStackNodes(params);
				AnalysisTrackStorage storage = new AnalysisTrackStorage(sysFunc, callAddr, params, stackArgs);
				BasicBlock startBlock = blockGraph.getBlockByAddress(callAddr);
				buildTraceToProgramStart(storage, 0, blockGraph, startBlock);
				output.add(mergeTrackerForSystemCall());
			}
		}
		
		return output;
	}
	
	
	
	
	/** 
	 * @param storage
	 * @param depthLevel
	 * @param graph
	 * @param block
	 * 
	 * Basic blocks, starting from the system call block, are recursively iterated backwards to find the origin
	 * If the tracked values are all constant, the iteration is stopped.
	 * For multiple tracked paths, the tracked values are put in an array of trackers for latter merging.
	 * 
	 */
	protected void buildTraceToProgramStart(AnalysisTrackStorage storage, int depthLevel, BasicBlockGraph graph, BasicBlock block) {
		getInputLocationAtBlockStart(storage, block, depthLevel);
		if(!ProgramAnalysisUtilities.trackerIsConstant(storage) && depthLevel < 15) {
			ArrayList<BasicBlock> sourceBlocks = filterSourcesByNull(graph, block.getIncomingSources());
			if(sourceBlocks.size() > 0) {
				buildTraceToProgramStart(storage, depthLevel+1, graph, sourceBlocks.get(0));
			    if(sourceBlocks.size() > 1) {
				    for(int index = 1; index < sourceBlocks.size(); index++) {
					    AnalysisTrackStorage clone = deepCopy(storage);
					    buildTraceToProgramStart(clone, depthLevel+1, graph, sourceBlocks.get(index));
				    }
			    }
			} else {
				traceResults.add(storage);
			}
		} else {
			traceResults.add(storage);
		}
	}


	
	/** 
	 * @param graph
	 * @param sources
	 * @return ArrayList<BasicBlock>
	 * 
	 * Filters source blocks by checking if they are null
	 * 
	 */
	public ArrayList<BasicBlock> filterSourcesByNull(BasicBlockGraph graph, ArrayList<Address> sources) {
		ArrayList<BasicBlock> filtered = new ArrayList<BasicBlock>();
		for(Address src : sources) {
			BasicBlock srcBlock = graph.getBlockByAddress(src);
			if(srcBlock != null) {
				filtered.add(srcBlock);
			}
		}

		return filtered;
	}


	
	/** 
	 * @param storage
	 * @return AnalysisTrackStorage
	 * 
	 * Creates a deep copy of the tracker storage for following multiple paths that split from one
	 * 
	 */
	public AnalysisTrackStorage deepCopy(AnalysisTrackStorage storage) {
		AnalysisTrackStorage clone = new AnalysisTrackStorage(storage.getFunc(), storage.getCall(), new ArrayList<Varnode>(), new ArrayList<MemoryPosition>());
		storage.getOriginFuncs().forEach(of -> clone.addOriginFunc(new String(of)));
		storage.getCalledFuncs().forEach(cf -> clone.addCalledFunc(new String(cf)));
		storage.getNodes().forEach(node -> clone.addNode(node));
		storage.getMemoryPosition().forEach(pos -> clone.addMem(new MemoryPosition(pos.getRegister(), pos.getOffset())));
		return clone;
	}
	
	
	
	
	/** 
	 * @return AnalysisTrackStorage
	 * 
	 * If multiple trackers have been created, the results are merged into on tracker
	 * by simply checking for duplicates
	 * 
	 */
	protected AnalysisTrackStorage mergeTrackerForSystemCall() {
		AnalysisTrackStorage merge = new AnalysisTrackStorage(traceResults.get(0).getFunc(), traceResults.get(0).getCall(), new ArrayList<Varnode>(), new ArrayList<MemoryPosition>());
		for(AnalysisTrackStorage storage : traceResults) {
			merge.getNodes().addAll(storage.getNodes());
			merge.getMemoryPosition().addAll(storage.getMemoryPosition());
			merge.getCalledFuncs().addAll(storage.getCalledFuncs());
			merge.getOriginFuncs().addAll(storage.getOriginFuncs());
		}
		ArrayList<Varnode> mergedNodes = new ArrayList<Varnode>(merge.getNodes().stream().distinct().collect(Collectors.toList()));
		ArrayList<MemoryPosition> mergedMem = mergeMemoryPosition(merge);
		ArrayList<String> mergedCalled = new ArrayList<String>(merge.getCalledFuncs().stream().distinct().collect(Collectors.toList()));
		ArrayList<String> mergedOrigin = new ArrayList<String>(merge.getOriginFuncs().stream().distinct().collect(Collectors.toList()));
		merge.setNodes(mergedNodes);
		merge.setMemoryPosition(mergedMem);
		merge.setCalledFuncs(mergedCalled);
		merge.setOriginFuncs(mergedOrigin);
		traceResults.clear();
		
		return merge;
	}


	
	/** 
	 * @param merge
	 * @return ArrayList<MemoryPosition>
	 * 
	 * Merges memory positions and removes duplicates
	 * 
	 */
	protected ArrayList<MemoryPosition> mergeMemoryPosition(AnalysisTrackStorage merge){
		ArrayList<MemoryPosition> filtered = new ArrayList<MemoryPosition>();
		for(MemoryPosition pos : merge.getMemoryPosition()) {
			if(filtered.size() == 0) {
				filtered.add(pos);
			}
			for(MemoryPosition fp : filtered) {
				if(!(fp.getRegister().toString().equals(pos.getRegister().toString()) && fp.getOffset().toString().equals(pos.getOffset().toString()))) {
					filtered.add(pos);
				}
			}
		}
		return filtered;
	}
	
	
	
	
	/** 
	 * @param storage
	 * @param block
	 * @param depthLevel
	 * 
	 * Iterates backwards over a basic block to get the system call input location at the start
	 * of the block.
	 * It ignores the very first assembly instruction as it belongs to the system call itself
	 * and checks each last intruction of a block for interesting function calls
	 * 
	 */
	protected void getInputLocationAtBlockStart(AnalysisTrackStorage storage, BasicBlock block, int depthLevel) {
		ArrayList<EnhancedInstructionDetails> groups = block.getOps();
		for(int i = groups.size(); i-- > 0;) {
			EnhancedInstructionDetails group = groups.get(i);
			int numOfInstr = group.getGroup().size();
            // Check if current assembly instruction is a NOP
			if(numOfInstr > 0) {
				if(i == groups.size()-1 && depthLevel == 0) {
					continue;
				}
				if(i == groups.size()-1 && depthLevel > 0) {
					// Checks if the last Pcode instruction of a block is actually a jump
					PcodeOp branch = group.getGroup().get(numOfInstr - 1).getOp();
					if(ProgramGraphBuilder.JUMP_INSTRUCTIONS.contains(branch.getMnemonic())) {
						checkForOriginFunction(group, storage, block, depthLevel, branch);
					} else {
						checkForInterestingObjects(storage, group, block);
					}
				} else {
					checkForInterestingObjects(storage, group, block);
				}
				if(ProgramAnalysisUtilities.trackerIsConstant(storage)) {
					break;
				}
			}
			
		}
	}


	
	/** 
	 * @param storage
	 * @param group
	 * @param block
	 * 
	 * Checks whether assembly instructions contains in - or output objects that match an object in the tracker
	 * 
	 */
	protected void checkForInterestingObjects(AnalysisTrackStorage storage, EnhancedInstructionDetails group, BasicBlock block) {
		ArrayList<Varnode> matchedOutput = ProgramAnalysisUtilities.matchTrackedNodesWithOutput(storage, group.getResultObjects(), context);
		ArrayList<MemoryPosition> matchedInput = ProgramAnalysisUtilities.matchTrackedMemoryPositionWithInput(stackPointer, storage, group.getInputObjects(), context);
				
		if(!matchedOutput.isEmpty() || !matchedInput.isEmpty()) {
			if(group.getResultObjects().isEmpty()) {
				analysePcodeCompound(storage, group, block, matchedOutput, matchedInput, true);
			} else {
				analysePcodeCompound(storage, group, block, matchedOutput, matchedInput, false);
			}
		}
	}
	
	
	
	/** 
	 * @param storage
	 * @param group
	 * @param block
	 * @param output
	 * @param input
	 * @param noOutput
	 * 
	 * Analyses a group of Pcode instructions that belong to one assembly instruction.
	 * It further checks for stackpointer operations in the block.
	 * It treats the block differently, depending on it having output or not.
	 * If there ís no output, the STORE instruction is analysed, the whole block otherwise.
	 * 
	 */
	protected void analysePcodeCompound(AnalysisTrackStorage storage, EnhancedInstructionDetails group, BasicBlock block, ArrayList<Varnode> output, ArrayList<MemoryPosition> input, Boolean noOutput) {
		ArrayList<SimplifiedInstruction> ops = group.getGroup();
		if(stackOperations.contains(group.getInstruction().getMnemonicString())) {
			ArrayList<String> reg = storage.getMemoryPosition().stream().map(m -> context.getRegister(m.getRegister()).getName()).collect(Collectors.toCollection(ArrayList::new));
			if(reg.contains(stackPointer.getName())) {
				ProgramAnalysisUtilities.updateStackVariables(storage, group, context, stackPointer);
			}
		}
		if(noOutput) {
			getStoredInput(storage, input, ops);
			
		} else {
			StackFrame frame = funcMan.getFunctionContaining(group.getInstruction().getAddress()).getStackFrame();
			for(int j = ops.size(); j-- > 0;) {
				analysePcodeOperation(storage, ops.get(j).getOp(), frame);
			}
			
		}
	}


	
	/** 
	 * @param storage
	 * @param input
	 * @param ops
	 * 
	 * Checks if the input of the store instruction comes from the COPY or STORE op.
	 * 
	 */
	protected void getStoredInput(AnalysisTrackStorage storage, ArrayList<MemoryPosition> input, ArrayList<SimplifiedInstruction> ops) {
		ArrayList<Varnode> copied = new ArrayList<Varnode>();
		ProgramAnalysisUtilities.removeTrackedMemoryPositions(storage, input);
		Boolean inputSet = false;
		for(SimplifiedInstruction op : ops) {
			if(op.getOp().getOpcode() == PcodeOp.COPY && !op.getOp().getInput(0).isUnique()) {
				copied.add(op.getOp().getInput(0));
			}
			if(op.getOp().getOpcode() == PcodeOp.STORE && !ProgramAnalysisUtilities.checkIfStoreInputisVirtual(op.getOp())) {
				inputSet = true;
				storage.addNode(ProgramAnalysisUtilities.parseStoreInput(op.getOp()));
			}
		}

		if(!inputSet) {
			for(Varnode cpy : copied) {
				storage.addNode(cpy);
			}
		}

	}
	
	
	
	/** 
	 * @param compound
	 * @param storage
	 * @param block
	 * @param depthLevel
	 * @param branch
	 * 
	 * Checks whether the called function is one of the vulnerable, input, checkchar or origin functions.
	 * In case a match was found, the tracker's register values and memory positions are removed and the input
	 * arguments of the matched function are inserted. (not in case of the origin function)
	 * 
	 */
	protected void checkForOriginFunction(EnhancedInstructionDetails compound, AnalysisTrackStorage storage, BasicBlock block, int depthLevel, PcodeOp branch) {
		if(PcodeOp.CALL == branch.getOpcode()) {
			Function calledFunc = funcMan.getFunctionAt(branch.getInput(0).getAddress());
			if(checkCharFunctions.contains(calledFunc.getName()) && depthLevel < 4) {
				int arg_count = 1;
				ProgramAnalysisUtilities.getFunctionParams(storage, calledFunc, context, parameterRegister, cpuArchitecture, addressFactory, stackPointer, arg_count);
			}
			else if(inputFunctions.contains(calledFunc.getName()) && depthLevel < 5) {
				ProgramAnalysisUtilities.removeTracked(storage);
				int arg_count = 2;
				ProgramAnalysisUtilities.getFunctionParams(storage, calledFunc, context, parameterRegister, cpuArchitecture, addressFactory, stackPointer, arg_count);
			}
			else if(vulnerableFunctions .containsKey(calledFunc.getName()) && depthLevel < 3) {
				ProgramAnalysisUtilities.removeTracked(storage);
				ProgramAnalysisUtilities.getVulnFunctionParams(storage, calledFunc, context, parameterRegister, vulnerableFunctions , cpuArchitecture, addressFactory, stackPointer);
				
			} else if(calledFunc.isThunk() && calledFunc.getParameterCount() == 0 && !calledFunc.hasNoReturn()) {
				for(Varnode node : storage.getNodes()) {
					if(node.isRegister() && returnRegister.getName().equals(context.getRegister(node).getName())) {
						storage.addOriginFunc(calledFunc.getName());
						ProgramAnalysisUtilities.removeTracked(storage);
						break;
					}
				}
			}
		}
	}
	
	
	/** 
	 * @param storage
	 * @param op
	 * @param frame
	 * 
	 * Analyses a single Pcode instruction, depending on it being a Cast, BinOp, Copy or Load
	 * 
	 */
	protected void analysePcodeOperation(AnalysisTrackStorage storage, PcodeOp op, StackFrame frame) {
		
		Varnode output = op.getOutput();
		ArrayList<Long> varOffsets = ProgramAnalysisUtilities.getStackVarOffsets(frame);
		ArrayList<Varnode> trackedNodes = storage.getNodes();
		
		if(trackedNodes.contains(output)) {
			if(binaryOperations.contains(op.getMnemonic())) {
				updateNodeAndMemoryTracker(storage, op, varOffsets, output);	
			}
			if (casts.contains(op.getMnemonic())) {
				return;
			}
			if(op.getOpcode() == PcodeOp.COPY) {
				trackedNodes.remove(output);
				storage.addNode(op.getInput(0));
			}
			if (op.getOpcode() == PcodeOp.LOAD) {
				trackedNodes.remove(output);
				if(op.getNumInputs() == 2) {
					storage.addNode(op.getInput(1));
				} else {
					storage.addNode(op.getInput(0));
				}
			}
		}
	}
	
	
	
	/** 
	 * @param storage
	 * @param op
	 * @param varOffsets
	 * @param matchedOutput
	 * 
	 * Checks whether the Pcode instruction is either an INT_ADD or INT_SUB and if so, checks
	 * if the input is a memory position
	 * 
	 */
	protected void updateNodeAndMemoryTracker(AnalysisTrackStorage storage, PcodeOp op, ArrayList<Long> varOffsets, Varnode matchedOutput) {
		if(PcodeOp.INT_ADD == op.getOpcode() || PcodeOp.INT_SUB == op.getOpcode()) {
			Varnode destination = op.getInput(0);
			Varnode source = op.getInput(1);
			if(destination.isRegister()) {
				if(source.isConstant()) {
					handleConstantSource(storage, destination, source, matchedOutput);
				} else {
					storage.removeNode(matchedOutput);
					storage.addNode(source);
				}
			}
		}
	}


	
	/** 
	 * @param storage
	 * @param destination
	 * @param source
	 * @param matchedOutput
	 * 
	 * Adds memory location to tracker if not yet available
	 * 
	 */
	protected void handleConstantSource(AnalysisTrackStorage storage, Varnode destination, Varnode source, Varnode matchedOutput) {
		if(!destination.toString().equals(matchedOutput.toString())) {
			storage.removeNode(matchedOutput);
			if(storage.notATrackedMemoryPosition(destination, source, context)) {
				storage.addMem(new MemoryPosition(destination, source));
			}
		}
	}
	
}
