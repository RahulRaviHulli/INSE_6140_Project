package program.structure;


import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.VarnodeContext;

/**
 * Provides utility methods to support the analysis of programs, including fetching architecture-specific
 * registers, manipulating stack arguments, and identifying CPU architectures.
 */
public class ProgramAnalysisUtilities {
	
	/**
     * Retrieves the return register based on the CPU architecture.
     *
     * @param cpuArchitecture The CPU architecture.
     * @param context The context for accessing register information.
     * @return The return register for the specified architecture.
     */
	public static Register getReturnRegister(String cpuArchitecture, VarnodeContext context) {
		switch(cpuArchitecture) {
		case "x86-64": return context.getRegister("RAX");
		case "x86-32": return context.getRegister("EAX");
		case "ARM-32": return context.getRegister("r0");
		default: return context.getRegister("v0");
		}
	}
	
	
	
	/**
     * Retrieves the frame pointer register based on the CPU architecture.
     *
     * @param cpuArchitecture The CPU architecture.
     * @param context The context for accessing register information.
     * @return The frame pointer register for the specified architecture.
     */
	public static Register getFramePointer(String cpuArchitecture, VarnodeContext context) {
		switch(cpuArchitecture) {
		case "x86-64": return context.getRegister("RBP");
		case "x86-32": return context.getRegister("EBP");
		case "ARM-32": return context.getRegister("r11");
		default: return context.getRegister("fp");
		}
	}
	
	
	
	/**
     * Retrieves the parameter registers based on the CPU architecture.
     *
     * @param cpuArchitecture The CPU architecture.
     * @param context The context for accessing register information.
     * @return A list of parameter registers for the specified architecture.
     */
	public static ArrayList<Register> getParameterRegister(String cpuArchitecture, VarnodeContext context) {
		ArrayList<Register> parameters = new ArrayList<Register>();
		switch(cpuArchitecture) {
		case "x86-64": {
			parameters.add(context.getRegister("RDI"));
			parameters.add(context.getRegister("RSI"));
			parameters.add(context.getRegister("RDX"));
			parameters.add(context.getRegister("RCX"));
			parameters.add(context.getRegister("R8"));
			parameters.add(context.getRegister("R9"));
			return parameters;
		}
		case "x86-32": return parameters;
		case "ARM-32": {
			parameters.add(context.getRegister("r0"));
			parameters.add(context.getRegister("r1"));
			parameters.add(context.getRegister("r2"));
			parameters.add(context.getRegister("r3"));
			return parameters;
		}
		default: {
			parameters.add(context.getRegister("a0"));
			parameters.add(context.getRegister("a1"));
			parameters.add(context.getRegister("a2"));
			parameters.add(context.getRegister("a3"));
			return parameters;
		}
		}
	}
	
	

	
	/**
     * Determines the CPU architecture of a given program.
     *
     * @param program The program to inspect.
     * @return A string representing the CPU architecture.
     */
	public static String getcpuArchitecture(Program program) {
		String langId = program.getCompilerSpec().getLanguage().getLanguageID().getIdAsString();
		String[] arch = langId.split(":");
		return arch[0] + "-" + arch[2];
	}
	
	
	
	/** 
	 * @param stackPointer
	 * @param addressFactory
	 * @param params
	 * @param context
	 * @return ArrayList<MemoryPosition>
	 * 
	 * For each stack varnode, it creates a stackpointer + offset pair
	 * 
	 */
	public static ArrayList<MemoryPosition> getStackArgs(Register stackPointer, AddressFactory addressFactory, ArrayList<Varnode> params, VarnodeContext context) {
		ArrayList<MemoryPosition> stackArgs = new ArrayList<MemoryPosition>();
		for(Varnode param : params) {
			if(param.isFree() && !param.isRegister()) {
				stackArgs.add(new MemoryPosition(context.getRegisterVarnode(stackPointer), new Varnode(addressFactory.getConstantAddress(param.getAddress().getOffset()), param.getSize())));
			}
		}
		
		return stackArgs;
	}
	
	
	
	/** 
	 * @param params
	 * @return ArrayList<Varnode>
	 * 
	 * Removes stack varnodes
	 * 
	 */
	public static ArrayList<Varnode> removeStackNodes(ArrayList<Varnode> params) {
		ArrayList<Varnode> clean = new ArrayList<Varnode>();
		for(Varnode param : params) {
			if(param.isRegister()) {
				clean.add(param);
			}
		}
		
		return clean;
	}
	
	
	
	/** 
	 * @param storage
	 * @return Boolean
	 * 
	 * Checks whether the tracker only contains constant values
	 * 
	 */
	public static Boolean trackerIsConstant(AnalysisTrackStorage storage) {
		if(storage.getMemoryPosition().isEmpty()) {
			for(Varnode node : storage.getNodes()) {
				if(!node.isConstant()) {
					return false;
				}
			}
			return true;
		}
		return false;
	}
	
	
	
	/** 
	 * @param input
	 * @return Boolean
	 * 
	 * Checks whether the offset is negative
	 * 
	 */
	public static Boolean isNegative(String input) {
		if(input.startsWith("-")) {
			return true;
		}
		return false;
	}
	
	
	
	/** 
	 * @param program
	 * @param instr
	 * @return String
	 * 
	 * Gets referenced data from a memory location if available
	 * 
	 */
	public static String getReferencedData(Program program, Instruction instr) {
		Reference[] memRef = instr.getReferencesFrom();
		for(Reference ref : memRef) {
			if(ref.isMemoryReference()) {
				Data data = DataUtilities.getDataAtAddress(program, ref.getToAddress());
				return data.getDefaultValueRepresentation();
			}
		}
		
		return null;
	}
	
	
	
	/** 
	 * @param func
	 * @param context
	 * @return ArrayList<Varnode>
	 * 
	 * Gets a function's parameters
	 * 
	 */
	public static ArrayList<Varnode> getFunctionParameters(Function func, VarnodeContext context) {
		Parameter[] params = func.getParameters();
		ArrayList<Varnode> inputs = new ArrayList<Varnode>();
		for(Parameter param : params) {
			inputs.add(param.getFirstStorageVarnode());
		}
		
		return inputs;
	}
	
	
	
	/** 
	 * @param frame
	 * @return ArrayList<Long>
	 * 
	 * Gets the stack variable offsets from the stack frame
	 * 
	 */
	public static ArrayList<Long> getStackVarOffsets(StackFrame frame) {
		ArrayList<Long> varOffsets = new ArrayList<Long>();
		for(Variable var : frame.getStackVariables()) {
			varOffsets.add((long)var.getStackOffset());
		}
		
		return varOffsets;
	}
	
	
	
	/** 
	 * @param stackPointer
	 * @param storage
	 * @param context
	 * 
	 * Removes the stackpointer + offset pair
	 * 
	 */
	public static void removeStackPointer(Register stackPointer, AnalysisTrackStorage storage, VarnodeContext context) {
		ArrayList<MemoryPosition> updated = new ArrayList<MemoryPosition>();
		Boolean removed = false;
		for(MemoryPosition pos : storage.getMemoryPosition()) {
			if(removed) {
				updated.add(pos);
			} else if(!context.getRegister(pos.getRegister()).getName().equals(stackPointer.getName())) {
				updated.add(pos);
			} else {
				removed = true;
			}
		}
		storage.setMemoryPosition(updated);
	}
	
	
	
	/** 
	 * @param storage
	 * @param input
	 * 
	 * Removes tracked memory positions that match the input of the instructions as they are overwritten
	 * by a different source
	 * 
	 */
	public static void removeTrackedMemoryPositions(AnalysisTrackStorage storage, ArrayList<MemoryPosition> input) {
		for(MemoryPosition pos : input) {
			storage.getMemoryPosition().remove(pos);
		}
	}
	
	
	
	/** 
	 * @param op
	 * @return Boolean
	 * 
	 * Checks whether the input of a store instruction is a virtual register
	 * 
	 */
	public static Boolean checkIfStoreInputisVirtual(PcodeOp op) {
		if(op.getNumInputs() == 3) {
			return op.getInput(2).isUnique();
		}
		return op.getInput(1).isUnique();
	}


	
	/** 
	 * @param op
	 * @return Varnode
	 * 
	 * Gets the store input depending on it having a address space varnode or not
	 * 
	 */
	public static Varnode parseStoreInput(PcodeOp op) {
		if(op.getNumInputs() == 3) {
			return op.getInput(2);
		}
		return op.getInput(1);
	}
	
	
	
	/** 
	 * @param storage
	 * @param output
	 * @param context
	 * @return ArrayList<Varnode>
	 * 
	 * Matches register varnodes in the tracker with the output of the assembly instruction
	 * 
	 */
	public static ArrayList<Varnode> matchTrackedNodesWithOutput(AnalysisTrackStorage storage, ArrayList<String> output, VarnodeContext context){
		ArrayList<Varnode> seen = new ArrayList<Varnode>();
		for(String out : output) {
			for(Varnode node : storage.getNodes()) {
				if(node.isRegister() && context.getRegister(node).getName().equals(out)) {
					seen.add(node);
				}
			}
		}
		
		return seen;
	}
	
	
	
	/** 
	 * @param stackPointer
	 * @param storage
	 * @param inputs
	 * @param context
	 * @return ArrayList<MemoryPosition>
	 * 
	 * Matches memory positions with the input of the assembly instruction
	 * 
	 */
	public static ArrayList<MemoryPosition> matchTrackedMemoryPositionWithInput(Register stackPointer, AnalysisTrackStorage storage, ArrayList<String> inputs, VarnodeContext context) {
		ArrayList<MemoryPosition> tracked = new ArrayList<MemoryPosition>();
		MemoryPosition stackPos = stackPointerTracked(stackPointer, storage, context);
		if(inputs.contains(stackPointer.getName()) && stackPos != null) {
			tracked.add(stackPos);
		} else {
			tracked = matchOffset(storage, tracked, inputs, context);
		}
		
		return tracked;
	}
	
	
	
	/** 
	 * @param storage
	 * @param tracked
	 * @param inputs
	 * @param context
	 * @return ArrayList<MemoryPosition>
	 * 
	 * Matches the offset of a memory position with the offset of another memory position
	 * 
	 */
	public static ArrayList<MemoryPosition> matchOffset(AnalysisTrackStorage storage, ArrayList<MemoryPosition> tracked, ArrayList<String> inputs, VarnodeContext context) {
		for(String in : inputs) {
			if(in.startsWith("0x") || in.startsWith("-0x")) {
				for(MemoryPosition pos : storage.getMemoryPosition()) {
					String offset = pos.getOffset().getAddress().toString().replaceFirst("^const:", "");
					try {
						long input = 0;
						if(ProgramAnalysisUtilities.isNegative(in)) {
							input = new BigInteger(in.replaceFirst("^-0x", ""), 16).longValue();
							input *= -1;
						} else {
							input = new BigInteger(in.replaceFirst("^0x", ""), 16).longValue();
						}
						long off = new BigInteger(offset, 16).longValue();
						if((input == off || (input *= -1) == off) && inputs.contains(context.getRegister(pos.getRegister()).getName())) {
							tracked.add(pos);
						}
					} catch(NumberFormatException e) {
						continue;
					}
				}
			}
		}
		
		return tracked;
	}
	
	
	
	/** 
	 * @param stackPointer
	 * @param storage
	 * @param context
	 * @return MemoryPosition
	 * 
	 * Returns a stack position if it is tracked
	 * 
	 */
	public static MemoryPosition stackPointerTracked(Register stackPointer, AnalysisTrackStorage storage, VarnodeContext context) {
		for(MemoryPosition pos : storage.getMemoryPosition()) {
			if(context.getRegister(pos.getRegister()).getName().equals(stackPointer.getName())) {
				return pos;
			}
		}
		return null;
	}


	
	/** 
	 * @param storage
	 * @param calledFunc
	 * @param context
	 * @param parameterRegister
	 * @param cpuArchitecture
	 * @param addressFactory
	 * @param stackPointer
	 * @param arg_count
	 * 
	 * Gets the function parameter of a checkchar or input function
	 * 
	 */
	public static void getFunctionParams(AnalysisTrackStorage storage, Function calledFunc, VarnodeContext context, ArrayList<Register> parameterRegister, String cpuArchitecture, AddressFactory addressFactory, Register stackPointer, int arg_count) {
		storage.addCalledFunc(calledFunc.getName());
		if(!cpuArchitecture.equals("x86-32")) {
			for(int c = 0; c < arg_count; c++) {
				Varnode arg = context.getRegisterVarnode(parameterRegister.get(c));
				if(storage.notATrackedNode(arg)) {
					storage.addNode(arg);
				}
			}
		} else {
			for(int c = 0; c < arg_count; c++) {
				storage.addMem(new MemoryPosition(context.getRegisterVarnode(stackPointer), new Varnode(addressFactory.getConstantAddress((c + 1) * 4), 4)));
			}
		}
	}
	
	
	
	/** 
	 * @param storage
	 * @param calledFunc
	 * @param context
	 * @param parameterRegister
	 * @param vulnerableFunctions 
	 * @param cpuArchitecture
	 * @param addressFactory
	 * @param stackPointer
	 * 
	 * Gets the function parameters of a vulnerable function
	 * 
	 */
	public static void getVulnFunctionParams(AnalysisTrackStorage storage, Function calledFunc, VarnodeContext context, ArrayList<Register> parameterRegister, HashMap<String, Integer> vulnerableFunctions , String cpuArchitecture, AddressFactory addressFactory, Register stackPointer) {
		storage.addCalledFunc(calledFunc.getName());
		if(!cpuArchitecture.equals("x86-32")) {
			int parameterIndex = vulnerableFunctions .get(calledFunc.getName());
			Varnode arg = context.getRegisterVarnode(parameterRegister.get(parameterIndex));
			Varnode format_arg = null;
			if(calledFunc.getName().equals("snprintf") || calledFunc.getName().equals("sprintf")) {
				format_arg = context.getRegisterVarnode(parameterRegister.get(parameterIndex-1));
			}
			if(storage.notATrackedNode(arg)) {
				storage.addNode(arg);
			}
			if(format_arg != null && storage.notATrackedNode(format_arg)) {
				storage.addNode(format_arg);
			}
		} else {
			storage.addMem(new MemoryPosition(context.getRegisterVarnode(stackPointer), new Varnode(addressFactory.getConstantAddress(4), 4)));
			storage.addMem(new MemoryPosition(context.getRegisterVarnode(stackPointer), new Varnode(addressFactory.getConstantAddress(8), 4)));
		}
	}
	
	
	
	/** 
	 * @param storage
	 * @param group
	 * @param context
	 * @param stackPointer
	 * 
	 * Removes a stack variable from the tracker and adds the pushed value if the current assembly instruction is a push instruction
	 * 
	 */
	public static void updateStackVariables(AnalysisTrackStorage storage, EnhancedInstructionDetails group, VarnodeContext context, Register stackPointer) {
		PcodeOp firstInstr = group.getGroup().get(0).getOp();
		if(PcodeOp.COPY == firstInstr.getOpcode()) {
			Varnode in = firstInstr.getInput(0);
			if(storage.notATrackedNode(in)) {
				storage.addNode(in);
			}
		} else if(PcodeOp.INT_ADD == firstInstr.getOpcode()) {
			MemoryPosition newPos = new MemoryPosition(firstInstr.getInput(0), firstInstr.getInput(1));
			if(storage.notATrackedMemoryPosition(newPos.getRegister(), newPos.getOffset(), context)) {
				storage.addMem(newPos);
			}
		}
		
		removeStackPointer(stackPointer, storage, context);
	}


	/** 
	 * @param storage
	 * 
	 * Removes all tracked nodes, other than addresses and constants,
	 * and all memory positions
	 * 
	 */
	public static void removeTracked(AnalysisTrackStorage storage) {
		ArrayList<Varnode> registers = new ArrayList<Varnode>();
		for(Varnode node: storage.getNodes()) {
			if(!node.isRegister()) {
				registers.add(node);
			}
		}
		storage.setNodes(registers);
		storage.setMemoryPosition(new ArrayList<MemoryPosition>());
	}
}