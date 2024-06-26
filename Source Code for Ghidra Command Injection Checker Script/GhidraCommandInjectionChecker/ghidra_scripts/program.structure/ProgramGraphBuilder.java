package program.structure;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;


/**
 * Provides utility methods for constructing a graph of basic blocks from a program,
 * and for identifying potential vulnerabilities through static analysis.
 */
public class ProgramGraphBuilder{

  	// Jump instructions that alter control flow
    public static final List<String> JUMP_INSTRUCTIONS = List.of("CALL", "CALLIND", "BRANCHIND", "BRANCH", "CBRANCH", "RETURN");
	
	
	// System call symbols that could be vulnerable to injection
    public static final List<String> SYSTEM_CALL_SYMBOLS = List.of("system", "execl");
    
	// Mapping from system functions to their caller addresses
    public static HashMap<Function, ArrayList<Address>> callerToSystemFunctionMap = new HashMap<>();
	
	/**
     * Builds a graph of basic blocks for the entire program based on the functions it contains.
     *
     * @param funcMan The program's function manager.
     * @param simpleBm A simple block model of the program.
     * @param listing The program's listing.
     * @param context The varnode context for pcode operations.
     * @param monitor A task monitor.
     * @return A graph of basic blocks.
     */
	public static BasicBlockGraph buildBlockGraph(FunctionManager funcMan, SimpleBlockModel simpleBm, Listing listing, VarnodeContext context, TaskMonitor monitor) {
		BasicBlockGraph blockGraph = new BasicBlockGraph(new ArrayList<BasicBlock>());
		for(Function function : funcMan.getFunctionsNoStubs(true)) {
			AddressSetView addresses = function.getBody();
			try {
				CodeBlockIterator blockIter = simpleBm.getCodeBlocksContaining(addresses, monitor);
				while(blockIter.hasNext()) {
					BasicBlock block = buildBlock(blockIter.next(), function, context, listing, funcMan, monitor);
					blockGraph.addBlock(block);
				}
			} catch(CancelledException e) {
				System.out.println("Could not retrieve basic blocks containing addresses.\n");
			}
		}
		return blockGraph;
	}
	
	
	public static BasicBlock buildBlock(CodeBlock codeBlock, Function function, VarnodeContext context, Listing listing, FunctionManager funcMan, TaskMonitor monitor) {
		/*
		 * Builds one block for the graph
		 * 
		 * */
		BasicBlock block = new BasicBlock();
		block.setEntryPoint(codeBlock.getFirstStartAddress());
		block.setEnclosingFunction(function);
		block.setOps(buildInstructions(codeBlock, context, listing));
		block.setInstructionAddresses(getAddressVector(codeBlock));
		block.setIncomingSources(getNeighbouringAddresses(codeBlock, true, monitor));
		block.setJumpDestinations(getNeighbouringAddresses(codeBlock, false, monitor));
		
		return block;
	}
	
	
	public static ArrayList<Address> getAddressVector(CodeBlock codeBlock) {
		ArrayList<Address> addresses = new ArrayList<Address>();
		codeBlock.getAddresses(true).forEachRemaining(addresses::add);
		return addresses;
	}
	
	
	public static ArrayList<Address> getNeighbouringAddresses(CodeBlock codeBlock, Boolean source, TaskMonitor monitor) {
		/*
		 * Gets all source and destination addresses for a block which refer to other blocks
		 * 
		 * */
		ArrayList<Address> sourceAddresses = new ArrayList<Address>();
		try {
			CodeBlockReferenceIterator blockRefIter;
			if(source) {
				blockRefIter = codeBlock.getSources(monitor);
			} else {
				blockRefIter = codeBlock.getDestinations(monitor);
			}
			while(blockRefIter.hasNext()) {
				Address neighbourAddr;
				if(source) {
					neighbourAddr = blockRefIter.next().getSourceAddress();
				} else {
					neighbourAddr = blockRefIter.next().getDestinationAddress();
				}
				sourceAddresses.add(neighbourAddr);
			} 
		} catch(CancelledException e) {
			System.out.println("Could not build neighbouring blocks.\n");
		}
		
		return sourceAddresses;
	}
	
	
	public static ArrayList<EnhancedInstructionDetails> buildInstructions(CodeBlock codeBlock, VarnodeContext context, Listing listing) {
		/*
		 * Builds simple instruction containing the mnemonic, generic in-/outputs and the address of the assembly instruction
		 * 
		 * */
		InstructionIterator instructions = listing.getInstructions(codeBlock, true);
		ArrayList<EnhancedInstructionDetails> instrComs = new ArrayList<EnhancedInstructionDetails>();
		while(instructions.hasNext()) {
			Instruction instruction = instructions.next();
			instrComs.add(buildEnhancedInstructionDetails(instruction, context));	
		}
		
		return instrComs;
	}
	
	
	public static EnhancedInstructionDetails buildEnhancedInstructionDetails(Instruction instruction, VarnodeContext context) {
		EnhancedInstructionDetails instrCompound = new EnhancedInstructionDetails(new ArrayList<SimplifiedInstruction>());
		instrCompound.setInstruction(instruction);
		instrCompound.setResultObjects(new ArrayList<String>());
		instrCompound.setInputObjects(new ArrayList<String>());
		for(Object res : instruction.getResultObjects()) {instrCompound.addResultObjects(res.toString());}
		for(Object in : instruction.getInputObjects()) {instrCompound.addInputObjects(in.toString());}
		instrCompound.setInstrAddr(instruction.getAddress());
		for(PcodeOp pcodeOp : instruction.getPcode(true)) {
			SimplifiedInstruction simpleInstr = new SimplifiedInstruction();
			if(!pcodeOp.getMnemonic().equals("STORE") && !JUMP_INSTRUCTIONS.contains(pcodeOp.getMnemonic())) {
				simpleInstr.setOutput(pcodeOp.getOutput());
			}
			
			ArrayList<Varnode> inputs = new ArrayList<Varnode>();
			for(int i = 0; i < pcodeOp.getNumInputs(); i++) {
				inputs.add(pcodeOp.getInput(i));
			}
			
			simpleInstr.setOp(pcodeOp);
			simpleInstr.setMnemonic(pcodeOp.getMnemonic());
			simpleInstr.setInputs(inputs);
			simpleInstr.setAddress(instruction.getAddress());
			instrCompound.addToGroup(simpleInstr);
			
		}
		
		return instrCompound;
	}
	
	 /**
     * Maps system functions to the functions that call them, providing insight into potential vulnerabilities.
     *
     * @param symTab The program's symbol table.
     * @param funcMan The program's function manager.
     */
	public static void mapCallerToSystemFunctions(SymbolTable symTab, FunctionManager funcMan) {
		for(Symbol sym : symTab.getDefinedSymbols()) {
			if(SYSTEM_CALL_SYMBOLS.contains(sym.getName()) && !sym.isExternal()) {
				for(Reference ref : sym.getReferences()) {
					Function sysFunc = funcMan.getFunctionAt(sym.getAddress());
					Function func = funcMan.getFunctionContaining(ref.getFromAddress());
					Address calledAddr = ref.getFromAddress();
					if(func != null && !SYSTEM_CALL_SYMBOLS.contains(func.getName())) {
						if(callerToSystemFunctionMap.get(sysFunc) == null) {
							ArrayList<Address> addresses = new ArrayList<Address>();
							addresses.add(calledAddr);
							callerToSystemFunctionMap.put(sysFunc, addresses);
						} else {
							callerToSystemFunctionMap.get(sysFunc).add(calledAddr);
						}
					}
				}
			}
		}
	}
}
