package program.structure;

import java.util.ArrayList;
import ghidra.program.model.address.Address;

/**
 * Represents a graph of basic blocks within the program, enabling the analysis
 * and navigation of the program's structure through its constituent blocks.
 */
public class BasicBlockGraph {
	private ArrayList<BasicBlock> graph;
	
	/**
     * Constructs an empty BasicBlockGraph.
     */
	public BasicBlockGraph() {
		this.graph = new ArrayList<>();
	}

	/**
     * Constructs a BasicBlockGraph with a predefined list of basic blocks.
     * @param blocks The initial list of basic blocks to include in the graph.
     */	
	public BasicBlockGraph(ArrayList<BasicBlock> blocks) {
		this.graph = blocks;
	} 

 	/**
     * Returns the list of basic blocks in the graph.
     * @return An ArrayList of BasicBlock objects.
     */
	public ArrayList<BasicBlock> getGraph() {
		return graph;
	}


	/**
     * Sets the list of basic blocks that make up the graph.
     * @param blocks An ArrayList of BasicBlock objects to set.
     */
	public void setGraph(ArrayList<BasicBlock> graph) {
		this.graph = graph;
	}

	/**
     * Adds a basic block to the graph.
     * @param block The BasicBlock to add to the graph.
     */
	public void addBlock(BasicBlock block) {
		this.graph.add(block);
	}
	
	/**
     * Retrieves a basic block from the graph that contains the specified address
     * within its instruction addresses.
     * @param address The Address to search for within the basic blocks.
     * @return The BasicBlock containing the address, or null if not found.
     */
	public BasicBlock getBlockByAddress(Address address) {
		for(BasicBlock block : graph) {
			if(block.getInstructionAddresses().contains(address)) {
				return block;
			}
		}
		
		return null;
	}
}
