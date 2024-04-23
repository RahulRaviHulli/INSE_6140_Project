package program.structure;

import java.util.ArrayList;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/**
 * Represents a basic block within the program structure, encapsulating instructions,
 * their relationships, and associated metadata such as entry points and destinations.
 */
public class BasicBlock {
	private Address entryPoint; // The entry point address of this block
    private Function enclosingFunction; // The function that encompasses this block
    private ArrayList<EnhancedInstructionDetails> ops; // Groups of instructions within the block
    private ArrayList<Address> instructionAddresses; // Addresses of all instructions in the block
    private ArrayList<Address> jumpDestinations; // Destination addresses for jumps within the block
    private ArrayList<Address> incomingSources; // Source addresses leading into this block
	
	// Getters and setters for the class fields
	public Address getEntryPoint() {
		return entryPoint;
	}

	public void setEntryPoint(Address entryPoint) {
		this.entryPoint = entryPoint;
	}
	
	public Function getEnclosingFunction() {
        return enclosingFunction;
    }

	 public void setEnclosingFunction(Function enclosingFunction) {
        this.enclosingFunction = enclosingFunction;
    }
	
	public ArrayList<EnhancedInstructionDetails> getOps() {
		return ops;
	}

	public void setOps(ArrayList<EnhancedInstructionDetails> ops) {
		this.ops = ops;
	}
	
	public ArrayList<Address> getInstructionAddresses() {
        return instructionAddresses;
    }
	
	public void setInstructionAddresses(ArrayList<Address> instructionAddresses) {
        this.instructionAddresses = instructionAddresses;
    }

	public ArrayList<Address> getJumpDestinations() {
        return jumpDestinations;
    }

    public void setJumpDestinations(ArrayList<Address> jumpDestinations) {
        this.jumpDestinations = jumpDestinations;
    }

	public ArrayList<Address> getIncomingSources() {
        return incomingSources;
    }

    public void setIncomingSources(ArrayList<Address> incomingSources) {
        this.incomingSources = incomingSources;
    }


	/**
     * Retrieves the last instruction from the last group of instructions in the block,
     * often representing a branch or control flow change.
     * @return The final instruction if available, or null otherwise.
     */
    public SimplifiedInstruction getLastInstruction() {
        if (!ops.isEmpty()) {
            ArrayList<SimplifiedInstruction> lastGroup = ops.get(ops.size() - 1).getGroup();
            if (lastGroup != null && !lastGroup.isEmpty()) {
                return lastGroup.get(lastGroup.size() - 1);
            }
        }
        return null;
    }

}
