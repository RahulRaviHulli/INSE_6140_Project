package program.structure;


import ghidra.program.model.pcode.Varnode;

/**
 * Represents a memory position defined by a base register and an offset.
 * This class is used to pinpoint specific locations in memory, facilitating
 * the analysis and manipulation of memory-related operations.
 */
public class MemoryPosition {
	private Varnode register;
	private Varnode offset;
	
	/**
     * Constructs a MemoryPosition with a specified register and offset.
     *
     * @param register The base register of the memory position.
     * @param offset The offset from the base register, defining the exact memory location.
     */
	public MemoryPosition(Varnode register, Varnode offset) {
		this.setRegister(register);
		this.setOffset(offset);
	}

	/**
     * Returns the offset from the base register of this memory position.
     *
     * @return The offset Varnode.
     */
	public Varnode getOffset() {
		return offset;
	}

	public void setOffset(Varnode offset) {
		this.offset = offset;
	}


	/**
     * Returns the base register of this memory position.
     *
     * @return The base register Varnode.
     */
	public Varnode getRegister() {
		return register;
	}

	public void setRegister(Varnode register) {
		this.register = register;
	}
}
