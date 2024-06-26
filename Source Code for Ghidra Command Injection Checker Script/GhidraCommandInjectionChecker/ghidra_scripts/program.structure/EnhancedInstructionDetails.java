package program.structure;


import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class EnhancedInstructionDetails {
	private Address instrAddr;
	private Instruction instruction;
	private ArrayList<String> resultObjects;
	private ArrayList<String> inputObjects;
	private ArrayList<SimplifiedInstruction> group;
	
	public EnhancedInstructionDetails() {}
	
	public EnhancedInstructionDetails(ArrayList<SimplifiedInstruction> group) {
		this.setGroup(group);
	}
	
	public Address getInstrAddr() {
		return instrAddr;
	}
	
	public void setInstrAddr(Address instrAddr) {
		this.instrAddr = instrAddr;
	}
	
	public ArrayList<SimplifiedInstruction> getGroup() {
		return group;
	}
	
	public void setGroup(ArrayList<SimplifiedInstruction> group) {
		this.group = group;
	}
	
	public void addToGroup(SimplifiedInstruction instr) {
		this.group.add(instr);
	}

	public Instruction getInstruction() {
		return instruction;
	}

	public void setInstruction(Instruction instruction) {
		this.instruction = instruction;
	}

	public ArrayList<String> getResultObjects() {
		return resultObjects;
	}

	public void setResultObjects(ArrayList<String> resultObjects) {
		this.resultObjects = resultObjects;
	}
	
	public void addResultObjects(String resultObject) {
		this.resultObjects.add(resultObject);
	}

	public ArrayList<String> getInputObjects() {
		return inputObjects;
	}

	public void setInputObjects(ArrayList<String> inputObjects) {
		this.inputObjects = inputObjects;
	}
	
	public void addInputObjects(String inputObject) {
		this.inputObjects.add(inputObject);
	}
}
