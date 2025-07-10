package com.github.rafalh.ghidra.dwarfone.model;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum LocationAtomOp {
	REG(0x01),
	BASEREG(0x02),
	ADDR(0x03), 
	CONST(0x04), 
	DEREF2(0x05),
	DEREF4(0x06),
	ADD(0x07),
		//MWCC 
	FPREG(0x80),
	FPDREG(0x81),
	DEREF8(0x82),

	USER(null);

	private static final int LO_USER = 0xE0;
	private static final int HI_USER = 0xFF;
	private static final Map<Integer, LocationAtomOp> VALUE_MAP;
	
	private Integer value;
	
	static {
		VALUE_MAP = Stream.of(LocationAtomOp.values())
				.filter(op -> op.value != null)
				.collect(Collectors.toUnmodifiableMap(op -> op.value, Function.identity()));
	}
	
	LocationAtomOp(Integer value) {
		this.value = value;
	}
	
	public static LocationAtomOp decode(int value) {
		LocationAtomOp op = VALUE_MAP.get(value);
		if (op == null) {
			if (value >= LO_USER && value <= HI_USER) {
				return USER;
			}
			throw new IllegalArgumentException("invalid location atom " + value);
		}
		return op;
	}
}
