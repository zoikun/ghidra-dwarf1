package com.github.rafalh.ghidra.dwarfone.model;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum FundamentalType {
	CHAR(0x0001),
	SIGNED_CHAR(0x0002),
	UNSIGNED_CHAR(0x0003),
	SHORT(0x0004),
	SIGNED_SHORT(0x0005),
	UNSIGNED_SHORT(0x0006),
	INTEGER(0x0007),
	SIGNED_INTEGER(0x0008),
	UNSIGNED_INTEGER(0x0009),
	LONG(0x000A),
	SIGNED_LONG(0x000B),
	UNSIGNED_LONG(0x000C),
	POINTER(0x000D),
	FLOAT(0x000E),
	DBL_PREC_FLOAT(0x000F),
	EXT_PREC_FLOAT(0x0010),
	COMPLEX(0x0011),
	DBL_PREC_COMPLEX(0x0012),
	VOID(0x0014),
	BOOLEAN(0x0015),
	EXT_PREC_COMPLEX(0x0016),
	LABEL(0x0017),
	//MWCC
	LONG_LONG(0x8008),
	SIGNED_LONG_LONG(0x8108),
	UNSIGNED_LONG_LONG(0x8208),
	INT8(0x9001),
	SIGNED_INT8(0x9101),
	UNSIGNED_INT8(0x9201),
	INT16(0x9302),
	SIGNED_INT16(0x9402),
	UNSIGNED_INT16(0x9502),
	INT32(0x9604),
	SIGNED_INT32(0x9704),
	UNSIGNED_INT32(0x9804),
	INT64(0x9908),
	SIGNED_INT64(0x9a08),
	UNSIGNED_INT64(0x9b08),
	REAL32(0xa004),
	REAL64(0xa108),
	REAL96(0xa20c),
	REAL128(0xa310),
	FIXED_VECTOR_8x8(0xa408),
	LONG128(0xa510),
	SIGNED_INT_16x8(0xa610),
	SIGNED_INT_8x16(0xa710),
	SIGNED_INT_4x32(0xa810),
	UNSIGNED_INT_16x8(0xa910),
	UNSIGNED_INT_8x16(0xaa10),
	UNSIGNED_INT_4x32(0xab10),
	GekkoPairedSingle(0xac00),

	USER(null);

	private static final int LO_USER = 0x8000;
	private static final int HI_USER = 0xFFFF;
	private static final Map<Integer, FundamentalType> VALUE_MAP;
	
	private Integer value;
	
	static {
		VALUE_MAP = Stream.of(FundamentalType.values())
				.filter(at -> at.value != null)
				.collect(Collectors.toUnmodifiableMap(ft -> ft.value, Function.identity()));
	}
	
	FundamentalType(Integer value) {
		this.value = value;
	}
	
	public static FundamentalType fromValue(int value) {
		FundamentalType ft = VALUE_MAP.get(value);
		if (ft == null) {
			if (value >= LO_USER && value <= HI_USER) {
				return USER;
			}
			throw new IllegalArgumentException("invalid fundamental type " + value);
		}
		return ft;
	}
}
