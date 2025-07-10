package com.github.rafalh.ghidra.dwarfone.model;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum AttributeName {
	SIBLING(0x0010),
	LOCATION(0x0020),
	NAME(0x0030),
	FUND_TYPE(0x0050),
	MOD_FUND_TYPE(0x0060),
	USER_DEF_TYPE(0x0070),
	MOD_U_D_TYPE(0x0080),
	ORDERING(0x0090),
	SUBSCR_DATA(0x00A0),
	BYTE_SIZE(0x00B0),
	BIT_OFFSET(0x00C0),
	BIT_SIZE(0x00D0),
	ELEMENT_LIST(0x00F0),
	STMT_LIST(0x0100),
	LOW_PC(0x0110),
	HIGH_PC(0x0120),
	LANGUAGE(0x0130),
	MEMBER(0x0140),
	DISCR(0x0150),
	DISCR_VALUE(0x0160),
	STRING_LENGTH(0x0190),
	COMMON_REFERENCE(0x01A0),
	COMP_DIR(0x01B0),
	CONST_VALUE(0x01C0),
	CONTAINING_TYPE(0x01D0),
	DEFAULT_VALUE(0x01E0),
	FRIENDS(0x01F0),
	INLINE(0x0200),
	IS_OPTIONAL(0x0210),
	LOWER_BOUND(0x0220),
	PROGRAM(0x0230),
	PRIVATE(0x0240),
	PRODUCER(0x0250),
	PROTECTED(0x0260),
	PROTOTYPED(0x0270),
	PUBLIC(0x0280),
	PURE_VIRTUAL(0x0290),
	RETURN_ADDR(0x02A0),
	ABSTRACT_ORIGIN(0x02B0),
	START_SCOPE(0x02C0),
	STRIDE_SIZE(0x02E0),
	UPPER_BOUND(0x02F0),
	VIRTUAL(0x0300),
	//MWCC
	MANGLED(0x2008),
	RESTORE_SP(0x2010),
	GLOBAL_REF(0x2020),
	RESTORE_S0(0x2040),
	RESTORE_S1(0x2050),
	RESTORE_S2(0x2060),
	RESTORE_S3(0x2070),
	RESTORE_S4(0x2080),
	RESTORE_S5(0x2090),
	RESTORE_S6(0x20a0),
	RESTORE_S7(0x20b0),
	RESTORE_S8(0x20c0),
	RESTORE_F20(0x20d0),
	RESTORE_F21(0x20e0),
	RESTORE_F22(0x20f0),
	RESTORE_F23(0x2100),
	RESTORE_F24(0x2110),
	RESTORE_F25(0x2120),
	RESTORE_F26(0x2130),
	RESTORE_F27(0x2140),
	RESTORE_F28(0x2150),
	RESTORE_F29(0x2160),
	RESTORE_F30(0x2170),
	RESTORE_D20(0x2180),
	RESTORE_D21(0x2190),
	RESTORE_D22(0x21a0),
	RESTORE_D23(0x21b0),
	RESTORE_D24(0x21c0),
	RESTORE_D25(0x21d0),
	RESTORE_D26(0x2240),
	RESTORE_D27(0x2250),
	RESTORE_D28(0x2260),
	RESTORE_D29(0x2270),
	RESTORE_D30(0x2280),
	OVERLAY_ID(0x2290),
	OVERLAY_NAME(0x22a0),
	GLOBAL_REFS_BLOCK(0x2300),
	LOCAL_SPOFFSET(0x2310),
	MIPS16(0x2330),

	USER(null);

	public static final int MASK = 0xFFF0;
	private static final int LO_USER = 0x2000;
	private static final int HI_USER = 0x3ff0;
	private static final Map<Integer, AttributeName> VALUE_MAP;
	
	private Integer value;
	
	static {
		VALUE_MAP = Stream.of(AttributeName.values())
				.filter(at -> at.value != null)
				.collect(Collectors.toUnmodifiableMap(at -> at.value, Function.identity()));
	}
	
	AttributeName(Integer value) {
		this.value = value;
	}
	
	public static AttributeName decode(int value) {
		AttributeName at = VALUE_MAP.get(value);
		if (at == null) {
			if (value >= LO_USER && value <= HI_USER) {
				return USER;
			}
			throw new IllegalArgumentException("invalid attribute value " + value);
		}
		return at;
	}
}
