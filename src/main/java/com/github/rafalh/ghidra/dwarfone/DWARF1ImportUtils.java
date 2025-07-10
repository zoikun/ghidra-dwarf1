package com.github.rafalh.ghidra.dwarfone;

import java.io.IOException;
import java.util.Optional;

import com.github.rafalh.ghidra.dwarfone.model.AttributeName;
import com.github.rafalh.ghidra.dwarfone.model.BlockAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.LocationDescription;
import com.github.rafalh.ghidra.dwarfone.model.StringAttributeValue;

import ghidra.app.util.bin.ByteArrayProvider;

public class DWARF1ImportUtils {
	private DWARF1ImportUtils() {
		// empty
	}
	
	static Optional<String> extractName(DebugInfoEntry die) {
		return die.<StringAttributeValue>getAttribute(AttributeName.NAME)
				.map(StringAttributeValue::get);
	}
	
	static Optional<LocationDescription> extractLocation(DebugInfoEntry die, DWARF1Program dwarfProgram) {
		return die.<BlockAttributeValue>getAttribute(AttributeName.LOCATION)
				.map(av -> decodeLocation(av.get(), dwarfProgram.isLittleEndian()));
		
	}
	
	private static LocationDescription decodeLocation(byte[] encodedLocation, boolean isLittleEndian) {
		var bp = new ByteArrayProvider(encodedLocation);
		try {
			return LocationDescription.read(bp, isLittleEndian);
		} catch (IOException e) {
			throw new IllegalArgumentException("Failed to parse location", e);
		}
	}

	/**
	 * Converts a byte array to a long value, respecting endianness.
	 * Only converts up to 8 bytes. If `bytes` is shorter than 8, it's padded with zeros.
	 *
	 * @param bytes The byte array to convert.
	 * @param isBigEndian True if the bytes should be interpreted as big-endian, false for little-endian.
	 * @return The long value.
	 */
	public static long bytesToLong(byte[] bytes, boolean isBigEndian) {
	    long value = 0;
	    int len = Math.min(bytes.length, 8); // Only read up to 8 bytes for a long

	    if (isBigEndian) {
	        for (int i = 0; i < len; i++) {
	            value = (value << 8) | (bytes[i] & 0xFF);
	        }
	    } else { // Little Endian
	        for (int i = 0; i < len; i++) {
	            value |= ((long) (bytes[i] & 0xFF)) << (i * 8);
	        }
	    }
	    return value;
	}
}
