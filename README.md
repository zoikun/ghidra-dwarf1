GHIDRA DWARF1 MWCC Extension
=======================

This extension adds DWARF1 analyzer to Ghidra (built-in Ghidra DWARF analyzer does not support this version of DWARF
debug format).

Updated from [this fork]https://github.com/dbalatoni13/ghidra-dwarf1/tree/master with these features:

1. Fixed enums parsing and imporing
2. Anonymous enums/unions/structure/classes now will have unique names based on DIE offset in debug section
3. Fixed and (slightly) expanded code for variable imporing 
4. Added support for DWARF1 MWCC extensions. These were used by MetroWerks CodeWarrior PS2 SDK.
5. Updated to Ghidra 11.3.1
6. VSCode support
7. Some QOL changes

It may not work with other files, probably has some bugs and is incomplete. Use it on your own risk. 
I suggest making a backup of your Ghidra database before using it, or work on fresh DB to be safe.

Usage
-----

Install it like any other Ghidra extension. See https://ghidra-sre.org/InstallationGuide.html#Extensions for instructions.

License
-------
The MIT license. See LICENSE.txt.
