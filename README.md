GHIDRA DWARF1 MWCC Extension
=======================

This extension adds DWARF1 analyzer to Ghidra (built-in Ghidra DWARF analyzer does not support this version of DWARF
debug format).

Updated from [this fork](https://github.com/dbalatoni13/ghidra-dwarf1/tree/master) with these features:

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

Install it like any other Ghidra extension. See [Installation Guide](https://ghidra-sre.org/InstallationGuide.html#Extensions) for instructions.

Build
-----

### Prerequisites

Before you begin, ensure you have the following installed:

* **Java Development Kit (JDK) 11 or later**: Ghidra typically requires a specific JDK version.
* **Ghidra Installation**: An existing installation of Ghidra (e.g., `ghidra_11.3.1_PUBLIC`).
* **Visual Studio Code**: With the following extensions installed:
    * **Extension Pack for Java** (includes Language Support for Java, Debugger for Java, etc.)
    * **Gradle for Java**
    * **Python** (if you plan to work with PyGhidra scripts)
    * **Debugpy** (for Python debugging)

#### Project Setup

1.  **Set `GHIDRA_INSTALL_DIR` Environment Variable**:
    The build system relies on knowing the location of your Ghidra installation. Set the `GHIDRA_INSTALL_DIR` environment variable to the absolute path of your Ghidra installation directory.

    * **Linux/macOS (Bash/Zsh)**:
        ```bash
        export GHIDRA_INSTALL_DIR=/path/to/your/ghidra_installation
        ```
    * **Windows (PowerShell)**:
        ```powershell
        $env:GHIDRA_INSTALL_DIR = "C:\path\to\your\ghidra_installation"
        ```
    * **Windows (Command Prompt)**:
        ```cmd
        set GHIDRA_INSTALL_DIR=C:\path\to\your\ghidra_installation
        ```

2.  **Open Project in Visual Studio Code**:
    Navigate to the root directory of your cloned repository in your terminal and open it with VS Code:
    ```bash
    cd /path/to/your/cloned-repo
    code .
    ```
    VS Code's Java and Gradle extensions will automatically detect the project and configure the workspace. Allow some time for the Java Language Server to initialize and resolve dependencies.

3.  **Build the Extension**:
    You can build the extension using the Gradle Wrapper from your terminal:
    ```bash
    ./gradlew buildExtension
    ```
    Alternatively, in VS Code, open the "Gradle" view (the elephant icon in the Activity Bar), expand your project, and run the `buildExtension` task.

4.  **Run and Debug in VS Code**:
    * Open the **Run and Debug** view (`Ctrl+Shift+D` or `Cmd+Shift+D`).
    * Select the desired configuration from the dropdown:
        * **"Ghidra"**: To launch Ghidra with your extension loaded for Java debugging.
        * **"Ghidra Attach"**: To attach to an already running Ghidra instance.
    * Click the green "Start Debugging" play button.

    The "Ghidra" configuration will automatically run the `buildExtension` task before launching Ghidra, ensuring you're debugging the latest version of your code.

License
-------
The MIT license. See LICENSE.txt.
