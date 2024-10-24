##  Goal
Provide a powerful framework for extracting data from elfs automatically.
This library is written with binary exploitation in mind, where one needs addresses of Symbols, Functions, and Opcodes; for a large base of elf versions.

## Project concepts

### Offset
- An offset is a unit of data extracted from the ELF, and in the end, an integer (address).
- An offset can be a Symbol, a sequence of Opcodes, and more.
- An offset can depend on other offsets, and their values can be used on the offsets calculation.

Please look at the class `Offset` in the `offset` module for further documentation.

### Offset Config
The totality of offsets to search.
Has two parts
- general
  - general data to be extracted.
  - If, for a specific elf configuration, the general data cannot be extracted,the overall extraction fails (for this elf configuration) and is halted.
  - Offsets inside general can ONLY depend on other offsets inside general.
  
- chains
  - Represents a ROP chain
  - There can be multiple.
  - The offset is considered a failure (for a specific elf configuration) if not AT LEAST one chain can be found.
  - An offset in a chain can ONLY depend on offsets in general AND in the SAME chain.

Please look at the class `OffsetConfig` in the `offset` module for further documentation

### Searcher
- A searcher is the basic unit that actually interacts with the supplied ELF files.
- They implement a set of functions that each searches for a different type of Offset (Symbol, Opcodes, ect...)
- Each searcher is supposed to be INDEPENDENT of other searchers, each with their own benefits and drawbacks.
- Searchers are CONFIGURABLE, the user can choose which ones the library has access to - they can even decide which to install.
- Currently, three searchers are implemented
  - r2searcher - Uses radare2
  - elftools_searcher - users pyelftools library.
  - linux_searcher - uses linux shell commands.
- To allow dynamic loading of searchers, they must have a specific structure
  - be found in `searchers` directory
  - the file the contains a searcher and the searchers' class name must be the same. 
    - The file name to be in snake_case
    - The searcher class to be in CamelCase.

Please look at the `searcher` directory for implementation examples.

### OffsetExtractor
This object manages the searchers.
In effect, for each required Offset, it iterates over all available Searchers in an attempt to find the requested offset.

The OffsetExtractor implementation is found in the `offset` module.

### OffsetFinder
The most top-level user interface.

- Receives a wanted OffsetConfig to find, and a list of elf configurations to find those in.
- Finds all the offsets that it can, notifying the user for elf configurations that succeeded and those that fail.
- Has the option to write the resulting OffsetContext to DB.

class `OffsetFinder` can be found in the `offset_finder` module. 
