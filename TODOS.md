# Known Issues:
- If in the same ELF config two elfs share the same name, one will be overridden.
- Currently, symbols read from dynamic symbol table act weird and not always correctly.
  - Currently, ignore the version this symbol is exported for (after the @...)
  - Those different symbols might have different offsets, which are now ignored - thus inconsistent/wrong results might be returned.

# TODO:
- General
  - Improve code quality
- OffsetFinder
  - Currently, very bare-bones, especially writing to DB, make more robust/complex (is that needed? a simple serialization and de-serialization could be enough)
- OffsetConfig
  - Implement some common filters and modification as utils
- Offset Extractor
  - Some sort of Priority for each function of each searcher? So most effective searches will be run first
- Searchers
  - More comfortable and standardized way to configure searchers?
- Tests
  - Tests for OffsetFinder
  - How do I test the whole importing mess with searchers?
  - More robust tests - for everything.