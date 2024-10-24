# Offender - Exploitation ELF Offset Finder.

# Description
Offender is a powerful framework written in python for extracting data from ELFs automatically.
Offender is written with binary exploitation in mind, where one needs to extract addresses of Symbols, Functions and Opcodes, for a large base of ELF versions.

Offender is currently under development, please report any bugs encountered.
Any suggestions are very welcome!

# Installation
Currently, Offender has not been uploaded to PIP, so in order to install:
- Clone this project.
- Install with pip install .[all]

# Usage

```python
# Create a config of Offsets to extract.
from offender.offset.offset_config import OffsetConfig, Offsets
from offender.offset.offset import Symbol

config = OffsetConfig(
  general=Offsets(
    offsets=[
      Symbol(name="name_to_refer_to_symbol", data="name_of_symbol_in_elf")
    ]
  )
)

# Create an extractor object to extract the config
from offender.offset.offset_extractor import OffsetExtractor
from offender.offset.offset_config import OffsetContext
extractor = OffsetExtractor(
  binary_paths=[("path_to_elf_to_search_in", "path_to_dwarf_of_elf")]

)

# extract using the `extract` method
offsets: OffsetContext = extractor.extract(config)

# Extract over multiple ELF configurations
elfs_to_extract_from = {
  "version_1": [("elf_1", "dwarf_1")],
  "version_2": [("elf_2", "dwarf_2")]
}

from offender.offset_finder.offset_finder import OffsetFinder
finder = OffsetFinder(config)

# extract using the find method
found_offsets, failed_versions = finder.find(versions=elfs_to_extract_from)

# Save results in db
finder.write_to_db(
  "path_to_db",
  found_offsets,
  failed_versions
)
```

# Contributing

Contributions are very welcome! please consult [contributing](CONTRIBUTING.md) before making a PR!
