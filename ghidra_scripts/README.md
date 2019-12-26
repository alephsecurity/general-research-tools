# ghidra_scripts
This repository includes all Ghidra scrips that we wrote to ease the reverse engineering process

---

### ReplaceFuncNameFromLog
**TL;DR**
- Copy script into: `{GHIDRA_INSTALL_PATH}/Ghidra/Features/Base/ghidra_scripts`
- Ghidra-> CodeBrowser-> Window -> Script Manager
- Find the script (filter by name)
- Edit the script with your regex and group by adding the data to `proccessedConfig` list
- Run :)

This script is used to set a function name upon known structure (regular expression and relevant matched group)
Only unlabeled function names are changed.
Since Java doesn't have any (native) proper configuration setup, we use inline editing.
Two errors are logged:
- Warning when two alphanumeric values are found within one function
- Warning when the value of the defined group is not alphanumeric
