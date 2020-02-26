# Color the Executed Instructions

**TL;DR**
- Run your program in QEMU to get the instuction's trace:
 ```
 $ qemu-{ARCH} -d in_asm -D /tmp/qemu.log ./a.out
 ```
- Copy script into: `{GHIDRA_INSTALL_PATH}/Ghidra/Features/Base/ghidra_scripts`
- Ghidra-> CodeBrowser-> Window -> Script Manager
- If yiu use flag other than `in_asm`, edit the `FILTER_PATTERN` and `FILTER_GROUP` variables.
- Run :)

---
When reversing a comlicated code, it can help to visualize the actual path of execution.

Hope I will find a time to add to it the values of the registers.. 
You can allways fork the script and edit it, or PR to us with the improvements :)

### Example:

**The Code**

![](https://user-images.githubusercontent.com/9990629/75324702-323ae480-5880-11ea-84b3-3e666b4b98c5.png)

**Execute**

 ```
 $ qemu-x86_64 -d in_asm -D /tmp/qemu.log ./a.out
 ```
 Type 4 on the `Insert Number` prompt
 
**Analyze**

Run the script, take the `/tmp/qemu.log` as a trace log.

![](https://user-images.githubusercontent.com/9990629/75325009-b8572b00-5880-11ea-87de-ddbe79d51c38.png)
