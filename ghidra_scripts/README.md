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

It happens, when conducting reverse engineering on a stripped binary that we encounter logging mechanisms that just logs the **so needed** function name in plain text. For example, let's take [dropbear](https://github.com/mkj/dropbear) code compiled with TRACES flag as an example:

![](https://user-images.githubusercontent.com/9990629/71474859-241c0980-27e6-11ea-8b38-5c8643dba520.png)

Wouldn't it be great if we will find all occurrences of logs like `FUN_00012d54("enter buf_put_rsa_priv_key");` and take `buf_put_rsa_priv_key` and put it as function name:

![](https://user-images.githubusercontent.com/9990629/71475364-8d9d1780-27e8-11ea-9105-928f3e7a038b.png)

As [dropbear](https://github.com/mkj/dropbear) is open-source, we can see that we were right!

![](https://user-images.githubusercontent.com/9990629/71475828-b45c4d80-27ea-11ea-99cc-bd38177fb99a.png)

That is exactly what the script does!

Following our example, we will look for everithing that matches `\w+\(\"enter (\w+)\"\);` regex, retrive the goup 1 (which defined by `(\w+)`) and set it as function name. Of course this regex and the group will be different for each binary.

Only unlabeled function names are changed.

Since Java doesn't have any (native) proper configuration setup, we use inline editing.

Two errors are logged:
- Warning when two alphanumeric values are found within one function (can happen due to inline functions)
- Warning when the value of the defined group is not alphanumeric
