/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//This script is used to set a function name upon known structure (regular expression and relevant matched group)
//This script takes all .rodata elements, finds referenced functions, and looking for patterns in decompiled code.
//Decompilation occurs concurrently with each other. Only unlabeled function names are changed.
//The assumption is that for this task it is better to work with the decompiled code rather than with a binary format
//since the arguments retrieval can be challenging.
//
//Decompile is expensive procedure, to optimize the code consider decompile only
//the .rodata that matches to some "indication regex". mostly querying for "%" element will do. 
//Since Java doesn't have any (native) proper configuration setup, we use inline editing.
//
//Try your regex on one of your files to ensure that it working. 
//In case you are not confident with it take this as an example (also look for interactive tools online):
//The following regex will capture most of the function calls in the decompiler:
//"^( |\t)*\\w+\\(\n?([^;]+)(,\n?[^;]*)*\\)\n?( |\\t)*;"
//
//@category Function Symbols
//@author User Submitted

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class ReplaceFuncNameFromLog extends GhidraScript {
	
//  EXAMPLES
// 	RUCKUS (emfd) group 4
//	private final String pattern = "^( |\t)*\\w+\\(\n?(.*\"\\[[A-Z]*\\] id\\(0x%08x\\) - %s\\(\\):.*?\")(,\n?[^;,]*)(,\n?[^;,]*)(\n|[^;]*)*\\)\n?( |\t)*;";
//	RUCKUS (webs) group 3
//	private final String pattern = "^( |\t)*\\w+\\(\n?(.*\"\\[[A-Z]*\\] %s\\(\\):.*?\")(,\n?[^;,]*)(,\n?[^;,]*)(\n|[^;]*)*\\)\n?( |\t)*;";
// 	dropbear group 1
//	private final String pattern = "\\w+\\(\"enter (\\w+)\"\\);"; 
	
	private final String pattern = "";

	private class MyDecompileConfigurer implements DecompileConfigurer {
		@Override
		public void configure(DecompInterface decompiler) {
			DecompileOptions options = new DecompileOptions();
			OptionsService service = state.getTool().getService(OptionsService.class);
			if (service != null) {
				ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram(null, opt, currentProgram);
			}
			decompiler.setOptions(options);
		}
	}
	
	@Override
	protected void run() throws Exception {
		
		List<Entry<Pattern,Integer>> proccessedConfig = new ArrayList<Entry<Pattern,Integer>>();
		
		//-------------------------------------------------------------------------------
		//---------------THIS IS THE CONFIGURATION FOR THE SCRIPT------------------------
		//-------------------------------------------------------------------------------
		//proccessedConfig.add(new SimpleEntry<Pattern,Integer>(Pattern.compile(PATTERN),GROUP)
		
		proccessedConfig.add(new SimpleEntry<Pattern,Integer>( Pattern.compile(pattern,Pattern.MULTILINE),0));

		DecompilerCallback<Void> callback = new DecompilerCallback<Void>(currentProgram,
			new MyDecompileConfigurer()) {
			
			//The following will run for each decompiled function
			@Override
			public Void process(DecompileResults results, TaskMonitor m) throws Exception {
				boolean isFound = false;
				if (results != null && results.getDecompiledFunction() != null 
						&& results.getDecompiledFunction().getC() != null) {
					Function currentFunction = results.getFunction();
					String cCode = results.getDecompiledFunction().getC();
					List<String> posibleNames = new ArrayList<String>();
					for (Entry<Pattern,Integer> inputEntry : proccessedConfig) {
						Pattern tempPattern = inputEntry.getKey();
						Integer tempGroup = inputEntry.getValue();
						Matcher inputMatcher = tempPattern.matcher(cCode);
						String newFuncName = null;
						while (inputMatcher.find()) {
							String filteredGroup = inputMatcher
									.group(tempGroup)
									.replaceAll("\n", "")
									.replaceAll(",", "")
									.replaceAll("\"", "").trim();
							boolean isAlfpaNumeric = filteredGroup.matches("\\w+");
							if (posibleNames.contains(filteredGroup)) 
								continue;
							posibleNames.add(filteredGroup);
							if (!isAlfpaNumeric) {
								printerr(String.format(
										" %s :Given group <%d> "
										+ "has a non-alphanumeric value <%s> "
										+ "in the matched <%s> string\n",
										currentFunction,
										tempGroup, 
										filteredGroup, 
										inputMatcher.group().trim()));
								continue;
							}
							if (!isFound) {
								newFuncName = filteredGroup;
								
//								println("Match found! Going to change " + 
//								currentFunction.getName() +" to this: "+
//										newFuncName +"\n");
								
								currentFunction.setName(newFuncName,
										SourceType.USER_DEFINED);
								isFound = true;
								continue;
							}
							printerr(String.format(
									"Conflict in function at 0x%s! "
									+ "The name changed to %s but %s seems also good",
									currentFunction.getEntryPoint().toString(), 
									newFuncName, filteredGroup));
						} 
					}
				}
				return null;
			}
		};
		
		try {
			Set<Function> functions = getFunctiosThatRefferenceToData();
			ParallelDecompiler.decompileFunctions(callback, currentProgram, functions, monitor);
		}
		finally {
			callback.dispose();
		}
	}

	private Set<Function> getFunctiosThatRefferenceToData(){
		Set<Function> set = new HashSet<Function>();
		int counter = 0;
		try {
			Listing list = currentProgram.getListing();
			Memory mem = currentProgram.getMemory();
			MemoryBlock memblock = mem.getBlock(".rodata");
			Address minaddr = memblock.getStart();
			Address maxaddr = memblock.getEnd();
			AddressSetView addrsetview = new AddressSet(minaddr, maxaddr);
			//This will return all labels of .rodata section
			DataIterator dataIter = list.getDefinedData(addrsetview, false); 
			
			for ( Data data :dataIter ) {
				//for each data item take all the references to it
				ReferenceIterator refIter =  data.getReferenceIteratorTo();
				for (Reference ref : refIter) {
					Address addr = ref.getFromAddress();
					Function fun = list.getFunctionContaining(addr);
					if (fun != null && fun.getName().contains("FUN_")) {
						if (!set.contains(fun)) {
							set.add(fun);
							counter ++;
						}
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		printf("%d functions will be decompiled!\n",counter);
		return set;
	}
}
