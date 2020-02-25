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
//This small script is used to color each instruction that was executed during the run.
//The list of instructions get be retrieved with QEMU: 
//for example: qemu-x86_64 -d in_asm -D /tmp/qemu.log ./a.out
//You can use any other trace option. All you have to do is to change the FILTER_PATTERN and FILTER_GROUP accordingly.



import java.awt.Color;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class ColorAddress  extends GhidraScript {
	
	private static final String FILTER_PATTERN = "(0x[0-9a-fA-F]{16})(.*)"; // works with -d in_asm in QEMU
	private static final int FILTER_GROUP = 1;

	@Override
	protected void run() throws Exception {
		
		List<Address> listOfInstPtrToCollor = getAddresses();
		AddressSet addresses = new AddressSet();
		Address minAddress = currentProgram.getMinAddress();
		Address maxAddress = currentProgram.getMaxAddress();
		int counter = 0;
		
		if(listOfInstPtrToCollor == null || listOfInstPtrToCollor.isEmpty()) {
			printerr("Given list is empty!\n");
			return;
		}
		
		for (Address addr : listOfInstPtrToCollor) {
			//Check whether we are in the correct address space
			if (addr.compareTo(minAddress)>=0 && addr.compareTo(maxAddress) <=0){
				addresses.add(addr);
				counter++;
			}
		}

		//pink fuchsia <3
		setBackgroundColor(addresses, new Color(255, 119, 255));
		println(String.format("%d pointers were colored!",counter));
	}
	
	private List<Address> getAddresses() {
		Pattern pattern = Pattern.compile(FILTER_PATTERN);
		List<Address> listOfAccessedAddresses = new ArrayList<Address>();
		
		try {
			File file = askFile("Trace Log", "Choose file:");
			println("File chosen " + file);
			
			BufferedReader reader = new BufferedReader(new FileReader(file));
			String line = reader.readLine();
			while (line != null) {
				Matcher m = pattern.matcher(line);
				if(m.matches()) {
					String newAddr = m.group(FILTER_GROUP);
					listOfAccessedAddresses.add(currentAddress.getAddress(newAddr));
//					println("Adding address to be colored: " + m.group(FILTER_GROUP));
				}
				line = reader.readLine();
			}
			reader.close();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return listOfAccessedAddresses;
	}
}
