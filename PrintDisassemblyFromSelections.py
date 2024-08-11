#This script outputs the disassembly from the users selected address/addresses
#to the console. Additional options can be found below script header.
#@author Edward Krayer
#@category Assembly
#@keybinding
#@menupath
#@toolbar
#@runtime Jython

# Print entire function from selected addresses/ranges.

opt__print_whole_function = False

# Print Ghidra representation instead of raw disassembly.

opt__include_representations = False

# Assembly Format:          {0} = Address
#                           {1} = Opcode
#                           {2} = Operand/s
#                           {3} = Function Name

opt__asm_format = '{0:<18}{1:<10}\t{2}'

# Function Name Format:     {0} = Address
#                           {1} = Function Name

opt__print_function_name = False
opt__print_function_name_format = '{1}:'

# Function Argument Format: {0} = Name
#                           {1} = DataType
#                           {2} = Register

opt__print_function_args = False
opt__print_function_args_format = '{1:>17} {0:<10}{2:<10}'

import sys


def get_range_from_function(func):
    start = func.getEntryPoint()
    i = start
    while func == getFunctionContaining(i):
        i = i.next()
    return getAddressFactory().getAddressSet(start, i.previous())


# Set current_selection to user selected ranges.
# If not found, set to current address.

if currentSelection:
    current_selections = currentSelection.getAddressRanges()
else:
    current_selections = createAddressSet()
    current_selections.addRange(currentAddress, currentAddress)

# Convert ranges / addresses to their functions range.

if opt__print_whole_function:
    new_selection = []
    for selection in current_selections:
        curr = selection.getMinAddress()
        while curr <= selection.getMaxAddress():
            func = getFunctionContaining(curr)
            func_range = get_range_from_function(func)
            if func_range not in new_selection:
                new_selection.append(func_range)
            curr = curr.next()
    current_selections = new_selection

for selection in current_selections:
    print ''
    min_addr = selection.getMinAddress()
    curr = min_addr

    if opt__print_function_name:
        print opt__print_function_name_format.format(min_addr,
                getFunctionContaining(curr).getName())

    if opt__print_function_args:
        for var in getFunctionContaining(curr).getAllVariables():
            print opt__print_function_args_format.format(var.getName(),
                    var.getDataType(), var.getRegister())

    while curr <= selection.getMaxAddress():
        code = currentProgram.getListing().getCodeUnitAt(curr)
        if code:
            if opt__include_representations:
                code = getCodeUnitFormat().getRepresentationString(code)
            segments = str(code).split(' ', 1)
            print opt__asm_format.format(curr.toString(),
                    segments[0], segments[1],
                    getFunctionContaining(curr))

        curr = curr.next()
print ''
