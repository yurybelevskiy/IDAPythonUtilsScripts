import idaapi
import idautils

#Constant definitions

#List of typical IDA function prefixes
IDA_FUNC_PREFIXES = {"sub","nullsub","j_nullsub","j_memset","j_memcmp"}

"""Checks whether only 1 bit is set in the @val"""
"""Doesn't work with negative numbers"""
"""Returns True or False"""
def check_one_bit_set(val):
	if val > 0:
		counter = 0
		while(val>0):
			val = val >> 1
			if(val & 1 == 1):
				counter+=1
			if counter>1:
				return False		
		return counter == 1
	else:
		if val < 0:
			print "Value %d is negative! Please pass parameter >= 0!" % val
		return False

"""Collects structs of the given @struct_name located between @from_ea and @to_ea into the list"""
"""By default, function uses @from_ea = MinEA() and @to_ea=MaxEA()"""
"""If invalid name or address is given, returns empty list"""
def collect_structs_ea(from_ea=MinEA(),to_ea=MaxEA(),struct_name):
	if from_ea < MinEA() or from_ea > MaxEA():
		print "%s is out of bounds!" % hex(from_ea)
		return list()
	elif to_ea < MinEA() or to_ea > MaxEA():
		print "%s is out of bounds!" % hex(to_ea)
		return list()
	struct_id = GetStrucIdByName(struct_name)
	if struct_id == -1:
		print "%s struct doesn't exist!" % struct_name
		return list()
	else:
		refs = list()
		for ref in DataRefsTo(struct_id):
			refs.append(ref)
		return refs

"""Checks whether function at given @ea has a default name given by IDA"""
"""Note that @ea can be any address inside function scope"""
"""Returns boolean value"""
def check_default_function_name(ea):
	global IDA_FUNC_PREFIXES
	if ea < MinEA() or ea > MaxEA():
		print "%s is out of bounds!" % hex(ea)
		return False
	min_num_digits_ea = len(hex(MinEA()).split('x',1)[1])
	max_num_digits_ea = len(hex(MaxEA()).split('x',1)[1])
	func_name = GetFunctionName(ea)
	if not func_name:
		print "%s doesn't belong to any function!" % hex(ea)
		return False
	for prefix in IDA_FUNC_PREFIXES: 
		match = re.search("{0}_".format(prefix,min_num_digits_ea,max_num_digits_ea),func_name)
		if match:
			return True
	return False

""""""

