import idaapi
import idautils
import struct
#Constant definitions

#List of typical IDA function prefixes
IDA_FUNC_PREFIXES = {"sub","nullsub","j_nullsub","j_memset","j_memcmp"}

"""Checks whether only up to @num_bits bits is set in the @val"""
"""Returns True or False"""
def check_1_to_n_bits_set(val,num_bit):
	if num_bit==0:
		return val==0
	if num_bit<0:
		print "Number of bits %d is negative! Please pass parameter >= 0!" % num_bit
		return False
	else:
		counter = 0
		while(val!=0):
			val = val >> 1
			if(val & 1 == 1):
				counter+=1
			if counter>num_bit:
				return False		
		return counter > 0 and counter <= num_bit

"""Collects structs of the given @struct_name located between @from_ea and @to_ea into the list"""
"""By default, function uses @from_ea = MinEA() and @to_ea=MaxEA()"""
"""If invalid name or address is given, returns empty list"""
def collect_structs_ea(struct_name,from_ea=None,to_ea=None):
	if from_ea is None:
		from_ea=MinEA()
	if to_ea is None:
		to_ea = MaxEA()
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
		return list(DataRefsTo(struct_id))

"""Checks whether function at given @ea has a default name given by IDA"""
"""Note that @ea can be any address inside function scope"""
"""Returns boolean value"""
def is_default_function_name(ea):
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
		match = re.search("{0}_[{1},{2}]".format(prefix,min_num_digits_ea,max_num_digits_ea),func_name)
		if match:
			return True
	return False

"""Checks whether struct is defined at given @ea"""
"""Returns boolean value"""
def is_struct(ea):
	if ea < MinEA() or ea > MaxEA():
		print "%s is out of bounds!" % hex(ea)
		return False
	return isStruct(GetFlags(ea))

"""Returns set of tuples representing segments where each tuple is (segment_start_ea,segment_finish_ea)"""
def get_segment_ranges():
	segments = set()
	ea_pair = (FirstSeg(),SegEnd(FirstSeg()))
	while(NextSeg(ea_pair[1])!=BADADDR):
		segments.add(ea_pair)
		next_ea = NextSeg(ea_pair[1])
		ea_pair = (next_ea,SegEnd(next_ea))
	segments.add(ea_pair)
	return segments

"""undefines area from @ea till @ea+@length"""
def undefine(ea,length):
	if ea < MinEA() or ea > MaxEA() or ea+length > MaxEA():
		print "%s is out of bounds!" % hex(ea)
		return False
	MakeUnknown(ea,length,DOUNK_SIMPLE)	

"""Whilst IDA provides MakeStruct function, it won't define the required struct until all bytes to compose the struct are undefined"""
"""this function undefines required area first and defines the struct with @struct_name at @ea"""
def define_struct(ea,struct_name):
	if ea < MinEA() or ea > MaxEA():
		print "%s is out of bounds!" % hex(ea)
		return False
	struct_id = GetStrucIdByName(struct_name)
	if struct_id == -1:
		print "%s struct doesn't exist!" % struct_name
		return False
	struct_size = GetStrucSize(struct_id)
	undefine(ea,struct_size)
	MakeStructEx(ea,-1,struct_name)
