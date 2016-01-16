import idautils
import idaapi
from abc import ABCMeta, abstractmethod
#from ida_utils import check_one_bit_set,get_bytes_value


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

"""returns value of bytes between @ea and @ea+@length"""
def get_bytes_value(ea,length):
	if ea < MinEA() or ea > MaxEA():
		print "%s is out of bounds!" % hex(ea)
		return False
	byte_str = None
	for addr in range(ea,ea+length):
		byte_str += struct.pack("4B",Byte(addr))
	return struct.unpack("<L",byte_str)[0]

""""""
class DebMesRule(object):

	#line number field offset and length in TDebMes struct
	LINE_NUM_OFF = 0x0
	LINE_NUM_LEN = 2
	#SSID field offset and length in TDebMes struct
	SSID_OFF = 0x2
	SSID_LEN = 2
	#SS mask field offset and length in TDebMes struct
	SSMASK_OFF = 0x4
	SSMASK_LEN = 4

	def can_convert_to_struct(self,ea):
		return self.__is_valid_line_num(ea+self.LINE_NUM_OFF,self.LINE_NUM_LEN) and self.__is_valid_ssmask(ea+self.SSMASK_OFF,self.SSMASK_LEN)

	"""Line number in debug message structs have to be > 0"""
	def __is_valid_line_num(self,ea,length):
		line_num = get_bytes_value(ea,length)
		if line_num:
			return True	
		else:
			print "Error retrieving bytes from %s" % hex(ea)
			return False

	"""SS masks in debug message structs are numbers that are 2^{@length}"""
	def __is_valid_ssmask(self,ea,length):
		return check_one_bit_set(get_bytes_value(ea,length))

""""""
class TDebMesHashedRule(DebMesRule):

	def can_convert_to_struct(self,ea):
		return super(TDebMesHashedRule,self).can_convert_to_struct(ea)

""""""
class TDebMesRule(DebMesRule):

	#filename field offset and length in TDebMes struct
	FN_OFFSET = 0xC
	FN_MIN_LEN = 5
	FN_MAX_LEN = 20

	""""""
	def can_convert_to_struct(self,ea):
		return super(TDebMesRule,self).can_convert_to_struct(ea) and self.__is_valid_fn(ea+self.FN_OFFSET)

	"""Every TDebMes struct has associated filename string pointer"""
	"""Checks whether 4 bytes at @ea point to valid filename string"""
	def __is_valid_fn(self,ea):
		if ea < MinEA() or ea > MaxEA():
			print "%s is out of bounds!" % hex(ea)
			return False
		fn=GetString(Dword(ea),-1,ASCSTR_C)
		if fn:
			if len(fn)>=self.FN_MIN_LEN and len(fn)<=self.FN_MAX_LEN and ".c" in fn:
				return True
		return False


"""Main abstract class that is used for defining rules for programmatically defining structures"""
class StructRule(object):
	__metaclass__ = ABCMeta

	@abstractmethod
	def can_convert_to_struct(self,ea):
		"""Main abstract method that every subclass should implement"""
		"""Determines whether given @ea can be converted to the struct of appropriate type"""
		return

StructRule.register(DebMesRule)