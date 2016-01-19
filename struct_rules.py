from abc import ABCMeta, abstractmethod
import collections
import ida_utils

"""Class that gives an abstract example of debug message classes"""
class DebMesRule(StructRule):
	__metaclass__ = ABCMeta

	#Constants definition

	"""Main method checking whether a given @ea can be converted to debug message struct"""
	def convert_to_struct(self,ea):
		pass

	def get_size(self):
		return 0xFF

	def get_name(self):
		return "DebugMessageStruct"

	#method definitions
	#...

"""Main abstract class that is used for defining rules for programmatically defining structures"""
class StructRule(object):
	__metaclass__ = ABCMeta

	@abstractmethod
	def convert_to_struct(self,ea):
		"""Main abstract method that every subclass should implement"""
		"""Determines whether given @ea can be converted to the struct of appropriate type"""
		pass

	@abstractmethod
	def get_size(self):
		"""Returns size of the struct in bytes"""
		pass

	@abstractmethod
	def get_name(self):
		"""Returns name of the struct"""
		pass