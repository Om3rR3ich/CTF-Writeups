# TreeBox

## Challenge Description
**Category**: Sandbox

**Description**: I think I finally got Python sandboxing right.

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





