# Program for injecting code into windows PE executables

Injected code is appended after original code (leveraging fact that SizeOfRawData and VirtualSize could be different) 
and changing Address of entry point in PE structure. Program also adds jump instruction after appended code to pass control to
original code.
