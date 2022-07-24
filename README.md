# REFLECTIVE DLL INJECTION

## About
I decided to write my POC about reflective dll injection in order
to learn how this technique works.

Reflective dll injection is a code injection technique that allows 
a process to inject code into another process. The main difference
between this technique and the classic dll injection, is that in this one
the dll that will be injected will be picked up from the ram rather than 
the disk.

To better understand how reflective dll injection works see [stephenfewer](https://github.com/stephenfewer/ReflectiveDLLInjection).

## Compile
Open reffDllInje.sln with visual studio and compile the project in release mode.

## Usage
>reffDllInje.exe to inject in current process

>reffDllInje.exe [pid] to inject in another process

## Additional information

Currently, only 32bit process are supported.
