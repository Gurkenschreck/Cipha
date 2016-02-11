# Cipha
Lightweight cryptography library

It is currently under active development. Do not use for actual applications.

Cipha is a portable link library. Some of the goals are:
* making a reusable library for other projects
* providing an easy interface for interacting with various cryptographic functions

Stuff I want to add in the future:
* a random sorting mechanism
* different implementations of file-wiping algorithms
* hdd-wiping functions
* support for one-time pads
* support for HMACs
* factories for creating pre-defined ciphers of similar cryptographic stength
* possible (ssl) networking support for file and/or message transfers
* documentation :^)

I am not building my own cryptographic functions, I am relying on the cryptographic implementation of .NET  

To take a deeper look on how to use it, simply browse the wiki or go through the unit
tests.
Each class has its own Test class, settled in a folder structured which is built parallel to the
source code.
