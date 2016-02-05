# Cipha
Lightweight cryptography library

Check out the develop branch. That is where the changes are made.

Cipha is a portable link library. Some of the goals are:
* making a reusable library for other projects
* learn more about cryptography
* learn more about design patterns
* learn more about unit testing

Stuff I want to add in the future:
* a generic class for asymmetric encryption
* a random number/string/sorting mechanism
* some sort of mechanism to flush the currently free ram memory
* different implementations of file-wiping algorithms
* talking about that, different implementations of hdd-wiping mechanisms
* possible (ssl) networking support for file and/or message transfers
* documentation :^)

I am relying on the native .NET implementations which are pretty much rock-solid.

To take a deeper look on how to use it, simply browse the wiki or go through the unit
tests.
Each class has its own Test class, settled in a folder structured which is built parallel to the
source code.
