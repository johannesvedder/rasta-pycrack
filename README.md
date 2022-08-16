# RaSTA-Pycrack

## Summary
Wraps the [hashcat-rasta](https://github.com/WorldofJARcraft/hashcat) hashcat module.  
Can be used to extract a safety code and corresponding PDU from a RaSTA connection that was captured with WireShark and execute dictionary attacks using hashcat against the safety code's secret initialization vector.

## Installation
0. While scapy is multi-platform and works fine on Windows, hashcat requires GNU buildtools (e.g. gcc, make) for compilation. It can be cross-compiled to a Windows native binary however, see the BUILD\_WSL.md (BUILD\_CYGWIN.md / BUILD\_MSYS2.md) documentation in hashcat for details.
1. Install [scapy](https://github.com/secdev/scapy), at least version 2.4.5, from source. Currently, the pip package ships a broken version of the package that leads to the script failing.
2. Install [hashcat](https://github.com/WorldofJARcraft/hashcat) from source as documented in the BUILD.md (see step 0). 
3. On platforms other than Windows, be sure to `make install` and add */usr/local/bin* to your path (default hashcat installation path).
4. On Windows, copy the contents of this directory into hashcat's top level directory.

## Using the wrapper
The wrapper accepts the following arguments:
 - -f (mandatory): filepath to dump to analyze in pcap format
 - -c (optional): if given, output extracted PDU and safety code in a format suitable for a hashcat hash file to console
 - -w (optional): path to hashcat wordlist for dictionary attack
 - -p (optional): hashcat pattern for pattern attack

The script will cash extracted PDUs and safety codes in a pickle file *rasta.p*, make sure to delete it when using a different dump.  
Also, note that the hashcat arguments used in the wrapper are suitable for demonstration purposes and not optimized for speed. See the source code and the hashcat documentation for parameters suitable for your needs.
