# Linking tutorial
A step-by-step tutorial for low-level C++ linkage on Linux, meant for people with 0 C++ / low level knowledge.

Make sure you have a C++ compiler installed. On Ubuntu, you need to
```sudo apt-get install build-essential```
You also need `Python>=3.8`. Should be fine on any recent Ubuntu.

Run `./runme.py`.

At every step, the script will print the shell command used and explain what it's doing / why.

It will:
- generate a file containing binary data
- visualize its contents
- build a cpp file
- embed the data in the executable
- disassemble the executable
- show where the data is
- verify that everything is correct ☺
