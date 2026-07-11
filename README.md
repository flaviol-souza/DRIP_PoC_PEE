# DRIP_PoC_PEE
UNDER DEVELOPMENT
This repository contains the files of the PoC developed as part of my Master Thesis.
The PoC utilizes a ESP32 to broadcast the drone equivalent messages via wi-fi only (i couldn't make it work with the wifi and bluetooth modules active at the same time).
Them, the PC capture the packages via serial port (constrains with my PC wifi board, but i could see it using DroneRemoteID apps for android, so should be fine) using python scripts to decode and assert if the messages are valid or not (it can display some errors messages to help understand why the message was consider invalid).
As now the "drone" have it pub and private key hardcoded to facilitate test and experiments. It's expected to implement secure ways to store the privkey in the drone afterwards.


#OBSERVERFILES--------------------------------------------------------------------------------
Inside the ObserverFiles folder there is some interesting pythons scripts that is used in this project context:

ARDUINO_LOGGER.PY
The arduino_logger.py file is a python script that creates a text file named data_log.txt with the data that the arduino is transmitting in it's serial port.
For now it's used to catch the package that the ESP32 Drone is transmitting (it also broadcast via wi-fi but it was easy to capture the packages via serial because my computer wifi board don't support promiscuous mode).


OBSERVER.PY
To utilize the observer.py it's necessary to have a txt file in one of two formatations, the first one is the way the wireshark exports it's captured packages and the second one it's a specific way that my .ino code print's the packages. The observer only utilize the DRIP package to decode the information and verify the correctness of the messages but it's possible that without the headers it presents some problem.
To utilize the observer.py the commands are:

Run on your ESP32 serial log (the one captured from the serial port of the ESP)
python3 observer.py data_log.txt

Run verbose (shows every decoded message):
python3 observer.py data_log.txt --verbose

Enable DET↔key binding check (E-DET-02) — pass our public key:
python3 observer.py data_log.txt --pubkey 8B65B265A496E32046CFA378B5A5FB2E877A97723E557CB5F0D21848BFE94477 #-> This is the public key that I are using
	
Run on the test vectors file (the quickest demo):
python3 observer.py bytesonlytest2.txt

Run the full self-test (no file needed):
python3 make_vectors.py --selftest

KNOW BUGS:
When you run the arduino_logger.py script the ESP reset them start capturing the serial messages, it is good to garantee that none of the packages is missing from the log but it's bad to run some tests and have a problem with the way that different flight paths are implemented in the .ino file, i.e. the .ino file have some different flights paths available but they need to be selected via serial port. When the ESP32 is reseted it default to broadcast the 1st flight path available, this way for now i wasn't able to generate the map for the others flight path


MAKE_MAP.PY
This python script generates a .html file to display graphically the path of the drone using the captured data of a .txt file. It was only tested using the formatation that my .ino code generate using the arduino_logger.py file.
This file was made using as template the cyber-defence-campus/RemoteIDReceiver repository
To run the make_map.py you can use this command:

python3 make_map.py your_log.txt -o my_flight.html --title "Test flight 3"

The your_log.txt is the txt file that you want the graphic representation, the my_flight.html is the name that you want for the product (the map generated).
#---------------------------------------------------------------------------------------------

#DRIP_BROADCAST_RID---------------------------------------------------------------------------

In this folder you can find every file that is used by the ESP32.

The arduino library used are:
-Crypto by Rhys Weatherley [0.4.0]
-NimBLE-Arduino by h2zero [2.5.0] (i really don't remember if there is some bluetooth dead code but it was utilized during development and is still installed)
-Seeed_Arduino_mbedtls by Peter Yang [3.0.2]

The board used is the "ESP32 Dev Module" but i belive that it work with almost any ESP32 board

There are 23 flight's path at the user disposition to use, everyone of them is near the Interlagos Race Track. 

When reseted (be by the button or by power on) the ESP32 start broadcasting the flight path number 0. By typing "stop" in the serial monitor it display the bellow information

[Playback] Choose a flight to start transmitting again:
             <number>   select and start that flight
             reset      replay the current flight
             list       show all flights
===========================================================
[Playback] Available flights:
   0 : 0M63J2T001H037         270 pts  (~7.8 min real time)  <= selected
   1 : 0M6CG9QR0A0FD6         843 pts  (~124.6 min real time)
   2 : 1ZNBK5900C00A8        1032 pts  (~77.0 min real time)
   3 : 3NZCHCP0043PS1         330 pts  (~1.8 min real time)
   4 : 4GCCK6QR0B0QRZ         595 pts  (~2894.3 min real time)
   5 : 5FSCK320115HYT         513 pts  (~5.9 min real time)
   6 : F4XF82391006Q24L       135 pts  (~0.7 min real time)
   7 : F5BKB246700F00DV       177 pts  (~3.7 min real time)
   8 : F5FJC248L00D6GD3       765 pts  (~1549.5 min real time)
   9 : F5FJC248M00DXTG9       378 pts  (~2.9 min real time)
  10 : F67QC234U01429M1       180 pts  (~1069.1 min real time)
  11 : F6Z9A23BHML35V6J      1062 pts  (~13.3 min real time)
  12 : F6Z9A24AAML33B85      1074 pts  (~2927.7 min real time)
  13 : F6Z9C23A7003A3HF       117 pts  (~0.7 min real time)
  14 : F6Z9C23AB003BTNG       408 pts  (~2.4 min real time)
  15 : F6Z9C23AR003DHVF        93 pts  (~0.5 min real time)
  16 : F6Z9C24B60035ER9       916 pts  (~9.3 min real time)
  17 : F8PJC246L0004BAG       285 pts  (~4.0 min real time)
  18 : F986C254E0020E5T       732 pts  (~22.8 min real time)
  19 : F9DEC258M029H723       264 pts  (~6.7 min real time)
  20 : F9DEC259A029P8S8       209 pts  (~5.7 min real time)
  21 : KCG0021GGR             237 pts  (~3.0 min real time)
  22 : MissionAlpha          1019 pts  (~0.0 min real time)
  23 : encrypted              194 pts  (~2901.8 min real time)
[Playback] Type a number to select, or 'list' | 'info' | 'next' | 'reset'.

I this implementation the pub and priv key are hardcoded and can be easily changed.
For each of this flight path is possible to determine an different pub and private key but as it is now they all shake the same pair.

KNOWBUG: The estimate time of each flight isn't correct with relation to the real time that each one broadcast, it's in the list of improvements of the project
#---------------------------------------------------------------------------------------------

#OUTDATED-------------------------------------------------------------------------------------

This folder contains only two files, an .ino one and a .py.
These files is to utilize a second ESP32 board to capture the packages that the first board (the "drone") is broadcasting and make available to the PC via serial interface so the wireshark can receive the packages like it was capturing using he wi-fi board.

There is no guarantee that this contraption work as intended and the last test using it was months ago but it is provided in this repository as there is chance that it will be necessary later and to permit contributions from others.

To use it run the command below:
python bridge.py COM3 921600 | "C:\Program Files\Wireshark\Wireshark.exe" -k -i -