# Incident Response Project Write-up

#### Thomas Davidson

## Introduction

In recent weeks I've been working toward getting the foundations needed for a cyber security career. This is delving into some Blue Team Stuff. So basically I did a ~20 hr course in Incident Response (IR) for InfoSecAcademy which included a few projects (One of them was just a skill lecture as a cyber range). Of those projects two of them seemed like good candidates to do a writeup to highlight what I learned in the course. 

These two projects were focused on the identification stage of IR, but for this writeup I will give a brief overview of recommendations for Containment and Eradication at the end of the Identification portion.

## The (tool)Box

So during the lecture portion I was able to install the packages as needed to play along with syntax and to make sure my notes made sense. But, for the projects We were given a Kali linux virtual machine configuration as a .ova file. I was able to run it pretty easily in VMware Workstation17 Player. it had limited memory and I think only 1 hyper threaded core running or maybe 2 cpu cores I didn't check. But more importantly it contained a few additional tools that are not available for your KaliTools standard install I will go over these tools below. 

### Zeek

Zeek is a tool to analyze .pcap files. Zeek itself will take a .pcap file and create .log text files that can be taken with a companion tool zeek-cut to create command line output that can be taken with grep or sort of other linux utilities to filter down and highlight potentials Indicators of Compromise (IoC), or any evidence that your computer may be being exploited. 

Overall Zeek is pretty helpful early on and for recording evidence, but I usually prefer the next tool for looking at, collecting, and filtering  the particulars of packets in .pcap files. 

### Wireshark

This tool is luckily available in Kali Linux tools! So, if you are running kali you can sudo apt update && upgrade and usually it just works!

Wireshark is a GUI tool for viewing .pcap files. it loads things once and lets you play with them which is great for quick feedback. It has  extensive and well-trafficked filter options with pretty good documentation so when learning this you often get both good notes from "https://www.wireshark.org/docs/" and from stack exchange making this probably one of the easiest things to learn. Overall it has a lot of overlap with zeek and using both can aid in making your evidence gathering about saved packets fairly straightforward. 

### Volatility

Volatility is a tool to analyze memory dumps. Memory dumps are often the first intentionally collected evidence of a machine that has been showing IoCs. This is because memory is only really available at one particular point in time and if a threat actor recognizes that you are collecting evidence off the computer and decides to cover up, memory is the fasted to be overwritten, also you don't want to wade through your other tools in system memory, so it is urgent to get a memory dump before other evidence is gathered. 

Basically volatility can look at memory dumps and tell you what processes are running, give you an image type of a machine (mostly this is just to inform your volatility syntax), look at command line history, and look at internet connections and their status. 

## Project 1

[Project 1 writeup](project1/README.md)

This writeup may contain the following:some use of all described tools, some incomplete deobfuscation, some looking up
 if a file is known to the security section of the internet. 
 
## Project 2

[Project 2 writeup](project2/README.md)

