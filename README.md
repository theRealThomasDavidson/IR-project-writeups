# Incident Response Project Write-up

#### Thomas Davidson

## Introduction

I have recently been working towards establishing the foundations for a career in cybersecurity, particularly focusing on Blue Team operations.  As part of this pursuit, I completed a ~20-hour Incident Response (IR) course offered by InfoSecAcademy. The course included several projects, and I have chosen two of them to write about and highlight the key learnings.

These projects primarily centered around the identification stage of IR. In this writeup, I will provide a brief overview of the recommendations for containment and eradication, which will be presented at the end of the Identification section."

## The (tool)Box

During the lecture portion, I installed the necessary packages to follow along with the syntax and ensure that my notes were coherent. However, for the projects, we were provided with a Kali Linux virtual machine configuration in the form of a .ova file. Running it in VMware Workstation 17 Player was a straightforward process. The virtual machine had limited memory, and I believe it was running on either 1 hyper-threaded core or possibly 2 CPU cores (I didn't verify the exact configuration). Most importantly, the virtual machine included several additional tools that are not available in the standard KaliTools installation. I will discuss these tools in more detail below.

### Zeek

Zeek is a tool designed for the analysis of packet captures (.pcap) . When provided with a .pcap file, Zeek generates .log text files. These log files can be processed using the companion tool zeek-cut, allowing for command line output that can be further filtered using utilities like grep or other Linux tools. This enables the identification and highlighting of potential Indicators of Compromise (IoC) or any evidence indicating that your computer may be compromised or exploited.

While Zeek is particularly useful in the early stages of analysis and evidence collection, I personally tend to favor the next tool for examining, gathering, and filtering specific packet details within .pcap files.

### Wireshark

This tool is luckily available in Kali Linux tools! So, if you are running kali you can "sudo apt update && sudo apt upgrade -y" and usually it just works!

Wireshark is a graphical user interface (GUI) tool designed for viewing .pcap files. It loads the files once and allows you to interact with them, providing quick feedback during the analysis process. Wireshark offers a wide range of filter options, which are extensively documented and often supported by the Wireshark community. You can find useful notes and information on the official Wireshark documentation at "https://www.wireshark.org/docs/" as well as on various Stack Exchange platforms. As a result, learning and utilizing Wireshark is generally considered one of the easier aspects of packet analysis. There is significant overlap between Wireshark and Zeek, and leveraging both tools can greatly facilitate the process of gathering evidence from saved packets.

### Volatility

Volatility is a tool specifically designed for analyzing memory dumps. Memory dumps are often the initial evidence collected from a compromised machine exhibiting Indicators of Compromise (IoCs). Memory captures the system state at a specific moment in time, and if an attacker becomes aware of your evidence collection efforts and attempts to cover their tracks, the memory is the fastest component to be overwritten. Therefore, it is crucial to acquire a memory dump as quickly as possible before other evidence is gathered. This ensures that you have a snapshot of the system's memory for analysis.

Volatility allows you to examine memory dumps and extract valuable information. It can provide insights into the running processes, provide details about the machine's image type (which primarily assists in determining the appropriate volatility syntax), review command line history, and inspect internet connections and their statuses.

## Project 1

[Project 1 writeup](project1/README.md)

This writeup may contain the following: utilization of all the described tools, partial deobfuscation, and cross-referencing files against known security resources on the internet.
 
## Project 2

[Project 2 writeup](project2/README.md)

This writeup may contain the following: identification of SQL injection attacks, investigation of reverse shells, and potentially mentions of a chupacabra (for unknown reasons).
