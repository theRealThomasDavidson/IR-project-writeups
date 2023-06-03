# Project 1
#### Thomas Davidson

### Overview 
You are called in as a 3rd party consultant to a company. This company had an IT person being trained in Security
 downloading a link from a training resource. Soon after, the training resource website alerted it's users that it
  had a security breach and that links from it's website may have contained malicious code. You have been given a
   memory dump (.raw file) and a .pcap file from the virtual machine that the link was downloaded to. 

Well one of the questions in IR is always "What was the root cause of this breach?". int his case the answer is
 pretty straight forward. so we know one thing lets carry on to our next steps. 

### Initial Findings
after copying the files to my kali vm and making a folder for them I check to make sure they got there. 

    $ cd project1/
    $ ls -al
        total 1600500
        drwxr-xr-x  2 skillsuser skillsuser       4096 Mar  9  2020 .
        drwxr-xr-x 17 skillsuser skillsuser       4096 May 24 14:06 ..
        -rw-r--r--  1 skillsuser skillsuser   28283671 Mar  9  2020 project1.pcap
        -rw-r--r--  1 skillsuser skillsuser 1610612736 Mar  9  2020 project1.raw

They look good. 
Lets get our zeek logs and get a broad swath to look through. (this could have been done in wireshark but i wanted to
 make sure the zeek logs were there.)

    $ mkdir zeek && cd zeek
    $ sudo zeek -r ../project1.pcap 
    $ ls
        conn.log  dhcp.log  dns.log  dpd.log  files.log  http.log  packet_filter.log  ssl.log  weird.log  x509.log
    $ sudo zeek-cut < conn.log ts history id.orig_h id.orig_p id.resp_h id.resp_p proto duration > firstcut.txt

In the initial findings I found a few lines that looked suspicious. 

    timestamp               history originIP        :Port   destinationIP   :Port   protocol    duration
    1581717069.790101       DA      192.168.248.200 4444    192.168.248.100 49792   tcp         143.147936
    1581717223.669467       DA      192.168.248.200 7777    192.168.248.100 49793   tcp         46.618496
    1581717273.620527       AD      192.168.248.200 9999    192.168.248.100 49794   tcp         129.936901

These packets were suspisious because they showed long durations weird handshake history, weird ports all from the
 same IP address on the same subnet probably.

The next bit I did probably isn't important but if you find a lot of traffic to a port that is sub 1024 maybe google
 the port number before you spend 30 minutes looking at port 53 traffic before noticing they are all dns requests. 

when looking into Wireshark later I was able to uncover a POST request to a 192.168.217 for /dvwa/login.php the form
 included an item "username" with "admin" showing in plain text, additionally it had an item "password" with "admin
 " showing in plain text too. Apparently I'm not looking at xss or sql injection the ingress was simply plaintext
  passwords that are beaten by rockyou.txt being put unaltered into the username and password at the same time. This
   is replied to with a 302 found response. 
   
Looking more into this this was an instance of "Damn Vulnerable Web Application"? https://github.com/digininja/DVWA
So, I guess this is where the untrusted program was housed. 

Looking for all the connections our machine had with the this vulnerable app we find. 

     $ zeek-cut http.log < conn.log ts history id.orig_h id.orig_p id.resp_h id.resp_p proto duration |grep 192.168
     .248.217
        1581716976.664506       ^hadf   192.168.248.100 49784   192.168.248.217 80      tcp     18.582396
        1581716976.706922       ^hadf   192.168.248.100 49785   192.168.248.217 80      tcp     20.439976

Mostly just longer web traffic connections. 


### Moving Forward with wireshark

Next I moved on to wireshark and got the particulars of some of the streams

I wanted to look at the suspicious quad ports (four consecutive same digits) starting with the lowest number
  quadquad(4444).

In wiresharks filterbar I put:

    tcp.port == 4444

I followed the single tcp stream that was there and looked at the payload and the packets. 

    tcp.stream eq 392

[The contents](1ststream.txt) of stream look like a remote unecrypted shell probably powershell.

We look through the commands and seee that the shell is a bit obfuscated, but we get a long base64 string that is
 loaded into %TEMP%\FMEGz.b64 over several commands by appending to the file. 
 
 after thebase 64 we get things like 
 
    Set fs = CreateObject("Scripting.FileSystemObject") 
    Set file = fs.GetFile("%TEMP%\FMEGz.b64")
    If file.Size Then 
    Set fd = fs.OpenTextFile("%TEMP%\FMEGz.b64", 1) 
    
 copied into %TEMP%\xLLRe.vbs as well as more I will copy this deobfuscated vbscript into project1/xLLRe.nvbs
 
basically from what i can get on a quick scan of the file:
- this is a vbscript
- first it tries to get the base64 data from the file "%TEMP%\FMEGz.b64"
- creates a file "%TEMP%\mXvtj.exe". checks if it is already built before builing a new one. 
- while the data is in memory it processes a bit of the data then runs a function "base64_decode": described later in
 the file but pretty streaightforward. 
- it then takes the decoded data and writes it to "%TEMP%\mXvtj.exe"
- we have a function "base64_decode" that :builds a new file in using mimedecode for 4 base64characters at a time
 there is a bit of obfuscating here. 
- we have a function "mimedecode" that does the actual base 64 decodeing and writes it to "%TEMP%\mXvtj.exe"

[Deobfuscated code](xLLRe.nvbs)

cool now that we look into the next quad connection qaudseven(7777) 
filters:

   tcp.port == 7777
   tcp.stream eq 399

This downloaded a file that at the top of it was written "This program cannot be run in DOS mode." indicating that it is a windows binary. 


cool now that we look into the next quad connection quadnine(9999) 
filters:

   tcp.port == 9999
   tcp.stream eq 400

this downloaded a file that at the top of it was written "This program cannot be run in DOS mode." indicating that it is a windows binary. 

I looked into putting these files into strings. Eventually, I ended up with a command that gave me :

    $ strings quadseven.bin | grep Netscape -n        
        6725:Netscape Server Gated Crypto
        6826:Netscape Certificate Sequence
        6828:Netscape Comment
        6830:Netscape SSL Server Name
        6832:Netscape CA Policy Url
        6834:Netscape Renewal Url
        6836:Netscape CA Revocation Url
        6838:Netscape Revocation Url
        6840:Netscape Base Url
        6842:Netscape Cert Type
        6862:Netscape Data Type
        6864:Netscape Certificate Extension
        6866:Netscape Communications Corp.
        6867:Netscape
        6952:Netscape SSL server
        8516:d2i_Netscape_RSA

Notably, the line numbers for all of these strings were the same between the two files. So I did a hash of the fiels
 as a last item for this rabbit hole
 
    $ sha1sum quadnine.bin                    
        282f3443b0c6781d3eebf2cc14684a856adf1caf  quadnine.bin                                                                                                                                                 
    $ sha1sum quadseven.bin 
        1c1d84bba53264906242325efb7b0299cd197b8c  quadseven.bin

They are, in fact, different files. 

This has been fun, but I don't think looking more at these is going to crack the case wide open soon. 


### Memory dump 

So, we initally profile the system and get Win7SP1x86_23418 as a likely profile.

I want to start by checking out all the processes and do it in a pstree 

    $ sudo volatility -f project1.raw --profile=Win7SP1x86_23418 pstree
    
2 branches that stick out to me immediately
     
     0x85ea33a8:mXvtj.exe                                2644   3796      1     25 2020-02-14 21:50:57 UTC+0000
    . 0x84988a58:cmd.exe                                 2676   2644      1     23 2020-02-14 21:50:58 UTC+0000
    .. 0x84816030:ghost.exe                              3132   2676      3    106 2020-02-14 21:53:32 UTC+0000
    ... 0x846c9bf8:eDqYEC.exe                            2472   3132      5     49 2020-02-14 21:54:26 UTC+0000
    
     0x849db030:tior.exe                                  764    228      4     23 2020-02-14 21:54:27 UTC+0000
    . 0x86176030:cmd.exe                                 4052    764      1     25 2020-02-14 21:54:27 UTC+0000
    .. 0x849a6030:HgRgTVSdX.exe                          3324   4052      2    107 2020-02-14 21:54:27 UTC+0000
    ... 0x846dbd40:notepad.exe                           1492   3324      3    132 2020-02-14 21:54:29 UTC+0000

One of these is random letters piping into a shell that executes other nonrecognized programs which also run a random
 letters executable. If you are the type of person who memorizes phonetically every random string (or if you can
  press ctrl+f) you may notice that the first branch of the pstree contains mXvtj.exe which was made with the
   quadquad connection. ghost.exe is probably a C2 controller. 
   
The second process branch that stuck out to me did so because of the cmd and notepad which are both Living off the
 Land binaries (LoLbins) these are named as such because they can potentially contain helpful tools for threat actors
  to do what they want after gaining access to a shell. 

But, I didn't know a lot about tior.exe so I googled it as it phonetically makes sense so I thought it might not be a
 random collection of letters. and lo and behold. tior is a module that can be run in metasploit.

https://github.com/rapid7/metasploit-framework/blob/master/external/source/exploits/bypassuac/Win7Elevate/Win7Elevate.cpp

We see that this is in the Windows 7 Elevate bit so I think we can assume that our threat actor has at least admin
 privileges 
 
notes from the author:
 
    //	By Pavels
    //
    //	This application is used for redirection data from the console to the pipes, 
    //	not useng pipes at the other side.
    //	It is caused by some differences when using some other proceses which
    //	also redirect data. Main reason is differences in ReadConsole and ReadFile
    //	methods.
    //	Using this redirector app, child process will never know that his parent redirects it's IO.
    //
    //	Everything is asynchronous. 3 Threads.

Cool, overall I want to look into removing the processes above that are malicious, but if i remove things like cmd.exe
 if it is legitimate. So I dumped the binaries that executed the processes and put them into VirusTotal (instead of
  using my own limited antivirus). 
  
I was able to dump the proccess bins by Process ID(PID) with the command:
    
    $ sudo volatility -f ./project1.raw --profile=Win7SP1x86_23418 procdump -D ./volatility/ -p {PID}

I found that mXvtj.exe, ghost.exe, eDqYEC.exe, tior.exe, HgRgTVSdX.exe are probably malicious.

I found that cmd.exe(x2), and notepad.exe were probably not malicious. 



### Root Cause:
This was introduced to the subnet as described in the overview. this particular computer got infected by accessing
 the compromised dvwa. 

### Containment Recommendations:
192.169.248.200 is either hosting or being a proxy for malicous code that gives someone else remote command of
 target computers. I would try to grab a memdump of this computer, and disconnect it from the network, soon after
  disconnecting it from the network I would try to set up a honeypot for our own network on this ip address on
   all ports. If critical code runs on the computer we might want to try to sniff traffic and filter on all quad
    ports not just the three we saw.
192.168.248.100 had a .pcap and a memdump done so that we could start on this project. It potentially could
 become the next proxy for hosting malware like .200 so I would reccomend disconnecting it from the network if
  possible. reimage a new computer to do it's job otherwise. 
192.168.248.217 is hosting possibly malicious code on port 8080 this should be removed from the network
 immediately. And a memdump and hard drive image should be taken. If this virtual machine was running on a
  network with a sniffer on it we should look into any computers who accessed it via port 8080. We can narrow it
   down a bit by trying to see what each of them accessed, to make sure they did not download anything that
    executes, but it is an area for further Investigation. 

### Eradication Reccomendations:

Given that a metasploit privilege escalation process was running on our computer that could possibly give system
 access I think for this computer we would need to reimage the hard drive to be relatively certain that the whole
  infection was gone. For the other computers I wouldn't have specific reccomendations until I got the memdump. 
  
### Lessons Learned 

Windows 7 Extended Security updates officially stopped on Jan. 10, 2023. We aren't just talking about
 misconfigurations in your setup these days this is unpached 0-days and more. There needs to be a specific
  recommendation to the people who can make decisions to switch to another OS that is currently fully supported
  . Windows 10 and 11 can be the general workhorses that windows 7 was and can be used as bloated workstations or
   bloated servers, but linux alpine might be okay for servers but more work will be needed for the transition, and
    workstations are typically going to be windows 11 or MacOS 13.

The root cause of this was a webapp that was supposed to be used for security testing, but got comprimised. I would
 recommend keeping a small subnet for training that is logically seperated from production. You can additionally
  create another level of protection by issueing a policy of using a prepared virtual machine for security related
   tasks, as well as strong warnings about copying files from your vm to your computer. 
   