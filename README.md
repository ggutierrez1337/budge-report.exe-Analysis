# Malware Analysis of budget-report.exe

# Overview
This is a Static and Dynamic Analysis of a malware sample **budget-report.exe.** The sample was evaluated for IOCs, potential capabilities, persistence mechanisms, evasion techniques, C2 communication and network behavior.

# Tools and Utilities

- **PEStudio**: PE structure and import analysis
- **TridNet**: File type identification
- **FLOSS**: String deobfuscation
- **Capa**: Detection of ATT&CK techniques and capabilities
- **HashMyFile**: Hash extraction (MD5, SHA1, SHA256)
- **VirusTotal**: Malware reputation verification
- **Regshot**: Registry and file system diff tool
- **Fakenet-NG**: Network simulation and C2 trap
- **Procmon**: System API monitoring and event tracing
- **Procdot**: Visual correlation of Procmon and PCAP data
- **Wireshark**: PCAP analysis for C2 communications

# Static Analysis Steps

1. Check the file **extension** and file **icon**
2. Check the file **type**
3. Check the PE Header with pestudio
4. Use Floss to check for obfuscated code and decoding
5. Run Capa to view what Techniques were used as well as Capabilities
6. Attain the hash with either Capa or HashMyFile and confirm with VirusTotal

# Malware Details

## Metadata

| File Name | budget-report.exe |
| --- | --- |
| Size | 419328 bytes |
| MD5 | d7cc6c987c68a88defdab3a59070777e |
| SHA-1 | c1beec6f6b8cc01fc093ac896d33f89f885e7d07 |
| SHA-256 | 15cc3cad7aec406a9ec93554c9eaf0bfbcc740bef9d52dbc32bf559e90f53fee |

# Static Analysis

1. Upon first glance of the malware sample, it can be noted that a **fake Adobe** icon was used with the malware and a file extension of **.exe.** This is not normal because common Adobe extensions include: **.ai, .jpg, .pdf, .indd, .psd.** Never .exe

![image](https://github.com/user-attachments/assets/143dab87-a149-41f6-a123-7377301e0891)


2. Using **TridNet**, check the file type to confirm that this file is an **executable.** There is a an 81.8% match of this file being an executable

![image 1](https://github.com/user-attachments/assets/05ee762d-cadd-428b-b29f-e309e99ff696)


3. Next, use pestudio to analyze the **PE Header**. Drag and drop the malware sample into **pestudio**. Observing the output, the following indicators of malicious activity can be found:
    
    **57/72** AV Vendors have a signature for this malware
    
    ![Screenshot_(1481)](https://github.com/user-attachments/assets/f0611a68-cc1d-4036-a315-3f9e4776fdb1)

    
    This file has write, execute, and **virtual** characteristics
    
    ![Screenshot_(1480)](https://github.com/user-attachments/assets/601b961a-a4fb-42a0-be29-cba72027043c)

    
    Checking the **file-header,** the **timestamp** specifies Wed Oct 14, 08:31:48 1998 (UTC), but this can be falsified using tools such as **timestomp**
    
    ![image 2](https://github.com/user-attachments/assets/1ee182e9-278a-4309-bbab-8603ab8e71e3)

    
    The Libraries tab shows what DLL libraries this malware uses. The main libraries being,
    
    - **ADVAPI32.DLL -** Provides access advanced system functions such as interacting with the registry, handling user accounts, starting/stopping services, and security operations
    - **KERNEL32.dll** - Manage system level tasks such as memory allocation/deallocation and handling input/output as well as interacting with the kernel
    - **WININET.DLL** - Provides an interface for applications to interact with the internet mainly using FTP and HTTP
    - **User32.dll** - Manages user interface elements on Windows Machines
    - **SHELL32.DLL** - Provides function for Windows shell to interact with Windows elements, file system, Explorer, etc
    - **WS2_32.dll** - Provides core functionality for Windows Socket Networking especially with TCP/IP Protocols

From all the libraries combined, there are **190 imports** in total with **56 Imports** being flagged

**Note -** This malware is not packed as if it were, very few functions would be shown as imported

![image 3](https://github.com/user-attachments/assets/60672c55-759e-43eb-a723-a6f399c78b50)


Has **56 API Imports** utilizing the DLL Libraries (KERNEL32.dll, WININET.DLL, User32.dll, SHELL32.dll)

![Screenshot_(1484)](https://github.com/user-attachments/assets/ef15454d-22ef-4162-aafc-3863308e15ec)


In the string section, there are various suspicious values this malware uses, but those that stand out the most would include network-related, Registry tampering, and file/process creation/deletion APIs because a “budget-report” file should have no need to do such especially interacting with the internet

![image 4](https://github.com/user-attachments/assets/8dc64f10-acc3-4273-b8c5-9042d655ed4c)


![image 5](https://github.com/user-attachments/assets/fb891f27-ebeb-4c81-89e1-491ee4e0c0f2)


String encoding using base-64 was also found in this file in attempts to potentially obfuscate malicious commands 

![image 6](https://github.com/user-attachments/assets/075c80a3-5309-437e-8067-52d4a6d8eb4d)


![image 7](https://github.com/user-attachments/assets/d77c3cae-c510-4381-b4ad-099142700a18)


## Analysis of Extracted Strings from pestudio

| **String** | **DLL Library**  | **String Function** |
| --- | --- | --- |
| AdjustTokenPrivileges | ADVAPI32.DLL | Enables and disables privileges within an access token allowing processes to perform SYSTEM Level actions that would not be able to without |
| BuildExplicitAccessWithNameA | ADVAPI32.DLL | Initializes the the EXPLICIT_ACCESS structure defining who (trustee) can access the file and what (Access Control) they can do with it |
| LookupPrivilegeValueA | ADVAPI32.DLL | Retrieves the Local Unique Identifier (LUID)  to specify the given privileges of an object |
| OpenProcessToken | ADVAPI32.DLL | Opens the access token associated with the process which retrieves the handle pertaining to security context (User, access, etc), and can also be modified, query, or adjust to create new tokens |
| RegCreateKeyExA | ADVAPI32.DLL | Creates or opens the registry key. If the key is already created, the function will open it |
| RegDeleteValueA | ADVAPI32.DLL | Used to remove registry data/values from a specified registry key |
| RegFlushKey | ADVAPI32.DLL | Flushes the changed data of a specific registry key to storage/disk instead of memory  |
| RegSetValueExA | ADVAPI32.DLL | Sets the data for a registry Key |
| SetEntriesInAclA | ADVAPI32.DLL | Creates a new ACL by merging new access control or audit information into an existing ACL |
| SetKernelObjectSecurity | ADVAPI32.DLL | Specification/Modification for the security descriptor of kernel level objects such as processes, threads, events and who the owner is, what group it’s apart, of and ACLs |
| SetNamedSecurityInfoA | ADVAPI32.DLL | Set specified security descriptor/attributes of a given object (owner, group, ACL) |
| AddAtomA | KERNEL32.dll | Adds a character string to the atom table which will return a unique value to identify the string. Used to store executable code |
| CopyFileA | KERNEL32.dll | Copies the content of a source file to a destination file |
| CreateDirectoryA | KERNEL32.dll | Creates a new Directory |
| CreateProcessA | KERNEL32.dll | Creates a Process independent of the parent process |
| CreateToolhelp32Snapshot | KERNEL32.dll | Creates a snapshot of system’s processes, threads, modules, and heaps which can be used to enumerate system information  |
| DeleteFileA | KERNEL32.dll | Deletes an existing file |
| FindAtomA | KERNEL32.dll | Searches the atom table for a specified string and returns the atom associated with that string which could be executable code |
| FindFirstFileA | KERNEL32.dll | Opens the search handle and returns information about the first file that name matches the specified pattern in the file system |
| FindNextFileA | KERNEL32.dll | Retrieves the next file in the file system that matches the search criteria |
| GetAtomNameA | KERNEL32.dll | Retrieves a copy of the character string associated with a specific atom |
| GetCurrentProcess | KERNEL32.dll | Returns the process handle of a process |
| GetCurrentProcessId | KERNEL32.dll | Retrieves the Process ID of a given process |
| GetCurrentThread | KERNEL32.dll | Returns the handle of a thread executing code  |
| GetCurrentThreadId | KERNEL32.dll | Provides the thread ID that is executing a specific function |
| GetThreadContext | KERNEL32.dll | Returns the thread context of a thread |
| GetThreadPriority | KERNEL32.dll | Retrieves the priority value of a thread |
| GlobalMemoryStatus | KERNEL32.dll | Provides current state of the physical and virtual memory space |
| Module32First | KERNEL32.dll | Information pertaining to the first module of a process |
| Module32Next | KERNEL32.dll | Returns the next module associated with a process or thread |
| MoveFileExA | KERNEL32.dll | Copies a source file to a new location and deletes the original file once done |
| OpenProcess | KERNEL32.dll | Returns the handle of a specific process |
| Process32First | KERNEL32.dll | Retrieves the first process and its information (PID, PPID, Process Name) of a system snapshot |
| Process32Next | KERNEL32.dll | Retrieves the information of the next process in a system snapshot |
| SetFileAttributesA | KERNEL32.dll | Provides file system attributes (Name, owner, group, read status, hidden) |
| SetProcessAffinityMask | KERNEL32.dll | Sets the process affinity mask (bit vector to specify which process run on CPU cores) of processes with threads only in a single process group |
| SetThreadContext | KERNEL32.dll | Sets the context of a thread such as execution state, stack pointer, and program counter |
| SuspendThread | KERNEL32.dll | Suspends the execution of a thread essentially pausing its process |
| VirtualProtect | KERNEL32.dll | Changes the protection of region of memory in the virtual address space usually to allow execution or write |
| VirtualQuery | KERNEL32.dll | Queries information of about a region in memory within the current process’s address space (committed, reserved, free), access protection, and type of memory |
| WriteFile | KERNEL32.dll | Writes content on a file directly to an HTTP response output stream as a file block |
| rand | msvcrt.dll | Generates a random integer |
| srand | msvcrt.dll | Sets the seed of the integer for rand |
| ShellExecuteA | SHELL32.DLL | Used to execute operations pertaining to file manipulation or system interactions by launching or executed a specified file or operation |
| CloseClipboard | USER32.dll | Function used to close the clipboard |
| EmptyClipboard | USER32.dll | Empties the contents of the clipboard as well as freeing handles related to data in the clipboard |
| GetLastInputInfo | USER32.dll | Provides user input of a specific session that invoked or “called” the function |
| GetWindowThreadProcessId | USER32.dll | Retrieves the thread that created a specified window as well as its PID that created the window |
| OpenClipboard | USER32.dll | Opens the clipboard for examination and prevents other apps from modifying the clipboard |
| SetClipboardData | USER32.dll | Places data in the clipboard  |
| InternetCloseHandle | WININET.DLL | Closes the internet handle freeing up resources and discarding of outstanding operations and data |
| InternetOpenA | WININET.DLL | Tells the internet DLL to initialize internal data structures and prepare to receive calls from an application |
| InternetOpenUrlA | WININET.DLL | Parses the URL string, connect to a server, and prepare to download data identified by the URL |
| InternetReadFile | WININET.DLL | Retrieves data from an HINTERNET handle as stream of bytes essentially downloading data specified by InternetOpenUrl |
| closesocket | WS2_32.dll | Closes a socket ending a connection and freeing up resources |
| gethostbyname | WS2_32.dll | Function used to retrieve the IP of a given hostname and set a pointer to hostent containing information about the host, aliases, and address type |

4. Moving forward, **floss.exe** can be used to extract obfuscated strings usually used for commands 

```arduino
floss.exe C:\Users\User\Desktop\malware-sample-1\malware1\budget-report.exe
```

![image 8](https://github.com/user-attachments/assets/02f6406a-455d-4530-82d7-1cf9b58ec516)


5. Using **Capa,** we can identify what Attack techniques were used as well as capabilities. 

```arduino
capa C:\Users\User\Desktop\malware-sample-1\malware1\budget-report.exe
```

In this section, the malware’s main techniques were

- **Discovery** - Information gathering/Enumeration phase where assets are discovered as well as potential attack vectors, and vulnerabilities
- **Execution** - Phase where an attack is carried out after having gathered required intelligence and information
- **Defense Evasion** - Techniques used to avoid detection by security tools such as AV,EDRs, IDS/IPS, Detection Rules
- **Privilege Escalation** - Exploit of a vulnerability used to gain higher level privilege of a low/medium level account
- **Persistence** - Stage where an attacker maintains long term access to the machine/account even after initial access and security measures

![Screenshot_(1490)](https://github.com/user-attachments/assets/c47c1f56-bfbb-48d7-a4c3-b08bc7fe7d34)


![Screenshot_(1491)](https://github.com/user-attachments/assets/f30bb6b2-8e58-4914-9c4c-b2ec280920a0)


6. Right click the malware and select **HashMyFile.** File hashes will be generated and select either the **MD5** or **SHA256** hash. Go to **VirusTotal** to cross check/confirm the malicious file   

![image 9](https://github.com/user-attachments/assets/f0a590b7-7987-406e-9935-445b77bb160c)




# Dynamic Analysis

## Dynamic Analysis Steps

1. Start procmon, then pause and clear
2. Start Fakenet
3. Start Regshot, then take 1st shot
4. Run Malware for about 1 - 3 mins and study fakenet output
5. After about 3 mins, pause procmon
6. Use Regshot, to take 2nd shot
7. Once 2nd shot completes, click Compare → Compare and show output
8. Study Regshot output

When working with malware such as **worms,** the network should be disabled on the guest VM to prevent potential spread of the malware accidentally

1. Open **Procmon** and **pause** then **clear** the current telemetry the system generates.

![image 10](https://github.com/user-attachments/assets/34be9cfe-f4d4-4576-9084-268fb5d89bad)


2. Open **Fakenet-NG** so that it will intercept any traffic the malware generates

![Screenshot_(1496)](https://github.com/user-attachments/assets/3caea109-8888-4b85-9a3b-44d5d2acaba2)


3. After running Fakenet-NG, minimize the window and ensure **not** to **close** it since this will capture network traffic. Open **regshot.** Select the **Scan dir1[…]** box and change the directory to **C:\** since the entire filesystem will be analyzed.

![image 11](https://github.com/user-attachments/assets/6530abc4-f418-4046-a870-b583b87e621b)


4. Once the C drive has been selected, click **1st shot → Shot**. This will create a snapshot of the entire filesystem of the VM. A message will appear informing the snapshot has been completed. Select **Ok** once finished

![image 12](https://github.com/user-attachments/assets/9e34b687-b112-4293-8f12-97aa0aadaf56)


![Screenshot_(1499)](https://github.com/user-attachments/assets/46b48e7b-0cc2-4090-9879-f69b728d4c59)


5. Go back to Procmon and select **Capture** to begin the capture of all processes currently running on the machine. When the capture has begun, **execute the malware** 

![image 13](https://github.com/user-attachments/assets/189387ad-810c-4a60-847b-2f660a6932b0)


![image 14](https://github.com/user-attachments/assets/954840ae-a816-4afd-9e2d-57bc58de2b39)


Once the malware was executed, it has dissapeared from the directory as apart of its execution process

![image 15](https://github.com/user-attachments/assets/5ac5d551-ef0e-4654-839d-816e2ee4c178)


6. Once the malware has been running for 1 - 3 mins, go to Procmon and pause the capture
7. Back in **regshot,** select **2nd shot → Shot**. Again, a popup will appear when the snapshot of the filesystem has been captured

![image 16](https://github.com/user-attachments/assets/67ec3f90-e75b-43fd-90b0-e7b345995bf1)


![Screenshot_(1504)](https://github.com/user-attachments/assets/c71fba3c-138d-41d8-ab5c-377ea6a68d41)


8. When both the 1st and 2nd snapshots have been taken, click the **Compare → Compare Output** button to begin the process of comparing the clean state of the machine’s filesystem to the post malware execution state

![image 17](https://github.com/user-attachments/assets/63f3cdc4-ab97-4b48-9c27-a868e1ce2f91)


Regshot will generate the output of the comparison in a notepad file where all changes to the C:\ drive are listed and can be viewed. In this case, the malware made changes to the system with a main emphasis on file creation and registry change ****in order to run the file that was created by the malware  

| Descriptor     | IOC                                                                                                                                      | Number of IOCs |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------|----------------|
| Values Added   | `HKU\S-1-5-21-1187151677-3559349637-397545174-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*12648430: "C:\Users\User\AppData\Roaming\12648430\csrss.exe"` | 1              |
| Folders Added  | `C:\Users\User\AppData\Roaming\12648430`<br>`0x00000017`                                                                               | 1              |
| Files Added    | `C:\Users\User\AppData\Roaming\12648430\csrss.exe`<br>`2018-02-06 23:53:21, 0x00000007, 419328`                                         | 1              |
| Files Deleted  | `C:\Users\User\Desktop\malware-sample-1\malware1\budget-report.exe`<br>`2018-02-06 23:53:21, 0x00000020, 419328`                        | 1              |


9. Using the Output from Fakenet-NG, the output of any type of network telemetry the malware may have generated will be displayed

In this case, the malware tried to connect to a host with the IP address of **192.0.2.123** over port **80 (HTTP),** which leads to a site named [**mbaquyahcn.biz**](http://mbaquyahcn.biz). The HTTP POST method was used to try to potentially send data to the malicious server with a length of **80 bytes** using **encoding**

![image 18](https://github.com/user-attachments/assets/f0dceeec-221f-40ea-8fbc-548a75f7860a)


The output of the network activity was saved by Fakenet-ng and is stored in a file named **http_20250508_153857.txt**

## Procdot Analysis

1. After analyzing the regshot output comparison file of the C:\ drive and observing the network traffic generated by the malware, it is time to filter Procmon events. Select either the **Filter** tab or the **Filter** Icon

![image 19](https://github.com/user-attachments/assets/d6c6fbc7-85a6-4a70-b236-5250eb0c4c9c)


![image 20](https://github.com/user-attachments/assets/965ec57c-b529-4fa3-95ad-763ac14eb7af)


2. Under the first filter (pre-selected: Architecture), choose **Process Name,** ensure the option for the second filter **(is),** and select the **malware** that was ran, then click **Add** 

Following the addition of only the malware process name, all the other processes not pertaining to the malware will be excluded

![image 21](https://github.com/user-attachments/assets/d888c7ca-24ae-4879-ba4c-c524983a977b)



3. Go back to the **first filter,** select **Operation** (the system API calls made by processes). Second option should be **(is)**. The third filter should be the following APIs: **WriteFile, SetDipositionInformationFile, RegSetValue, ProcessCreate, TCP, UDP.** Once all the APIs have been added, select **Apply**

![image 22](https://github.com/user-attachments/assets/36e7cb28-c78d-4674-97c5-389b66951a49)



The number of events should drastically change since the filters are specific and honing in on only the process specified as well as the API functions pertaining to that process

![image 23](https://github.com/user-attachments/assets/ed1979c5-9e3d-466e-96cb-01ce8d0e79a8)


Number of events after all filters have been applied

![image 24](https://github.com/user-attachments/assets/8146fedd-b1c6-4a36-b5dd-bd4b49a5d9d4)


4. Go to the **Options** tab. And ensure none of the options available are checked then go to **Select Columns…** Ensure the following columns are checked:
    - Process Name
    - Operation
    - Time of Day
    - Path
    - Detail
    - Result
    - Process ID
    - Thread ID

![image 25](https://github.com/user-attachments/assets/96380c4f-dcd4-414c-8e51-5082188d3ee9)


![image 26](https://github.com/user-attachments/assets/81a546cb-08b6-4e12-9a0c-37b6a0992445)


5. Once everything is selected that is required, press **Ok** and now go to **File → Save…** Save **All events** in both **.pml** and **.csv**

PML format is saved in the case the Procmon events of this specific filtering need to be viewed again, and CSV will be used for the visualization of the malware activity

 

![image 27](https://github.com/user-attachments/assets/bd011f4b-8a1b-4935-a6a9-2615b7a76ea7)


![image 28](https://github.com/user-attachments/assets/9f9ec67a-dd3f-404f-8264-eb9f07e5d1a9)


![image 29](https://github.com/user-attachments/assets/23ed6b81-3a4c-4cd1-9468-a4a0deeced62)


6. Open **procdot**. Under **Edit → Options,** ensure that the **Path to dot (Graphiz)** is pointing to the **C:\Program Files\Graphiz\bin\dot.exe** path. Otherwise, the visualization will not work

![image 30](https://github.com/user-attachments/assets/c800dd6b-63b6-45e8-a108-abe5370775c4)


![image 31](https://github.com/user-attachments/assets/6372b731-303e-41db-be3a-fba8c27974c1)


7. Back in the main section of procdot, under **Monitoring Logs → Procmon,** select the **CSV** file of the procmon output that was saved earlier

![image 32](https://github.com/user-attachments/assets/4e5d452f-45d4-44e9-bdee-7ed74ded468f)


![image 33](https://github.com/user-attachments/assets/ef036054-e4d0-4c1f-8210-8d7c65c6f3b1)


8. In the **Render Configuration** section, select the ellipses for **Launcher** and it will begin analyzing the procmon file and generate a list of processes pertaining to the procmon file. Once the list is generated, select the **malware** that was executed, then select **Refresh**

![image 34](https://github.com/user-attachments/assets/151dbd39-e1a3-4696-bfc4-a6f2e3d29147)

![image 35](https://github.com/user-attachments/assets/922824d1-c2ff-43fa-8bd1-345c8c800794)


![image 36](https://github.com/user-attachments/assets/9ef8c984-50ab-4ecf-9701-eac9cf250b1b)


9. The graph has now been generated specifically for the process selected from the procmon output. In this case, **budget-report.exe** was selected and a procdot has generated a relational graph of the exact interaction from the malware based off the procmon output 

Six connection attempts were made by the malware in attempt to interact with the IP **192.0.2.123** to potentially further an attack by installing more malware and causing more harm

![Screenshot_(1529)](https://github.com/user-attachments/assets/74589028-683d-4066-904f-c1103bf6c5ed)


From detonation of the malware, a child process **cmd.exe (PID 1988)** was spawned from the malware 

![Screenshot_(1530)](https://github.com/user-attachments/assets/0513b620-2ac5-4812-a526-18180303fb8e)


From **cmd.exe** another child process was spawned, **conhost.exe (PID 5480)** which is used to manage console windows such as Command Prompt and Powershell. 

From the malware, a **batch file (12648430.bat)** was created in the following path: **C:\Users\pc\AppData\Local\Temp\.** The batch file then killed the the **cmd.exe** process as well as deleted itself

![Screenshot_(1531)](https://github.com/user-attachments/assets/417fda91-5bec-4526-a3b8-4045dd48900e)


The malware also created a new **folder (\12648430)** under the **C:\Users\User\AppData\Roaming\** path, ****renamed itself in and moved to a different directory in attempt to avoid detection

- **Original Directory -** C:\Users\User\Desktop\malware-sample-1\malware1
- **New Directory** - C:\Users\User\AppData\Roaming\12648430\csrss.exe

On top of creating a new folder in a different path than where the original malware was stored, renaming itself, and moving to the newly created folder, persistence can be seen being used. A **registry key** was created **(HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*12648430)** in order to execute everything within the \12648430 directory upon user login

![Screenshot_(1532)](https://github.com/user-attachments/assets/335cce0b-f6dc-4ba4-ad19-86a49f5b683d)


By using both procdot and regshot, we can identify the exact location of the malware as well as the newly created folder that is storing the renamed malware and the value of the registry key created by the malware

- **C:\Users\User\AppData\Roaming\12648430**

Upon inspection of the directory **C:\Users\User\AppData\Roaming\,** the folder \12648430 does not appear to be there. That is because evasive measures were used to try to hide the folder. Under **View** select the **Hidden items** box, and now the folder storing the malware will be visible

![image 37](https://github.com/user-attachments/assets/0b195be4-c3ae-459a-9acf-3b36417f4b1c)


![image 38](https://github.com/user-attachments/assets/2452879e-33a7-404f-b63a-e55664510e88)


![image 39](https://github.com/user-attachments/assets/067bf69b-0e05-466e-adfa-238f766d1071)


Going into the directory **\12648430,** the malware is in fact under this path and can be identified with the new name of **crss.exe** instead of the original, **budget-report.exe.** This showcases how sophisticated malware can be and the lengths taken to remain undetected and persistent for as long as possible

![image 40](https://github.com/user-attachments/assets/3cde24ec-6f70-42a2-a860-b125bb7d5570)


We can verify that **crss.exe** is the same file as **budget-report.exe** by comparing the hash values to one another

Using Cappa, the hash values can be seen for the malware. The hashes remain the same, so this is in fact the same file just with a different name and location

![Screenshot_(1539)](https://github.com/user-attachments/assets/0471dc16-f029-47a6-a626-0f739caba465)


![image 41](https://github.com/user-attachments/assets/e0fc51f5-5741-4ff0-8fc8-8dd2e790206a)


## Network Analysis

1. Open the **pcap** file saved by Fakenet. Can be found in **\Desktop\fakenet_logs** or **C:\Tools\Fakenet\.** Looking at the traffic, we can filter down to **http** traffic since that what was being sent between the machine and potential C2 server

We can identify that various POST requests were being made from the analysis machine to the potential C2 server **192.0.2.123**

![image 42](https://github.com/user-attachments/assets/8a000ea2-019f-41ad-a533-2144c5257577)


If we follow the TCP stream of one the POST methods, it seems to lead to a site with a form where data is being posted in encoded format

![image 43](https://github.com/user-attachments/assets/2f5cec3d-8083-45c8-9cc0-a31af95f84d6)


Using Wireshark, we are able to identify network-related indicators of compromise/attacks . In this case the malware was trying to reach out to a potential C2 server and submit data in encoded format, which is ideal for some level of detection evasion since network signatures of data can be identified by network controls

# Conclusion

The malware **budget-report.exe** disguises itself with a fake Adobe icon and attempts to masquerade as a legitimate report. Upon execution, it creates a batch file named **12648430.batch** which in turn creates a directory **C:\Users\User\AppData\Roaming\12648430** renames **budget-report.exe** to **crss.exe**, and moves to the directory **\12648430** for persistence. 

The following registry key is created **HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\*12648430** for RunOnce execution. 

While analyzing network traffic with Wireshark, potential C2 activity was found in an attempt to POST data to an external domain **(mbaquyahcn.biz)** with the IP Address of **192.0.2.123**.

Obfuscation, evasion, privilege escalation, and persistence techniques are all present. The malware is confirmed by VirusTotal having been marked by 57/72 AV engines and demonstrates high-risk behavior across multiple phases of the attack lifecycle.
