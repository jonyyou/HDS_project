# HDS_project

This project implements HDS (Hierarchical Detection Scheme)  for detecting DDoS attacks. Its main function is to progressively detect the attack in three layers: MAC address pair layer, MAC+Subnet IP address layer, and IP address layer. 

It can be used in two ways: (1) analyze local pcap files, and (2) capture and analyze traffic in real-time.

------

### Files

- main_HDS_capture.cpp: capture and analyze real-time network traffic to detect DDoS flooding attacks
- main_HDS_pcap.cpp: analyze local pcap file to detect DDoS flooding attacks

------

### HDS_pcap - Analyze Local PCAP File

main_HDS_pcap.exe can run on both Windows and Ubuntu.

We show how to compile and run the main_HDS_pcap.exe on Ubuntu.

#### Compiling Environment

Windows: vscode + mingw 10.2.0 + cmake
Ubuntu: vscode + gcc 9.3.0 + cmake

#### Compile and run

##### Compile

```
$ make HDS_pcap
```

##### Run

1. **Modify the settings in data.cfg**

   **step1: modify the settings of HDS_pcap**

```
//the path of the pcap file to be analyzed.
HDS_in_pcap_file = "/home/cayman/data/pcap/202006031400.pcap.cut_type0_0-20_payload0.pcap";

//the random seed is used to randomly select the starting point of packet sampling.
HDS_random_seed = 2022;
```

​		**step2: modify the settings of HDS sketch**

```
HDS_ratio = 1;         //packet sampling ratio: 0(1/1),1-14(1/8, 1/16, ..., 1/32768, 1/65536)
HDS_sketch_layer = 3;  //the number of sketch layers

HDS_sketch_type1 = 7;  //layer1: interface-level. flowkey: MAC pair
HDS_sketch_type2 = 4;  //layer2: area-level. flowkey: (MAC, Subnet IP)
HDS_sketch_type3 = 2; //layer3: host-level. flowkey: IP

/* 
optional statistical features:

a --- forward Pck. (1B)
b --- backward Pck.(1B)
e --- forward IP+port hash16 Distr. (2B)
f --- backward IP+port hash16 Distr. (2B)
p --- forward Pck. speed
q --- backward Pck. speed

The features selected for detecting DDoS flooding attacks at each layer are "abefpq". 
*/
HDS_sketch_feature1 = "abefpq";    //the features at layer 1
HDS_sketch_feature2 = "abefpq";    //the features at layer 2
HDS_sketch_feature3 = "abefpq";    //the features at layer 3

//hash bit
HDS_sketch_hash_bit1 = 10;         //the number of columns in layer1 sketch: 2^10     
HDS_sketch_hash_bit2 = 12;         //the number of columns in layer2 sketch: 2^12
HDS_sketch_hash_bit3 = 12;         //the number of columns in layer3 sketch: 2^12
//threshold 
HDS_sketch_threshold1 = 100;       //the featuren extraction threshold of layer1 sketch
HDS_sketch_threshold2 = 100;       //the featuren extraction threshold of layer2 sketch
HDS_sketch_threshold3 = 100;       //the featuren extraction threshold of layer3 sketch
```

2. **Run**

Requirement: copy data.cfg to your running path.

Notice: if you run HDS_pcap in Windows, you should also copy the four .dll files in /bin/win to your running path

```
$ ./HDS_pcap
```

------

### HDS_capture - Capture and Analyze Traffic in Real-time

main_HDS_capture.exe can run on Ubuntu with libpcap.

We show how to compile and run the main_HDS_capture.exe on Ubuntu.

#### Compiling Environment

Ubuntu: vscode + gcc 9.3.0 + cmake + libpcap

#### Compile and run

##### Compile

```
$ make HDS_capture
```

##### Run

**1. Modify the settings in data.cfg**

​		**step1: modify the settings of HDS_capture**

```
//the NIC that captures the traffic.
HDS_dev = "enp0s31f6";

//the path of the pcap file to be analyzed.
HDS_out_pcap_file = "/home/cayman/data/pcap/20210501_3.pcap";

//whether to dump the file locally. 
//0: no dump; 1: dump only the sampled traffic; 2: dump all traffic.
HDS_dump_type = 2; //0 -- not dump, 1 -- only sample, 2 -- all

//set the maximum number of packets to be captured.
HDS_max_packet = 5000000;

//capture time (seconds).
HDS_capture_time = 900;
```

​		**step2: modify the settings of HDS sketch**: the same in Usage 1.

**2. Run**

Requirement: copy data.cfg to your running path

```
$ ./HDS_capture
```

------

### Machine Learning - Applying HDS_project to DDoS Attack Detection

HDS_pcap will output feature vectors to a **.csv file, while HDS_capture will output feature vectors to Redis database. In both cases, each feature vector identified by *flowkey*. 

1.To **train** a classification model for DDoS attack detection, the following steps need to be performed:

- Acquisition of training set with ground truth.

  Background traffic: using the public dataset MAWI Working Group Traffic Archive (MAWI)

  DDoS attack traffic : using the public dataset CICDDoS-2019

- Mix the background traffic with the attack traffic and extracting the features of the mixed traffic by **HDS_pcap** to obtain a **.csv file.

- Label the feature vectors according to the *flowkey* to obtain the training set.

- Train the traffic classifier using machine learning algorithms (e.g., decision tree, random forest).

2.To **detect** DDoS attacks using **HDS_pcap**:

- Extract traffic features by **HDS_pcap** , which are output to a **.csv file.
- Input the features into the traffic classifier. The classifier outputs the identification results: the DDoS victim set.

3.To **detect** DDoS attacks using **HDS_capture**:

- ​	We build a simulation network in **Mininet**, as shown in Figure 1. The background traffic and attack traffic are replayed in Host 1 and destined for Host2.  
- The **traffic collection system** in the switch is responsible for collecting sampled traffic and then sending the traffic to the **traffic analysis server**. 
- We run HDS_capture on the traffic analysis server to extract traffic features for real-time traffic classification using the well-trained traffic classifier. The features are stored in the Redis database.

- ![Sytem topology](/images/system.png)  

<center>Figure 1. System Topology</center>  

<br>

Device Name	| Device Configuration
:---: | :---:
Host1 for Replay Traffic<br>Host2 for Replay Traffic<br>Traffic Analysis System | CPU: Inter Core i7-12700K 3.6GHz<br>RAM: 128GB 3200MHz<br>ROM: 5TB<br>NIC1: 10000Mbps<br>NIC2: 1000Mbps
TAP Switch | Centec V580-48X6Q-TAP

 If you have any problems, please contact yqzhuang@seu.edu.cn.