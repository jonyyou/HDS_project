/**
MIT License

Copyright (c) 2021 hwu(hwu@seu.edu.cn), yqzhuang(yqzhuang@seu.edu.cn)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <iostream>
#include <cstring>
#include <time.h>
#include <vector>
#include "_lib.h/libconfig.h++"
#include "_lib.h/libSketchPoolSE.h"
#include "_lib.h/libPcapSE.h"
#include "_lib.h/libCsvStorage.h"
#include "other/bit_conversion.h"

using namespace std;
using namespace libconfig;

bool iterPcapPacket(string name, ISketchPool* lpSKP, int ratio)
{
    bool bout = false;
    CPacket *lppck;
    uint64_t cntPck = 0, cntPckSample = 0;
    uint64_t lenPck = 0, lenPckSample = 0;
    clock_t beginC, endC;

    int iCheckNum = 0;
    //random
    if(ratio>1)
        iCheckNum = rand() % ratio;
    cout << "begin number:" << iCheckNum << " ratio:" << ratio << endl;

    CReader* pr = create_pcap_reader(name.c_str());
    bool bret = pr->openPcap();
    if(bret){
        beginC = clock();

        int iret = 0;
        while(iret>=0){
            if(ratio == 1 || cntPck % ratio == iCheckNum)
            {
                iret = pr->readPacket();
                if(iret>=0){
                    lppck = pr->getPacket();
                    if(lppck && (lppck->getProtocol()==6 || lppck->getProtocol()==17) )     //tcp || udp
                    {         
                        lpSKP->procPacket(lppck);
                    }
                    cntPckSample ++;
                    lenPckSample += lppck->getLenPck();
                }
            }
            else
            {
                iret = pr->nextPacket();
                //iret = pr->readPacket();
            }
            cntPck ++;
            if(!(cntPck & 0xfffff))
                 cout << "count:" << cntPck << endl;
        }
        cout << "================================" << endl;
        cout << "Pck. count:" << cntPck << ", sample Pck. count:" << cntPckSample << endl;
        cout << "sample Pck. length:" << lenPckSample << endl;
        endC = clock();
        double tmLen = (endC - beginC);
        double tmSk = tmLen - pr->getReadTime();
        cout << "--------Time to read  + sketch(ms):" << tmLen*1000.0/(double)CLOCKS_PER_SEC << endl;
        cout << "--------Time to read file(ms):" << pr->getReadTime()*1000.0/(double)CLOCKS_PER_SEC <<endl;
        cout << "--------Time to sketch(ms):" << tmSk*1000.0/(double)CLOCKS_PER_SEC <<endl;
        //saveStatSumSpeed();
    }
    else
        cout << "open pcap file " << name << " error." << endl;

    delete pr;    
    return bout;
}

bool add_HDS_SK(int skc, Config* lpCfg, ISketchPool* lpSKP)
{
    bool bout = false;
    if(lpCfg && lpSKP)
    {
        for(int i=1; i<=skc; i++)
        {
            int type, bit, thre;
            //type
            lpCfg->lookupValue("HDS_sketch_type" + to_string(i), type);
            cout << "sketch:" << to_string(i) <<" type:" << type << endl;
            //bit
            lpCfg->lookupValue("HDS_sketch_hash_bit" + to_string(i), bit);
            cout << "sketch:" << to_string(i) <<" length:2^" << bit << endl;
            //threshold
            lpCfg->lookupValue("HDS_sketch_threshold" + to_string(i), thre);
            cout << "sketch:" << to_string(i) <<" threshold:" << thre << endl;
            //features
            string strFea = lpCfg->lookup("HDS_sketch_feature" + to_string(i));
            cout << "sketch:" << to_string(i) <<" features:" << strFea << endl;
            uint64_t ufea = convStringValue(strFea);
            //range
            uint32_t uflag = 12;
            vector<int> vctTCP, vctUDP;
            if(ufea & uflag) //range flag
            {
                vctTCP.clear();
                vctUDP.clear();

                int cntRange;
                lpCfg->lookupValue("HDS_sketch_range_count_" + to_string(i), cntRange);
                cout << "sketch:" << to_string(i) <<" range count:" << cntRange << endl;
                for(int j=1; j<=cntRange; j++)
                {
                    int value;
                    if(lpCfg->lookupValue("HDS_sketch_range_TCP_" + to_string(i) + "_"  + to_string(j), value))
                    {
                        vctTCP.push_back(value);
                        cout << "HDS_sketch_range_TCP_" + to_string(i) + "_"  + to_string(j) << ":" << value << endl;
                    }
                    if(lpCfg->lookupValue("HDS_sketch_range_UDP_" + to_string(i) + "_"  + to_string(j), value))
                    {
                        vctUDP.push_back(value);
                        cout << "HDS_sketch_range_UDP_" + to_string(i) + "_"  + to_string(j) << ":" << value << endl;
                    }
                }
            }
            if(lpSKP->addSketch((packet_statistics_object_type)type, bit, thre, ufea, &vctTCP, &vctUDP))
                bout = true;
            else
                cout << "sketch pool:" << to_string(i) <<" error!" << endl;
        }
    }
    return bout;
}

int main(int argc, char *argv[])
{
    char buf[UINT8_MAX] = "data.cfg";

    if(argc==2)
        strcpy(buf, argv[1]);

    std::cerr << "HDS from pcap file" << std::endl;        

    Config cfg;
    try
    {
        cfg.readFile(buf);
    }
    catch(...)
    {
        std::cerr << "I/O error while reading file." << std::endl;
        return(EXIT_FAILURE); 
    }    

    try
    {
        //name
        string name = cfg.lookup("HDS_in_pcap_file");    
        cout << "HDS incoming pcap file name:" << name << endl;

        int seed, rationo, ratio;
        //random seed
        cfg.lookupValue("HDS_random_seed", seed);
        cout << "Random seed:" << seed << endl;
        srand(seed);
        //ratio
        cfg.lookupValue("HDS_ratio", rationo);
        cout << "Sample ratio No.:" << rationo << endl;
        ratio = calSampleRate(rationo);
        cout << "Sample ratio:1/" << ratio << endl;

        //sketch count
        int cntSketch;
        cfg.lookupValue("HDS_sketch_layer", cntSketch);
        cout << "number of sketch layer:" << cntSketch << endl;

        if(name.length()>0)
        {
            IEigenvectorStorage* lpStorage = CCsvStorageCreator::createCsvStorage();
            lpStorage->initialPara(name, 0, "");
            ISketchPool* lpSKPool = CSketchPoolCreator::create_sketch_pool(ratio);
            lpSKPool->setStorage(lpStorage);

            if(add_HDS_SK(cntSketch, &cfg, lpSKPool))
                iterPcapPacket(name, lpSKPool, ratio);

            delete lpSKPool;
        }
        else
            cout << "parameter error." << endl;
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return(EXIT_FAILURE);
    }
    std::cerr << "sketch pool end" << std::endl;        

    return 0;
}