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

#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include "_lib.h/libPacketSE.h"
#include "PckCap/CPckCap.h"
#include "_lib.h/libSketchPoolSE.h"
#include "_lib.h/libCsvStorage.h"
#include "_lib.h/libconfig.h++"
#include "other/bit_conversion.h"
#include <sys/time.h>
#include "_lib.h/libRedisStorage.h"

using namespace std;
using namespace libconfig;

timeval timde;

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

    std::cerr << "HDS capture begin" << std::endl;        

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
        //dev
        string dev = cfg.lookup("HDS_dev");    
        cout << "HDS capture dev name:" << dev << endl;
        //file
        string file = cfg.lookup("HDS_out_pcap_file");    
        cout << "HDS capture file name:" << file << endl;

        int dumptype;
        cfg.lookupValue("HDS_dump_type", dumptype);
        cout << "HDS dump type(0--not capture, 1--capture all, 2--capture sample):" << dumptype << endl;

        //ratio
        int rationo, ratio;
        cfg.lookupValue("HDS_ratio", rationo);
        cout << "Sample ratio No.:" << rationo << endl;
        ratio = calSampleRate(rationo);
        cout << "Sample ratio:1/" << ratio << endl;

        uint32_t cntPck;
        cfg.lookupValue("HDS_max_packet", cntPck);
        cout << "Maximum packet capture:" << cntPck << endl;
        int tmCap;
        cfg.lookupValue("HDS_capture_time", tmCap);
        cout << "Maximum packet capture time:" << tmCap << endl;

        if(dev.length()>0)
        {
            IEigenvectorStorage* lpStorage = CCsvStorageCreator::createCsvStorage();
            lpStorage->initialPara(file, 0, "");
            ISketchPool* lpSKPool = CSketchPoolCreator::create_sketch_pool(ratio);
            //Eigenvectors are stored in a CSV file
            lpSKPool->setStorage(lpStorage);

            //Eigenvectors are stored in Redis
            //IEigenvectorStorage* lpStorage3 = CRedisStorageCreator::createRedisStorage();           
            //lpSKPool->setStorage(lpStorage3);

            //sketch layer
            int cntSketch;
            cfg.lookupValue("HDS_sketch_layer", cntSketch);
            cout << "number of sketch layer:" << cntSketch << endl;

            if(add_HDS_SK(cntSketch, &cfg, lpSKPool))
            {

                CPckCap* lpPC = new CPckCap(dev, file);
                lpPC->setPcapType(dumptype);
                lpPC->setSketchPool(lpSKPool);

                lpPC->starCapture(cntPck, tmCap, ratio);
            }
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return(EXIT_FAILURE);
    }
    std::cerr << "HDS capture end" << std::endl;        

    return 0;    
}
