#include <bits/stdc++.h>
#include <iostream>
#include <map>
#include <string>
#include <vector>

using namespace std;

void detectBruteforce(map<string, vector<int>>&logs){
    for(auto& ip : logs){//Checks bruteforce for each line of the log file  
        int  left = 0 , right = 0;\
        while (right < ip.second.size()) {
            if (ip.second[right] - ip.second[left] > 60) {
                left++;
            }
            if((right - left +1) >=6){
                cerr <<"Brute Force attempt detected from " << ip.first<<endl;
                break;
            }
            right ++;
        }
    }
}


void parseLog(string fileName,  map<string, vector<int>>&logs){
    ifstream file(fileName);//this replace filename from logs.txt
    //parse the file
    string line;
    while(getline(file,line)){//If we initialize filename twice that means we are overwritting the woring of the filename so we choose different name to loop the file line by line 
        if(line.find("Failed") != string::npos){
            // cout <<true<<endl; Hypothetical assumption 
            
            
    //              Extract the IP address
    int pos = line.find("from");
    int res = line.find(" ", pos+5);
    int length = res - (pos+5);
    int start = pos+5;
    string ip = line.substr(start,length);
    //              Now for timestamp extraction 
    int firstSpace = line.find(" ");
    int secondSpace = line.find(" ", firstSpace +1);
    int thirdSpace = line.find(" ", secondSpace+1);
    int end = thirdSpace- (secondSpace+1);
    int begin = secondSpace+1;
    string timestamp = line.substr(begin,end);
    
    //------------------Convert Hours and minutes into seconds ----------------------
    int firstCol = timestamp.find(':');
    int secondCol = timestamp.find(':',firstCol+1);
    int hours = stoi(timestamp.substr(0, firstCol));
    int minutes = stoi(timestamp.substr(firstCol+1, secondCol-(firstCol+1)));
    int second = stoi(timestamp.substr(secondCol+1));
    int totalTime = hours*3600+minutes*60+second;
    
    logs[ip].push_back(totalTime);
}
    

}
}
int main(int argc, char* argv[]){//I used here so that whenever the program is runned with terminal the input allong with  the terminal becomes input for main
    map<string, vector<int>>logs;
    if (argc < 2) {
        cerr<< "Usage ./loganalyzer <logfile>\n";
        return 1;
    }
    string fileName = argv[1];//First command int the terminal after running the program will be input value for the string
    parseLog(fileName, logs);
    detectBruteforce(logs);

}