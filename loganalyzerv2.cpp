#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>
using namespace std;

set<string>whitelists = {    "ssh.service",
    "bluetooth.service", 
    "gdm.service",
    "systemd-timesyncd.service",
    "NetworkManager.service",
    "jenkins.service",
    "cron.service",
    "nginx.service"
};

void checkMaliciousService(map<string, vector<int>> &oomKills, map<string, vector<int>> &segFaults, set<string> &unknownServices){
    for (string x : unknownServices) {
        cout<<"The service "<<x<<" is malicious\n";
    }
    for (auto x : oomKills) {
        cout<<"The service "<<x.first<<" is out of memory, Kill the process\n";
    }
    for (auto z : segFaults) {
        int left = 0, right = 0 ;
        while(right < z.second.size()){
            if (z.second[right]- z.second[left] > 3600) {
                left++;
            }
            if ((right-left+1)>=6) {
                cerr<<"The service " <<z.first<<" has segmentation fault \n";
                break;
            }
            right++;
        }
    }   
}

void parseLog(string fileName,  map<string, vector<int>>&oomKills, map<string, vector<int>> &segFaults,set<string>&unknownServices){
    ifstream file(fileName);
    string line;
    while(getline(file, line)){
        //Extract Out of memory process
        if(line.find("Out of memory")!=string::npos){
            int start = line.find('(');
            int end = line.find(')');
            int length = end - (start+1);
            string pName = line.substr(start+1, length);
            //Extract timestamp and convert it to seconds
            int firstSpace = line.find(" ");
            int secondSpace = line.find(" ", firstSpace +1);
            int thirdSpace = line.find(" ", secondSpace+1);
            int stop = thirdSpace- (secondSpace+1);
            int begin = secondSpace+1;
            string timestamp = line.substr(begin,stop);
            //Analyze timestamp in seconds:
            int firstCol = timestamp.find(':');
            int secondCol = timestamp.find(':',firstCol+1);
            int hours = stoi(timestamp.substr(0, firstCol));
            int minutes = stoi(timestamp.substr(firstCol+1, secondCol-(firstCol+1)));
            int second = stoi(timestamp.substr(secondCol+1));
            int totalTime = hours*3600+minutes*60+second;
            oomKills[pName].push_back(totalTime);
            
        }
        if (line.find("segfault")!= string::npos) {
            int firstColon = line.find(':');
            int bracketPos = line.find('[');
            int spaceBeforeName = line.rfind(' ', bracketPos);
            string process = line.substr(spaceBeforeName+1, bracketPos - spaceBeforeName - 1);
            //cout << "DEBUG: '" << process << "' size=" << segFaults[process].size() << "\n";
            //Extract timestamp
            int firstSpace = line.find(" ");
            int secondSpace = line.find(" ", firstSpace +1);
            int thirdSpace = line.find(" ", secondSpace+1);
            int stop = thirdSpace- (secondSpace+1);
            int begin = secondSpace+1;
            string timestamp = line.substr(begin,stop);
            //Timestamp conversion
            int firstCol = timestamp.find(':');
            int secondCol = timestamp.find(':',firstCol+1);
            int hours = stoi(timestamp.substr(0, firstCol));
            int minutes = stoi(timestamp.substr(firstCol+1, secondCol-(firstCol+1)));
            int second = stoi(timestamp.substr(secondCol+1));
            int totalTime = hours*3600+minutes*60+second;
            segFaults[process].push_back(totalTime);

        }
        //Now for unknown Service
        if (line.find("Started")!=string::npos && line.find(".service")!=string::npos) {
            int start = line.find("Started")+8;
            int end = line.find(".service")+8;
            string service = line.substr(start,end-start);
            if (whitelists.count(service) == 0) {
                unknownServices.insert(service);
            }
        }
    }
}
int main(int argc, char* argv[]){
    map<string, vector<int>>oomKills,segFaults;
    set<string>unknownServices;
    if (argc < 2) {
        cerr<< "Usage ./loganalyzer <logfile>\n";
        return 1;
    }
    string fileName = argv[1];//First command int the terminal after running the program will be input value for the string
    parseLog(fileName, oomKills, segFaults, unknownServices);
    checkMaliciousService(oomKills, segFaults, unknownServices);

}