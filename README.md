# Spynet
A tool written in *python3* to scan for live hosts on a network and scan for open ports.

*download and install*
```
git clone https://github.com/Rival420/Spynet.git
cd Spynet/
pip3 install -r requirements.txt
```

*Usage*
Should be used like this on default LAN:

`python3 Spynet.py -t 192.168.1.0/24`

I added extra functionality so you have more control over the portscan and it's range/speed

*First_port: -f or --first-port => can be used to specify starting port (default: 1)
* Last_port: -l or --last-port => can be used to specify the last port (default: 1024)
  * setting this higher can result in errors, make sure to adapt defaulttimeout with it!
* Default_Timeout: changing this will affect the speed of the script. (default: 0.01)
* verbosity: -v or --verbose => this is mainly for debugging purpose. this will output all ports it's scanned.

Extra: portscan on certain host can be skipped with KeyboardInterrupt (ctrl+C)


Made By Rival23 and Requird

Thanks for help: Comradecereal and X4v1l0k !!
