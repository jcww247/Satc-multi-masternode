# Mag-multi-masternode
Mag multi masternode(this is not the official script , use at your own risk)

```bash
git clone https://github.com/jcww247/Mag-multi-masternode
cd mag-1.0.0/bin 
sudo chmod +x magd 
sudo chmod +x mag-cli
```
replace the # in the next command with number of nodes to setup
```bash
./multinode_SAP.sh -c # -n 4
```
it will asks you for the masternode private keys , go to your wallet console and type: 
```bash 
masternode genkey
``` 
remember that each nodes needs a different key

after everything is done , start it up 
```bash 
./start_multinode.sh
```

Currently the commands only works while you are inside the folder that you cloned, current commands:
```bash 
./start_multinode.sh # start the masternodes
./stop_multinode.sh # stop the masternodes
./mn_status.sh # check the state of the masternodes
./mn_getinfo.sh # receive info of the wallet server (can check blocks progress as well from here)
```

reminder that if you restart your VPS you need to use the above command to start the masternodes servers 
# Credits
script base on many individuals that have helped with this script.

# Donation
MAG address: Coming Soon

# The Person Who Helped has BTC Here till i get mine :)
BTC  address: 
