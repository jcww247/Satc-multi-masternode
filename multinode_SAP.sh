#!/bin/bash

BASE="/home/sap"
PORT=3877
# Execute options
ARGS=$(getopt -o "hp:n:c:r:wsudx" -l "help,count:,net" -n "multinode_SAP.sh" -- "$@");

net=4
count=1
eval set -- "$ARGS";

while true; do
    case "$1" in
        -n|--net)
            shift;
                    if [ -n "$1" ];
                    then
                        net="$1";
                        shift;
                    fi
            ;;
        -c|--count)
            shift;
                    if [ -n "$1" ];
                    then
                        count="$1";
                        shift;
                    fi
            ;;
        --)
            shift;
            break;
            ;;
    esac
done
	
#######################-------------------------------------------------------------------------IP TESTING	

# break here of net isn't 4 or 6
if [ ${net} -ne 4 ] && [ ${net} -ne 6 ]; then
    echo "invalid NETWORK setting, can only be 4 or 6!"
    exit 1;
fi
	
if [ ${net} = 4 ]; then
	IPADDRESS=$(ip addr | grep 'inet ' | grep -Ev 'inet 127|inet 192\.168|inet 10\.' | sed "s/[[:space:]]*inet \([0-9.]*\)\/.*/\1/")
fi
	
if [ ${net} = 6 ]; then
	IPADDRESS=$(ip -6 addr show dev eth0 | grep inet6 | awk -F '[ \t]+|/' '{print $3}' | grep -v ^fe80 | grep -v ^::1 | cut -f1-4 -d':' | head -1)
fi
#######################-------------------------------------------------------------------------END IP TESTING

# currently only for Ubuntu 16.04 & 18.04
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        if [[ "${VERSION_ID}" != "16.04" ]] && [[ "${VERSION_ID}" != "18.04" ]] ; then
            echo "This script only supports Ubuntu 16.04 & 18.04 LTS, exiting."
            exit 1
        fi
    else
        # no, thats not ok!
        echo "This script only supports Ubuntu 16.04 & 18.04 LTS, exiting."
        exit 1
    fi
	

#install Deps

	sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
	sudo apt-get -y upgrade
	sudo apt-get -y dist-upgrade
	sudo apt-get -y autoremove
	sudo apt-get -y install wget nano htop jq git curl
	sudo apt-get -y install libzmq3-dev libzmq5
	sudo apt-get -y install libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev lshw
	sudo apt-get -y install libevent-dev libbz2-dev libicu-dev python-dev g++
	sudo apt -y install software-properties-common
	sudo add-apt-repository ppa:bitcoin/bitcoin -y
	sudo apt-get -y update
	sudo apt-get -y install libdb4.8-dev libdb4.8++-dev bsdmainutils libgmp3-dev ufw pkg-config autotools-dev redis-server npm nodejs nodejs-legacy
	sudo apt-get -y install libminiupnpc-dev
	sudo apt-get -y install fail2ban
	sudo service fail2ban restart
	sudo apt-get install -y libdb5.3++-dev libdb++-dev libdb5.3-dev libdb-dev && ldconfig
	sudo apt-get install -y unzip libzmq3-dev build-essential libtool autoconf automake libboost-dev libssl-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libboost-system1.58.0 libboost1.58-all-dev libdb4.8++ libdb4.8 libdb4.8-dev libdb4.8++-dev libevent-pthreads-2.0-5
	sudo apt-get update

#Create 5GB swap file
if grep -q "SwapTotal" /proc/meminfo; then
    echo -e "${GREEN}Skipping disk swap configuration...${NC} \n"
else
    echo -e "${YELLOW}Creating 5GB disk swap file. \nThis may take a few minutes!${NC} \a"
    touch /var/swap.img
    chmod 600 swap.img
    dd if=/dev/zero of=/var/swap.img bs=1024k count=5000
    mkswap /var/swap.img 5> /dev/null
    swapon /var/swap.img 5> /dev/null
    if [ $? -eq 0 ]; then
        echo '/var/swap.img none swap sw 0 0' >> /etc/fstab
        echo -e "${GREEN}Swap was created successfully!${NC} \n"
    else
        echo -e "${YELLOW}Operation not permitted! Optional swap was not created.${NC} \a"
        rm /var/swap.img
    fi
fi

echo -e "Installing and setting up firewall to allow ingress on port 8120"
  ufw allow 3877/tcp comment "SATC MN port" >/dev/null
  ufw allow ssh comment "SSH" >/dev/null 2>&1
  ufw limit ssh/tcp >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  echo "y" | ufw enable >/dev/null 2>&1

#Download Latest
echo 'Downloading latest version:  wget https://github.com/SatoshiCoin-Crypto/SatoshiCoin-rebrand/releases/download/v1.0.2.1/ubuntu16.04-daemon.zip.tar.gz' &&  wget https://github.com/SatoshiCoin-Crypto/SatoshiCoin-rebrand/releases/download/v1.0.2.1/ubuntu16.04-daemon.zip.tar.gz
			
#Install Latest
echo '==========================================================================='
echo 'Extract new Satoshi Coin Masternode : \n# tar -xf ubuntu16.04-daemon.zip.tar.gz -C /usr/local/bin' && tar -xf ubuntu16.04-daemon.zip.tar.gz -C /usr/local/bin

rm ubuntu16.04-daemon.zip.tar.gz

# our new mnode unpriv user acc is added
if id "sap" >/dev/null 2>&1; then
    echo "user exists already, do nothing" 
else
    echo "Adding new system user sap"
    adduser --disabled-password --gecos "" sap
fi

netDisable=$(lshw -c network | grep -c 'network DISABLED')
venet0=$(cat /etc/network/interfaces | grep -c venet)

if [ $netDisable -ge 1 ]; then
	if [ $venet0 -ge 1 ]; 
	then
		dev2=venet0
	else
		echo 'Cannot use this script at this time'
		exit 1
	fi
else
	dev2=$(lshw -c network | grep logical | cut -d':' -f2 | cut -d' ' -f2)
fi

# individual data dirs for now to avoid problems
echo "* Creating masternode directories"
mkdir -p "$BASE"/multinode
for NUM in $(seq 1 ${count}); do
    if [ ! -d "$BASE"/multinode/SAP_"${NUM}" ]; then
        echo "creating data directory $BASE/multinode/SAP_${NUM}" 
        mkdir -p "$BASE"/multinode/SAP_"${NUM}" 
		#Generating Random Password for Satc JSON RPC
		USER=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
		USERPASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
		read -e -p "MasterNode Key for SAP_"${NUM}": " MKey
		echo "rpcallowip=127.0.0.1
rpcuser=$USER
rpcpassword=$USERPASS
server=1
daemon=1
listen=1
printtoconsole=1
maxconnections=256
masternode=1
masternodeprivkey=$MKey
promode=1
addnode=178.32.70.48	
addnode=37.59.163.33
addnode=193.70.58.118
addnode=213.32.121.24
addnode=217.182.53.134
addnode=37.59.151.24
addnode=46.105.161.92
addnode=137.74.50.219
addnode=51.254.255.3
addnode=51.255.29.147
addnode=80.211.4.117
addnode=5.196.177.228
addnode=51.254.51.126
addnode=94.23.104.180
addnode=151.80.5.16
addnode=80.211.5.209
addnode=37.59.221.129
addnode=178.33.145.95
addnode=5.135.29.228
addnode=46.105.130.19
addnode=51.255.132.244
addnode=137.74.232.111
addnode=213.32.12.25
addnode=51.75.97.110
addnode=178.32.70.59
addnode=91.121.235.23
addnode=54.38.15.185
addnode=80.211.228.131
addnode=188.213.168.179
addnode=92.222.144.182	
addnode=91.121.235.31
addnode=137.74.201.137
addnode=209.97.154.140
addnode=68.198.145.62	
addnode=80.211.128.198
addnode=54.37.188.57
addnode=100.37.112.34
addnode=54.38.19.87
addnode=51.68.6.85
addnode=5.196.177.238
addnode=164.132.180.146
addnode=77.55.223.121
addnode=178.33.93.54	" |sudo tee -a "$BASE"/multinode/SAP_"${NUM}"/satc.conf >/dev/null
echo 'bind=192.168.1.'"${NUM}"':'"$PORT" >> "$BASE"/multinode/SAP_"${NUM}"/satc.conf
echo 'rpcport=8119'"${NUM}" >> "$BASE"/multinode/SAP_"${NUM}"/satc.conf

echo 'ip addr del 192.168.1.'"${NUM}"'/32 dev '"$dev2"':'"${NUM}" >> start_multinode.sh
echo 'ip addr add 192.168.1.'"${NUM}"'/32 dev '"$dev2"':'"${NUM}" >> start_multinode.sh
echo "runuser -l sap -c 'satcd -daemon -pid=$BASE/multinode/SAP_${NUM}/satc.pid -conf=$BASE/multinode/SAP_${NUM}/satc.conf -datadir=$BASE/multinode/SAP_${NUM}'" >> start_multinode.sh

echo 'ip addr del 192.168.1.'"${NUM}"'/32 dev '"$dev2"':'"${NUM}" >> stop_multinode.sh
echo "satc-cli -conf=$BASE/multinode/SAP_${NUM}/satc.conf -datadir=$BASE/multinode/SAP_${NUM} stop" >> stop_multinode.sh

echo "echo '====================================================${NUM}========================================================================'" >> mn_status.sh
echo "satc-cli -conf=$BASE/multinode/SAP_${NUM}/satc.conf -datadir=$BASE/multinode/SAP_${NUM} masternode status" >> mn_status.sh

echo "echo '====================================================${NUM}========================================================================'" >> mn_getinfo.sh
echo "satc-cli -conf=$BASE/multinode/SAP_${NUM}/satc.conf -datadir=$BASE/multinode/SAP_${NUM} getinfo" >> mn_getinfo.sh
# When Blocks are synched, it copies the wallet into the remaining Mns Wallet automatically
echo "echo 'stop MN${NUM}'"
    echo "satc-cli -conf=$BASE/multinode/SAP_${NUM}/satc.conf -datadir=$BASE/multinode/SAP_${NUM} stop" >> mn_sync_block.sh
    if (( ${NUM} > 1)) ; then
        echo "echo 'copy MN1 blocks folder into masternode ${NUM}'" >> mn_sync_block.sh
        echo "sudo yes | cp -R $BASE/multinode/SAP_1/blocks/ $BASE/multinode/SAP_${NUM}/blocks" >> mn_sync_block.sh
    fi

fi
done

chmod +x start_multinode.sh
chmod +x stop_multinode.sh
chmod +x mn_status.sh
chmod +x mn_getinfo.sh
cat start_multinode.sh >> /usr/local/bin/start_multinode.sh
cat stop_multinode.sh >> /usr/local/bin/stop_multinode.sh
cat mn_getinfo.sh >> /usr/local/bin/mn_getinfo.sh
cat mn_status.sh >> /usr/local/bin/mn_status.sh
chown -R sap:sap /home/sap/multinode
chmod -R g=u /home/sap/multinode
#command below starts all MNs, so it creates requirements per user. Need to shut it off manually to prevent high cpu
./start_multinode.sh

echo 'run start_multinode.sh to start the multinode'
echo 'run stop_multinode.sh to stop it'
echo 'run mn_getinfo.sh to see the status of all of the nodes'
echo 'run mn_status.sh for masternode debug of all the nodes'
echo "in masternode.conf file use the external IP address as the address ex. MN1 $IPADDRESS:8120 privekey tx_id tx_index"
