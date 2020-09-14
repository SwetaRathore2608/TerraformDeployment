#!/bin/bash
#INSTALLING JDK
sudo yum -y update &&
sudo yum -y upgrade &&
sudo yum -y install java-1.8.0-openjdk &&

sudo chmod 755 /var/lib/rpm &&

#INSTALLING ELASTICSEARCH
sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch &&
sudo wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.6.0-x86_64.rpm &&
sudo wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.6.0-x86_64.rpm.sha512 &&
sudo shasum -a 512 -c elasticsearch-7.6.0-x86_64.rpm.sha512 &&
sudo rpm --install elasticsearch-7.6.0-x86_64.rpm &&

#CONFIG CHANGES
sudo sed -i 's/#cluster.name: my-application/cluster.name: my-application/g' /etc/elasticsearch/elasticsearch.yml &&
#sudo sed -i 's/#cluster.initial_master_nodes: ["node-1", "node-2"]/cluster.initial_master_nodes: ["node-1", "node-2", "node-3"]/g' /etc/elasticsearch/elasticsearch.yml

yes | sudo yum remove java-1.7.0-openjdk.x86_64 &&
cd /usr/share/elasticsearch/bin &&
yes | sudo ./elasticsearch-plugin install discovery-ec2

