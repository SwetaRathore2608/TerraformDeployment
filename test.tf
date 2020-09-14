provider "aws" {
         profile  = "default"
         region = "us-east-1"
        }

locals{
  instance-userdata1 = <<EOF
#!/bin/bash
sudo sed -i "s/#node.name: node-1/node.name: node-1/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's/\#cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\]/cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\, \"node\-3\"\]/g' /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#node.attr.rack: r1/#node.attr.rack: r1\nnode.master: true/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#network.host: 192.168.0.1/network.host: [_local_, _site_]/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/\#discovery.seed\_hosts\: \[\"host1\"\, \"host2\"\]/discovery.seed_providers: ec2/g" /etc/elasticsearch/elasticsearch.yml
sleep 30
sudo service elasticsearch start
EOF

 instance-userdata2 = <<EOF
#!/bin/bash
sudo sed -i "s/#node.name: node-1/node.name: node-2/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's/\#cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\]/cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\, \"node\-3\"\]/g' /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#node.attr.rack: r1/#node.attr.rack: r1\nnode.master: true/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#network.host: 192.168.0.1/network.host: [_local_, _site_]/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/\#discovery.seed\_hosts\: \[\"host1\"\, \"host2\"\]/discovery.seed_providers: ec2/g" /etc/elasticsearch/elasticsearch.yml
sleep 30
sudo service elasticsearch start
EOF

 instance-userdata3 = <<EOF
#!/bin/bash
sudo sed -i "s/#node.name: node-1/node.name: node-3/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's/\#cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\]/cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\, \"node\-3\"\]/g' /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#node.attr.rack: r1/#node.attr.rack: r1\nnode.master: true/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#network.host: 192.168.0.1/network.host: [_local_, _site_]/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/\#discovery.seed\_hosts\: \[\"host1\"\, \"host2\"\]/discovery.seed_providers: ec2/g" /etc/elasticsearch/elasticsearch.yml
sleep 30
sudo service elasticsearch start
EOF

instance-userdata4 = <<EOF
#!/bin/bash
sudo sed -i "s/#node.name: node-1/node.name: node-4/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's/\#cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\]/cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\, \"node\-3\"\]/g' /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#node.attr.rack: r1/#node.attr.rack: r1\nnode.master: false\nnode.data: false\nnode.ingest: false/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#network.host: 192.168.0.1/network.host\: localhost\ntransport.host\: \[\_local\_, \_site\_\]\ntransport.tcp.port\: 9300\-9400/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/\#discovery.seed\_hosts\: \[\"host1\"\, \"host2\"\]/discovery.seed_providers: ec2/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#elasticsearch.hosts: ["http://localhost:9200"]/elasticsearch.hosts: ["http://localhost:9200"]/g" /etc/kibana/kibana.yml
sudo sed -i "s/#server.host: \"localhost\"/server.host: \"0.0.0.0\"/g" /etc/kibana/kibana.yml
sudo sed -i "s/#http.port: 9200/http.port: 9200/g" /etc/elasticsearch/elasticsearch.yml

sleep 30
sudo service elasticsearch start
EOF

 instance-userdata1_test = <<EOF
#!/bin/bash
sudo sed -i "s/cluster.name: my-application/cluster.name: my-application2/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#node.name: node-1/node.name: node-1/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's/\#cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\]/cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\, \"node\-3\"\]/g' /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#node.attr.rack: r1/#node.attr.rack: r1\nnode.master: true/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#network.host: 192.168.0.1/network.host: [_local_, _site_]/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/\#discovery.seed\_hosts\: \[\"host1\"\, \"host2\"\]/discovery.seed_providers: ec2/g" /etc/elasticsearch/elasticsearch.yml
sleep 30
sudo service elasticsearch start
EOF

 instance-userdata2_test = <<EOF
#!/bin/bash
sudo sed -i "s/cluster.name: my-application/cluster.name: my-application2/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#node.name: node-1/node.name: node-2/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's/\#cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\]/cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\, \"node\-3\"\]/g' /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#node.attr.rack: r1/#node.attr.rack: r1\nnode.master: true/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#network.host: 192.168.0.1/network.host: [_local_, _site_]/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/\#discovery.seed\_hosts\: \[\"host1\"\, \"host2\"\]/discovery.seed_providers: ec2/g" /etc/elasticsearch/elasticsearch.yml
sleep 30
sudo service elasticsearch start
EOF

 instance-userdata3_test = <<EOF
#!/bin/bash
sudo sed -i "s/cluster.name: my-application/cluster.name: my-application2/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#node.name: node-1/node.name: node-3/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's/\#cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\]/cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\, \"node\-3\"\]/g' /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#node.attr.rack: r1/#node.attr.rack: r1\nnode.master: true/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#network.host: 192.168.0.1/network.host: [_local_, _site_]/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/\#discovery.seed\_hosts\: \[\"host1\"\, \"host2\"\]/discovery.seed_providers: ec2/g" /etc/elasticsearch/elasticsearch.yml
sleep 30
sudo service elasticsearch start
EOF

instance-userdata4_test = <<EOF
#!/bin/bash
sudo sed -i "s/cluster.name: my-application/cluster.name: my-application2/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#node.name: node-1/node.name: node-4/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's/\#cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\]/cluster\.initial\_master\_nodes\: \[\"node\-1\"\, \"node\-2\"\, \"node\-3\"\]/g' /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#node.attr.rack: r1/#node.attr.rack: r1\nnode.master: false\nnode.data: false\nnode.ingest: false/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#network.host: 192.168.0.1/network.host\: localhost\ntransport.host\: \[\_local\_, \_site\_\]\ntransport.tcp.port\: 9300\-9400/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/\#discovery.seed\_hosts\: \[\"host1\"\, \"host2\"\]/discovery.seed_providers: ec2/g" /etc/elasticsearch/elasticsearch.yml
sudo sed -i "s/#elasticsearch.hosts: ["http://localhost:9200"]/elasticsearch.hosts: ["http://localhost:9200"]/g" /etc/kibana/kibana.yml
sudo sed -i "s/#server.host: \"localhost\"/server.host: \"0.0.0.0\"/g" /etc/kibana/kibana.yml
sudo sed -i "s/#http.port: 9200/http.port: 9200/g" /etc/elasticsearch/elasticsearch.yml

sleep 30
sudo service elasticsearch start
EOF

}



data "aws_ami" "ec2-ami" {

                owners = ["self"]
                filter {
                        name = "state"
                        values = ["available"]
                }

                filter {
                        name = "tag:Name"
                        values = ["ElasticSearchAMI"]
                }

                most_recent = true
}

data "aws_ami" "ec2-ami-kibana" {

                owners = ["self"]
                filter {
                        name = "state"
                        values = ["available"]
                }

                filter {
                        name = "tag:Name"
                        values = ["KibanaAMI"]
                }

                most_recent = true
}


resource "aws_key_pair" "deployer" {
        key_name = "TerraformNewMachine"
        public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjl1Bc+YLGs5WpU9Q9wjyTKd/xkzEkKga/yCmt0g6xJlgOE3LjgoTh62WdUAwsdsbyqltp9OF+1nSxVwpRP4u+tA1Xg8DJUd+Li5JaENm/um/bLeV/kc8yxuCwpu+ZThbBK5TUNjK5UNJU6jW6IGmGW0PDybhNil9KYTzrqGHTSbLhc+Rcti5W7NDwnZYCookBGwx4Z05Ahie9XOzNB32wTMZK0orvZreZ5Q1u9okgNP6A+iR72LwBpAyliSuunZnJr8nCOrESS//AactD5ToJ9Sozf5DRvMLifjKPOl0kgFZ5twpj9HTyraYFkuPbnKubehx4qYVtTKNNluh4PfSb TerraformNewMachine"
}



module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]


  tags = {
    Terraform = "true"
    Environment = "dev"
  }
}

resource "aws_subnet" "ESSubnet" {
  vpc_id     = "${module.vpc.vpc_id}"
  cidr_block = "10.0.0.0/24"
  tags = {
    Name = "ESSubnet"
  }
}

resource "aws_security_group" "ESGroup" {

        name = "ESGroup"
        description = "ElasticSearch Security Group"
        vpc_id = "${module.vpc.vpc_id}"

        ingress {

                from_port = 22
                to_port = 22
                protocol = "tcp"

                cidr_blocks = ["204.124.16.0/24", "184.188.101.0/24", "172.23.130.91/32", "209.54.90.100/32", "100.64.14.173/32"]
                }
         ingress {

                from_port = 5601
                to_port = 5601
                protocol = "tcp"
                self = true
                cidr_blocks = ["209.54.90.100/32", "184.188.101.162/32", "10.20.207.15/32"]
                }

        ingress {

                from_port = 9200
                to_port = 9400
                protocol = "tcp"
                self = true
                }


        egress {

                from_port = 0
                to_port = 0
                protocol = "-1"
                cidr_blocks = ["0.0.0.0/0"]

                }
}

resource "aws_iam_role" "elasticsearch_role" {
  name = "elasticsearch_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
      tag-key = "elasticsearch"
  }
}

resource "aws_iam_instance_profile" "elasticsearch_profile" {
  name = "elasticsearch_profile"
  role = "${aws_iam_role.elasticsearch_role.name}"
}

resource "aws_iam_role_policy" "elasticsearch_policy" {
  name = "elasticsearch_policy"
  role = "${aws_iam_role.elasticsearch_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}


resource "aws_instance" "ec2_instance_test1" {
 ami = "${data.aws_ami.ec2-ami.id}"
 instance_type = "t2.small"
 key_name = "TerraformNewMachine"
 user_data_base64 = "${base64encode(local.instance-userdata1)}"
 vpc_security_group_ids = [aws_security_group.ESGroup.id]
 associate_public_ip_address = true
# subnet_id = "${aws_subnet.ESSubnet.id}"
 subnet_id = element(tolist(module.vpc.public_subnets), 1)
#  for_each = toset(module.vpc.public_subnets)
#  subnet_id = each.value
  tags = {
    Name = "ElasticSearchMachine-1"
  }
 iam_instance_profile = "${aws_iam_instance_profile.elasticsearch_profile.name}"

}

resource "aws_instance" "ec2_instance_test2" {
 ami = "${data.aws_ami.ec2-ami.id}"
 instance_type = "t2.small"
 key_name = "TerraformNewMachine"
 user_data_base64 = "${base64encode(local.instance-userdata2)}"
 vpc_security_group_ids = [aws_security_group.ESGroup.id]
 associate_public_ip_address = true
#subnet_id = "${aws_subnet.ESSubnet.id}"
# for_each = toset(module.vpc.public_subnets)
# subnet_id = each.value
 subnet_id = element(tolist(module.vpc.public_subnets), 1)
  tags = {
    Name = "ElasticSearchMachine-2"
  }
 iam_instance_profile = "${aws_iam_instance_profile.elasticsearch_profile.name}"

}

resource "aws_instance" "ec2_instance_test3" {
 ami = "${data.aws_ami.ec2-ami.id}"
 instance_type = "t2.small"
 key_name = "TerraformNewMachine"
 user_data_base64 = "${base64encode(local.instance-userdata3)}"
 vpc_security_group_ids = [aws_security_group.ESGroup.id]
 associate_public_ip_address = true
# subnet_id = "${aws_subnet.ESSubnet.id}"
# for_each = toset(module.vpc.public_subnets)
# subnet_id = each.value
 subnet_id = element(tolist(module.vpc.public_subnets), 1)
  tags = {
    Name = "ElasticSearchMachine-3"
  }
 iam_instance_profile = "${aws_iam_instance_profile.elasticsearch_profile.name}"

}


resource "aws_instance" "ec2_instance_kibana" {
ami = "${data.aws_ami.ec2-ami-kibana.id}"
instance_type = "t2.medium"
key_name = "TerraformNewMachine"
user_data_base64 = "${base64encode(local.instance-userdata4)}"
vpc_security_group_ids = [aws_security_group.ESGroup.id]
associate_public_ip_address = true
#subnet_id = "${aws_subnet.ESSubnet.id}"
subnet_id = element(tolist(module.vpc.public_subnets), 1)
  tags = {
    Name = "KibanaMachine"
  }
iam_instance_profile = "${aws_iam_instance_profile.elasticsearch_profile.name}"

}

resource "aws_instance" "ec2_instance_test1_2" {
 ami = "${data.aws_ami.ec2-ami.id}"
 instance_type = "t2.small"
 key_name = "TerraformNewMachine"
 user_data_base64 = "${base64encode(local.instance-userdata1_test)}"
 vpc_security_group_ids = [aws_security_group.ESGroup.id]
 associate_public_ip_address = true
# subnet_id = "${aws_subnet.ESSubnet.id}"
 subnet_id = element(tolist(module.vpc.public_subnets), 1)
#  for_each = toset(module.vpc.public_subnets)
#  subnet_id = each.value
  tags = {
    Name = "ElasticSearchMachine-1-demo"
  }
 iam_instance_profile = "${aws_iam_instance_profile.elasticsearch_profile.name}"

}

resource "aws_instance" "ec2_instance_test2_2" {
 ami = "${data.aws_ami.ec2-ami.id}"
 instance_type = "t2.small"
 key_name = "TerraformNewMachine"
 user_data_base64 = "${base64encode(local.instance-userdata2_test)}"
 vpc_security_group_ids = [aws_security_group.ESGroup.id]
 associate_public_ip_address = true
#subnet_id = "${aws_subnet.ESSubnet.id}"
# for_each = toset(module.vpc.public_subnets)
# subnet_id = each.value
 subnet_id = element(tolist(module.vpc.public_subnets), 1)
  tags = {
    Name = "ElasticSearchMachine-2-demo"
  }
 iam_instance_profile = "${aws_iam_instance_profile.elasticsearch_profile.name}"

}

resource "aws_instance" "ec2_instance_test3_2" {
 ami = "${data.aws_ami.ec2-ami.id}"
 instance_type = "t2.small"
 key_name = "TerraformNewMachine"
 user_data_base64 = "${base64encode(local.instance-userdata3_test)}"
 vpc_security_group_ids = [aws_security_group.ESGroup.id]
 associate_public_ip_address = true
# subnet_id = "${aws_subnet.ESSubnet.id}"
# for_each = toset(module.vpc.public_subnets)
# subnet_id = each.value
 subnet_id = element(tolist(module.vpc.public_subnets), 1)
  tags = {
    Name = "ElasticSearchMachine-3-demo"
  }
 iam_instance_profile = "${aws_iam_instance_profile.elasticsearch_profile.name}"

}


resource "aws_instance" "ec2_instance_kibana_2" {
ami = "${data.aws_ami.ec2-ami-kibana.id}"
instance_type = "t2.medium"
key_name = "TerraformNewMachine"
user_data_base64 = "${base64encode(local.instance-userdata4_test)}"
vpc_security_group_ids = [aws_security_group.ESGroup.id]
associate_public_ip_address = true
#subnet_id = "${aws_subnet.ESSubnet.id}"
subnet_id = element(tolist(module.vpc.public_subnets), 1)
  tags = {
    Name = "KibanaMachine-demo"
  }
iam_instance_profile = "${aws_iam_instance_profile.elasticsearch_profile.name}"

}
