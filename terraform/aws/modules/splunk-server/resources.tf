

data "aws_ami" "latest-ubuntu" {
  most_recent = true
  owners = ["099720109477"] # Canonical

  filter {
      name   = "name"
      values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
  }

  filter {
      name   = "virtualization-type"
      values = ["hvm"]
  }
}

resource "aws_iam_role" "splunk_role" {
  name = "cloud_ar_splunk_role_${var.config.key_name}"

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

}

resource "aws_iam_instance_profile" "splunk_profile" {
  name = "cloud_ar_splunk_profile_${var.config.key_name}"
  role = aws_iam_role.splunk_role.name
}


data "aws_iam_policy_document" "splunk_logging" {

  statement {
    actions = [
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:DescribeDestinations",
      "logs:DescribeDestinations",
      "logs:TestMetricFilter",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    actions = [
      "logs:Describe*",
      "logs:Get*",
      "logs:FilterLogEvents",
    ]

    resources = [
      "arn:aws:logs:*:log-group:/aws/eks/kubernetes_${var.config.key_name}/cluster*",
    ]
  }

  statement {
    actions = [
      "sqs:GetQueueAttributes",
      "sqs:ListQueues",
      "sqs:ReceiveMessage",
      "sqs:GetQueueUrl",
      "sqs:DeleteMessage",
      "s3:Get*",
      "s3:List*",
      "s3:Delete*",
      "kms:Decrypt",
    ]

    resources = [
      "*"
    ]
  }
}

resource "aws_iam_role_policy" "splunk_logging_policy" {
  name = "cloud_ar_splunk_logging_policy_${var.config.key_name}"
  role = aws_iam_role.splunk_role.id
  policy = data.aws_iam_policy_document.splunk_logging.json
}


resource "aws_instance" "splunk-server" {
  ami           = data.aws_ami.latest-ubuntu.id
  instance_type = "t2.2xlarge"
  key_name = var.config.key_name
  subnet_id = var.ec2_subnet_id
  vpc_security_group_ids = [var.vpc_security_group_ids]
  private_ip = var.config.splunk_server_private_ip
  iam_instance_profile = aws_iam_instance_profile.splunk_profile.name
  monitoring = true
  depends_on = [var.phantom_server_instance]
  root_block_device {
    volume_type = "gp2"
    volume_size = "30"
    delete_on_termination = "true"
  }
  tags = {
    Name = "cloud-ar-splunk-${var.config.range_name}-${var.config.key_name}"
  }

  provisioner "remote-exec" {
    inline = ["echo booted"]

    connection {
      type        = "ssh"
      user        = "ubuntu"
      host        = aws_instance.splunk-server.public_ip
      private_key = file(var.config.private_key_path)
    }
  }

  provisioner "local-exec" {
    working_dir = "../../ansible"
    command = "ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -u ubuntu --private-key ${var.config.private_key_path} -i '${aws_instance.splunk-server.public_ip},' splunk_server.yml -e 'ansible_python_interpreter=/usr/bin/python3 splunk_admin_password=${var.config.attack_range_password} splunk_url=${var.config.splunk_url} splunk_binary=${var.config.splunk_binary} s3_bucket_url=${var.config.s3_bucket_url} splunk_escu_app=${var.config.splunk_escu_app} splunk_asx_app=${var.config.splunk_asx_app} splunk_cim_app=${var.config.splunk_cim_app} splunk_python_app=${var.config.splunk_python_app} splunk_mltk_app=${var.config.splunk_mltk_app} install_es=${var.config.install_es} splunk_es_app=${var.config.splunk_es_app} phantom_app=${var.config.phantom_app} phantom_server=${var.config.phantom_server} phantom_server_private_ip=${var.config.phantom_server_private_ip} phantom_admin_password=${var.config.attack_range_password} splunk_security_essentials_app=${var.config.splunk_security_essentials_app} splunk_server_private_ip=${var.config.splunk_server_private_ip} install_mltk=${var.config.install_mltk} splunk_aws_app=${var.config.splunk_aws_app} sqs_queue_url=${var.config.sqs_queue_url} key_name=${var.config.key_name} region=${var.config.region}'"
  }
}

resource "aws_eip" "splunk_ip" {
  instance = aws_instance.splunk-server.id
}
