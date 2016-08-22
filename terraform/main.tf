provider "aws" {
  access_key = "${var.access_key}"
  secret_key = "${var.secret_key}"
  region     = "${var.region}"
}

resource "aws_instance" "unik-hub" {
  ami           = "ami-c60b90d1"
  instance_type = "t2.small"
  provisioner "file" {
    source = "provision.sh"
    destination = "/tmp/provision.sh"
    connection = {
      user = "ubuntu"
      type = "ssh"
      private_key = "${file("${var.private_key_path}")}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "bash /tmp/provision.sh ${var.access_key} ${var.secret_key} ${var.region} ${var.bucket}"
    ]
    connection = {
      user = "ubuntu"
      type = "ssh"
      private_key = "${file("${var.private_key_path}")}"
    }
  }
  tags {
      Name = "Unik-Hub Sever 0.1"
  }
  key_name = "${var.key_name}"
}