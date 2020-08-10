provider "aws" {
  region     =  var.config.region
}

module "networkModule" {
  source			  = "./modules/network"
  config                = var.config
}

module "splunk-server" {
  source			           = "./modules/splunk-server"
	vpc_security_group_ids = module.networkModule.sg_vpc_id
	ec2_subnet_id         = module.networkModule.ec2_subnet_id
  phantom_server_instance = module.phantom-server.phantom_server_instance
  config                = var.config
}

module "phantom-server" {
  source                     = "./modules/phantom-server"
  vpc_security_group_ids = module.networkModule.sg_vpc_id
	ec2_subnet_id          = module.networkModule.ec2_subnet_id
  config                 = var.config
}

module "kubernetes" {
  source                = "./modules/kubernetes"
  config                = var.config
  vpc_id                = module.networkModule.vpc_id
  vpc_private_subnets   = module.networkModule.vpc_private_subnets
  sg_worker_group_mgmt_one_id = module.networkModule.sg_worker_group_mgmt_one_id
  sg_worker_group_mgmt_two_id = module.networkModule.sg_worker_group_mgmt_two_id
}
