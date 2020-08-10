
from python_terraform import *
from tabulate import tabulate
from modules import aws_service, kubernetes_service
import ansible_runner
import yaml
import time
import tarfile
import os


class TerraformController():

    def __init__(self, config, log):
        self.config = config
        self.log = log
        custom_dict = self.config.copy()
        variables = dict()
        variables['config'] = custom_dict
        self.terraform = Terraform(working_dir='terraform',variables=variables)


    def build(self):
        self.log.info("[action] > build\n")
        return_code, stdout, stderr = self.terraform.apply(capture_output='yes', skip_plan=True, no_color=IsNotFlagged)
        if not return_code:
           self.log.info("attack_range has been built using terraform successfully")

        if self.config["kubernetes"]=="1":
            kubernetes_service.install_application(self.config, self.log)

        self.list_machines()


    def destroy(self):
        if self.config["kubernetes"]=="1":
            kubernetes_service.delete_application(self.config, self.log)
        self.log.info("[action] > destroy\n")
        return_code, stdout, stderr = self.terraform.destroy(capture_output='yes', no_color=IsNotFlagged)
        self.log.info("attack_range has been destroy using terraform successfully")


    def stop(self):
        instances = aws_service.get_all_instances(self.config)
        aws_service.change_ec2_state(instances, 'stopped', self.log)


    def resume(self):
        instances = aws_service.get_all_instances(self.config)
        aws_service.change_ec2_state(instances, 'running', self.log)


    def simulate(self, target, simulation_techniques, simulation_atomics, var_str = 'no'):
        pass


    def list_machines(self):
        instances = aws_service.get_all_instances(self.config)
        response = []
        instances_running = False
        for instance in instances:
            if instance['State']['Name'] == 'running':
                instances_running = True
                response.append([instance['Tags'][0]['Value'], instance['State']['Name'], instance['NetworkInterfaces'][0]['Association']['PublicIp']])
            else:
                response.append([instance['Tags'][0]['Value'], instance['State']['Name']])
        print()
        print('Status EC2 Machines\n')
        if len(response) > 0:
            if instances_running:
                print(tabulate(response, headers=['Name','Status', 'IP Address']))
            else:
                print(tabulate(response, headers=['Name','Status']))
        else:
            print("ERROR: Can't find configured EC2 Attack Range Instances in AWS.")
        print()

        if self.config['kubernetes'] == '1':
            print()
            print('Status Kubernetes\n')
            kubernetes_service.list_deployed_applications()
            print()
