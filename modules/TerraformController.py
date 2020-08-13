
from python_terraform import *
from tabulate import tabulate
from modules import aws_service, kubernetes_service
import ansible_runner
import yaml
import time
import tarfile
import os
import sys
from jinja2 import Environment, BaseLoader
import glob
import pathlib


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


    def simulate(self, simulation_technique, simulation_file, force, simulation_vars):

        # read definition files from Leonidas
        # search for technique or name
        # run command with subsitution of variables

        filelist = []
        objects = []

        if simulation_technique:
            path ="leonidas/definitions"

            for root, dirs, files in os.walk(path):
                for file in files:
                    if os.path.splitext(file)[1] == ".yml":
                        filepath = os.path.join(root,file)
                        object = self.load_file(filepath)
                        for technique in object['mitre_ids']:
                            if technique == simulation_technique:
                                filelist.append(filepath)
                                objects.append(object)

            if not filelist:
                self.log.error('ERROR: No attack file found for given technique')
                sys.exit(1)

        elif simulation_file:
            filelist.append(simulation_file)
            object = self.load_file(simulation_file)
            objects.append(object)

        for object in objects:
            data = dict()
            if simulation_vars:
                data = dict(item.split("=") for item in simulation_vars.split(", "))
            else:
                for var in object['input_arguments']:
                    data[var] = object['input_arguments'][var]['value']

            rtemplate = Environment(loader=BaseLoader()).from_string(object['executors']['sh']['code'])
            function_call = rtemplate.render(**data)
            print(function_call)
            if force:
                stream = os.popen(function_call)
                output = stream.read()
                print(output)
            else:
                if self.query_yes_no('Run attack command? [default=Y]') or force:
                    stream = os.popen(function_call)
                    output = stream.read()
                    print(output)
                else:
                    self.log.info('Attack is not executed.')


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


    def dump(self, dump_name):
        # download Cloudtrail logs from S3
        # export Cloudwatch logs to S3 and then download them

        folder = "attack_data/" + dump_name
        os.mkdir(folder)

        # Cloudtrail
        if self.config['dump_cloudtrail_data'] == '1':
            self.log.info("Dump Cloudtrail logs. This can take some time.")
            aws_service.download_S3_bucket('AWSLogs', self.config['cloudtrail_s3_bucket'], folder, self.config['cloudtrail_data_from_last_x_hours'], self.config['cloudtrail_data_from_regions'].split(','))

        # Cloudwatch
        if self.config['dump_aws_eks_data'] == '1':
            self.log.info("Dump AWS EKS logs from Cloudwatch. This can take some time.")
            aws_service.download_cloudwatch_logs(self.config, folder)

        # Sync to S3
        if self.config['sync_to_s3_bucket'] == '1':
            self.log.info("upload attack data to S3 bucket. This can take some time")
            for file in self.getListOfFiles(folder):
                self.log.info("upload file " + file  + " to S3 bucket.")
                p = pathlib.Path(file)
                new_path = str(pathlib.Path(*p.parts[1:]))
                aws_service.upload_file_s3_bucket(self.config['s3_bucket_attack_data'], file, new_path)


## helper functions

    def load_file(self, file_path):
        with open(file_path, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                sys.exit("ERROR: reading {0}".format(file_path))
        return object


    def query_yes_no(self, question, default="yes"):
        """Ask a yes/no question via raw_input() and return their answer.

        "question" is a string that is presented to the user.
        "default" is the presumed answer if the user just hits <Enter>.
            It must be "yes" (the default), "no" or None (meaning
            an answer is required of the user).

        The "answer" return value is True for "yes" or False for "no".
        """
        valid = {"yes": True, "y": True, "ye": True,
                 "no": False, "n": False}
        if default is None:
            prompt = " [y/n] "
        elif default == "yes":
            prompt = " [Y/n] "
        elif default == "no":
            prompt = " [y/N] "
        else:
            raise ValueError("invalid default answer: '%s'" % default)

        while True:
            sys.stdout.write(question + prompt)
            choice = input().lower()
            if default is not None and choice == '':
                return valid[default]
            elif choice in valid:
                return valid[choice]
            else:
                sys.stdout.write("Please respond with 'yes' or 'no' "
                                 "(or 'y' or 'n').\n")


    def getListOfFiles(self, dirName):
        # create a list of file and sub directories
        # names in the given directory
        listOfFile = os.listdir(dirName)
        allFiles = list()
        # Iterate over all the entries
        for entry in listOfFile:
            # Create full path
            fullPath = os.path.join(dirName, entry)
            # If entry is a directory then get the list of files in this directory
            if os.path.isdir(fullPath):
                allFiles = allFiles + self.getListOfFiles(fullPath)
            else:
                allFiles.append(fullPath)

        return allFiles
