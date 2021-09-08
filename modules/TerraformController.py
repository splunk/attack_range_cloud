from modules.IEnvironmentController import IEnvironmentController
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
import re


class TerraformController(IEnvironmentController):

    def __init__(self, config, log):
        super().__init__(config, log)
        statefile = self.config['range_name'] + ".terraform.tfstate"
        if self.config['cloud_provider'] == 'aws':
            self.config["statepath"] = os.path.join(os.path.dirname(__file__), '../terraform/aws/state', statefile)
        elif self.config['cloud_provider'] == 'azure':
            self.config["statepath"] = os.path.join(os.path.dirname(__file__), '../terraform/azure/state', statefile)

        self.config['splunk_es_app_version'] = re.findall(r'\d+', self.config['splunk_es_app'])[0]

        custom_dict = self.config.copy()
        variables = dict()
        variables['config'] = custom_dict

        if self.config['cloud_provider'] == 'aws':
            self.terraform = Terraform(working_dir=os.path.join(os.path.dirname(__file__), '../terraform/aws'),variables=variables, parallelism=15 ,state=config["statepath"])
    

    def build(self):

        self.log.info("[action] > build\n")
        return_code, stdout, stderr = self.terraform.apply(capture_output='yes', skip_plan=True, no_color=IsNotFlagged)
        if not return_code:
           self.log.info("attack_range has been built using terraform successfully")

           if self.config["kubernetes"]=="1":
               kubernetes_service.install_application(self.config, self.log)

           self.list_machines()


    def destroy(self):

        self.log.info("[action] > destroy\n")
        return_code, stdout, stderr = self.terraform.destroy(
            capture_output='yes', no_color=IsNotFlagged)
        self.log.info("Destroyed with return code: " + str(return_code))
        statepath = self.config["statepath"]
        statebakpath = self.config["statepath"] + ".backup"
        if os.path.exists(statepath) and return_code==0:
            try:
                os.remove(statepath)
                os.remove(statebakpath)
            except Exception as e:
                self.log.error("not able to delete state file")
        self.log.info(
            "attack_range has been destroy using terraform successfully")

        if self.config["kubernetes"]=="1":
            kubernetes_service.delete_application(self.config, self.log)
        self.log.info("[action] > destroy\n")
        return_code, stdout, stderr = self.terraform.destroy(capture_output='yes', no_color=IsNotFlagged, force=IsNotFlagged, auto_approve=True)
        self.log.info("attack_range has been destroy using terraform successfully")


    def stop(self):
        if self.config['cloud_provider'] == 'aws':
            instances = aws_service.get_all_instances(self.config)
            aws_service.change_ec2_state(instances, 'stopped', self.log, self.config)
        elif self.config['cloud_provider'] == 'azure':
            azure_service.change_instance_state(self.config, 'stopped', self.log)

    def resume(self):
        if self.config['cloud_provider'] == 'aws':
            instances = aws_service.get_all_instances(self.config)
            aws_service.change_ec2_state(instances, 'running', self.log, self.config)
        elif self.config['cloud_provider'] == 'azure':
            azure_service.change_instance_state(self.config, 'running', self.log)
        
    def test(self, test_file):
        # read test file
        test_file = self.load_file(test_file)

        # build attack range
        self.build()

        epoch_time = str(int(time.time()))
        folder_name = "attack_data_" + epoch_time
        os.mkdir(os.path.join(os.path.dirname(__file__), '../attack_data/' + folder_name))

        output = 'loaded attack data'

        if self.config['update_escu_app'] == '1':
            self.update_ESCU_app()

        result_tests = []

        for test in test_file['tests']:
            result_test = {}
            for attack_data in test['attack_data']:
                url = attack_data['data']
                r = requests.get(url, allow_redirects=True)
                open(os.path.join(os.path.dirname(__file__), '../attack_data/' + folder_name + '/' + attack_data['file_name']), 'wb').write(r.content)

                # Update timestamps before replay
                if 'update_timestamp' in attack_data:
                    if attack_data['update_timestamp'] == True:
                        data_manipulation = DataManipulation()
                        data_manipulation.manipulate_timestamp(folder_name + '/' + attack_data['file_name'], self.log, attack_data['sourcetype'], attack_data['source'])

                self.replay_attack_data(folder_name, None, {'sourcetype': attack_data['sourcetype'], 'source': attack_data['source'], 'out': attack_data['file_name']})

            self.log.info('Wait for 200 seconds')
            time.sleep(200)

            if 'baselines' in test:
                results_baselines = []
                for baseline_obj in test['baselines']:
                    baseline_file_name = baseline_obj['file']
                    baseline = self.load_file(os.path.join(os.path.dirname(__file__), '../../security_content/' + baseline_file_name))
                    result_obj = dict()
                    result_obj['baseline'] = baseline_obj['name']
                    result_obj['baseline_file'] = baseline_obj['file']
                    if self.config['cloud_provider'] == 'aws':
                        instance = aws_service.get_instance_by_name(
                            'ar-splunk-' + self.config['range_name'] + '-' + self.config['key_name'], self.config)
                        if instance['State']['Name'] == 'running':
                            result = splunk_sdk.test_baseline_search(instance['NetworkInterfaces'][0]['Association']['PublicIp'], str(self.config['attack_range_password']), baseline['search'], baseline_obj['pass_condition'], baseline['name'], baseline_obj['file'], baseline_obj['earliest_time'], baseline_obj['latest_time'], self.log)
                            results_baselines.append(result)
                        else:
                            self.log.error('ERROR: Splunk server is not running.')
                    elif self.config['cloud_provider'] == 'azure':
                        instance = azure_service.get_instance(self.config, "ar-splunk-" + self.config['range_name'] + "-" + self.config['key_name'], self.log)
                        if instance['vm_obj'].instance_view.statuses[1].display_status == "VM running":
                            result = splunk_sdk.test_baseline_search(instance['public_ip'], str(self.config['attack_range_password']), baseline['search'], baseline_obj['pass_condition'], baseline['name'], baseline_obj['file'], baseline_obj['earliest_time'], baseline_obj['latest_time'], self.log)
                            results_baselines.append(result)
                result_test['baselines_result'] = results_baselines

            detection_file_name = test['file']
            detection = self.load_file(os.path.join(os.path.dirname(__file__), '../../security_content/detections/' + detection_file_name))
            if self.config['cloud_provider'] == 'aws':
                instance = aws_service.get_instance_by_name(
                    'ar-splunk-' + self.config['range_name'] + '-' + self.config['key_name'], self.config)
                if instance['State']['Name'] == 'running':
                    result_detection = splunk_sdk.test_detection_search(instance['NetworkInterfaces'][0]['Association']['PublicIp'], str(self.config['attack_range_password']), detection['search'], test['pass_condition'], detection['name'], test['file'], test['earliest_time'], test['latest_time'], self.log)
                    self.log.info('Running Detections now.')
                else:
                    self.log.error('ERROR: Splunk server is not running.')
            elif self.config['cloud_provider'] == 'azure':
                instance = azure_service.get_instance(self.config, "ar-splunk-" + self.config['range_name'] + "-" + self.config['key_name'], self.log)
                if instance['vm_obj'].instance_view.statuses[1].display_status == "VM running":
                    result_detection = splunk_sdk.test_detection_search(instance['public_ip'], str(self.config['attack_range_password']), detection['search'], test['pass_condition'], detection['name'], test['file'], test['earliest_time'], test['latest_time'], self.log)
                    self.log.info('Running Detections now.')

            result_detection['detection_name'] = test['name']
            result_detection['detection_file'] = test['file']
            result_test['detection_result'] = result_detection
            result_tests.append(result_test)

        self.log.info('Running Detections - Complete')

        # destroy attack range
        self.destroy()

        return result_tests


    def load_file(self, file_path):
        with open(file_path, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                sys.exit("ERROR: reading {0}".format(file_path))
        return object

    def find_attack_yaml(self,path,simulation_techniques):
        objects = []
        for root, dirs, files in os.walk(path):
                for file in files:
                    if os.path.splitext(file)[1] == ".yaml":
                        file = file.replace('.yaml','')
                       
                        if simulation_techniques == file:
                            
                            filename = file + ".yaml"
                            filepath = os.path.join(root,filename)                
                            object = self.load_file(filepath)
                            objects.append(object)

        return objects
    #This Function is to replace variables in the atomic yamls

    def replace_simulation_vars(self,atomic_tests,clean_up):

        if clean_up == 'no':
            for key, value in atomic_tests['input_arguments'].items():

                old_command = (str(atomic_tests['executor']['command']))

                if key in old_command:
                    new_command = old_command.replace(key,value['default']).replace('#{','').replace('}','')
                    
        if clean_up == 'yes':
            for key, value in atomic_tests['input_arguments'].items():

                old_command = (str(atomic_tests['executor']['cleanup_command']))

                if key in old_command:
                    new_command = old_command.replace(key,value['default']).replace('#{','').replace('}','')
        
        if  '$PathToAtomicsFolder' in  new_command:
            new_command = new_command.replace('$PathToAtomicsFolder',self.config['atomic_red_team_path'])  
            
        return (new_command)

    #This Function is to simulate specific techniques 
    def simulate_techniques(self,simulation_techniques,clean_up, var_str='no'):
 
            path = self.config['atomic_red_team_path']
            new_commands=[]
            objects = self.find_attack_yaml(path,simulation_techniques)
            

            if simulation_techniques and clean_up == 'no':
                for object in objects:
                
                    data = dict()
                    for atomic_tests in object['atomic_tests']:
                        if 'iaas:aws' not in (atomic_tests['supported_platforms']): 
                            print("WARNING - NOT an AWS Atomic test:",atomic_tests['name'])

                        if 'iaas:aws' in (atomic_tests['supported_platforms']): 
                            new_command = self.replace_simulation_vars(atomic_tests,clean_up)
                            print("Simulating Atomic {0}:\n{1}".format(object['attack_technique'], atomic_tests['name']))
                            rtemplate = Environment(loader=BaseLoader()).from_string(new_command)
                            function_call = rtemplate.render(**data)
                            stream = os.popen(function_call)
                            output = stream.read()
                            print(output)
                            print("Finished Simulating\n")                         
           

            if simulation_techniques and clean_up == 'yes':

                for object in objects:
                
                    data = dict()

                    for atomic_tests in object['atomic_tests']:
                        if 'iaas:aws' not in (atomic_tests['supported_platforms']): 
                            print("WARNING - NOT an AWS Atomic test:",atomic_tests['name'])

                        if 'iaas:aws' in (atomic_tests['supported_platforms']):
                            new_command = self.replace_simulation_vars(atomic_tests,clean_up)
                            print("Clean up {0}:\n{1}".format(object['attack_technique'], atomic_tests['name']))
                            rtemplate = Environment(loader=BaseLoader()).from_string(new_command)
                            function_call = rtemplate.render(**data)
                            stream = os.popen(function_call)
                            output = stream.read()
                            print(output)
                            print("Finished Clean up\n")
                                                               
                            
    # Main function :To be tested and refactored
    def simulate(self, simulation_techniques,clean_up, var_str='no'):

        if os.path.isdir(self.config['atomic_red_team_path']) == False:
            print(" ERROR: Atomic Red Team file path is not set or the path is incorrect in the conf file: ", self.config['atomic_red_team_path'])
            sys.exit(1)

            
        if simulation_techniques and clean_up == 'no':
            self.simulate_techniques(simulation_techniques,clean_up
                )
            

        if simulation_techniques  and clean_up == 'yes':
            self.simulate_techniques(simulation_techniques,clean_up
                )
     
        
    def list_machines(self):
        if self.config['cloud_provider'] == 'aws':
            instances = aws_service.get_all_instances(self.config)
            response = []

            instances_running = False
            for instance in instances:
                if instance['State']['Name'] == 'running':
                    instances_running = True
                    
                    response.append([instance['Tags'][0]['Value'], instance['State']['Name'],
                                     instance['NetworkInterfaces'][0]['Association']['PublicIp']])
                else:
                    response.append([instance['Tags'][0]['Value'],
                                     instance['State']['Name']])

        print()
        print('Status Virtual Machines\n')
        if len(response) > 0:
            if instances_running:
                print(tabulate(response, headers=[
                      'Name', 'Status', 'IP Address']))
            else:
                print(tabulate(response, headers=['Name', 'Status']))
        else:
            print("ERROR: Can't find configured Attack Range Instances")
        print()
        
        if self.config['kubernetes'] == '1':
            print()
            print('Status Kubernetes\n')
            kubernetes_service.list_deployed_applications()
            print()



    def dump_attack_data(self, dump_name, last_sim):
        self.log.info("Dump log data")

        folder = "attack_data/" + dump_name
        os.mkdir(os.path.join(os.path.dirname(__file__), '../' + folder))

        server_str = ("ar-splunk-" + self.config['range_name'] + "-" + self.config['key_name'])
        if self.config['cloud_provider'] == 'aws':
            target_public_ip = aws_service.get_single_instance_public_ip(server_str, self.config)
            ansible_user = 'Administrator'
            ansible_port = 5986
        elif self.config['cloud_provider'] == 'azure':
            target_public_ip = azure_service.get_instance(self.config, server_str, self.log)['public_ip']
            ansible_user = 'AzureAdmin'
            ansible_port = 5985

        with open(os.path.join(os.path.dirname(__file__), '../attack_data/dumps.yml')) as dumps:
            for dump in yaml.full_load(dumps):
                if dump['enabled']:
                    dump_out = dump['dump_parameters']['out']
                    if last_sim:
                        # if last_sim is set, then it overrides time in dumps.yml
                        # and starts dumping from last simulation
                        with open(os.path.join(os.path.dirname(__file__),
                                               "../attack_data/.%s-last-sim.tmp" % self.config['range_name']),
                                  'r') as ls:
                            sim_ts = float(ls.readline())
                            dump['dump_parameters']['time'] = "-%ds" % int(time.time() - sim_ts)
                    dump_search = "search %s earliest=%s | sort 0 _time" \
                                  % (dump['dump_parameters']['search'], dump['dump_parameters']['time'])
                    dump_info = "Dumping Splunk Search to %s " % dump_out
                    self.log.info(dump_info)
                    out = open(os.path.join(os.path.dirname(__file__), "../attack_data/" + dump_name + "/" + dump_out), 'wb')
                    splunk_sdk.export_search(target_public_ip,
                                             s=dump_search,
                                             password=self.config['attack_range_password'],
                                             out=out)
                    out.close()
                    self.log.info("%s [Completed]" % dump_info)


    def replay_attack_data(self, dump_name, dump, replay_parameters = None):
        if self.config['cloud_provider'] == 'aws':
            splunk_ip = aws_service.get_single_instance_public_ip("ar-splunk-" + self.config['range_name'] + "-" + self.config['key_name'], self.config)
        elif self.config['cloud_provider'] == 'azure':
            splunk_ip = azure_service.get_instance(self.config, "ar-splunk-" + self.config['range_name'] + "-" + self.config['key_name'], self.log)['public_ip']

        if replay_parameters == None:
            with open(os.path.join(os.path.dirname(__file__), '../attack_data/dumps.yml')) as dump_fh:
                for d in yaml.full_load(dump_fh):
                    if (d['name'] == dump or dump is None) and d['enabled']:
                        if 'update_timestamp' in d['replay_parameters']:
                            if d['replay_parameters']['update_timestamp'] == True:
                                print('d1')
                                data_manipulation = DataManipulation()
                                data_manipulation.manipulate_timestamp(os.path.join(dump_name, d['dump_parameters']['out']), self.log, d['replay_parameters']['sourcetype'], d['replay_parameters']['source'])
                        self.replay_attack_dataset(splunk_ip, dump_name, d['replay_parameters']['index'], d['replay_parameters']['sourcetype'], d['replay_parameters']['source'], d['dump_parameters']['out'])
        else:
            self.replay_attack_dataset(splunk_ip, dump_name, 'test', replay_parameters['sourcetype'], replay_parameters['source'], replay_parameters['out'])
