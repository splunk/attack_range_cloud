import sys
import re
import boto3
from botocore.exceptions import ClientError
import uuid
import time
import yaml
import os
from datetime import datetime
from datetime import timedelta


def get_instance_by_name(ec2_name, config):
    instances = get_all_instances(config)
    for instance in instances:
        str = instance['Tags'][0]['Value']
        if str == ec2_name:
            return instance

def get_single_instance_public_ip(ec2_name, config):
    instance = get_instance_by_name(ec2_name, config)
    return instance['NetworkInterfaces'][0]['Association']['PublicIp']


def get_all_instances(config):
    key_name = config['key_name']
    region = config['region']
    client = boto3.client('ec2', region_name=region)
    response = client.describe_instances(
        Filters=[
            {
                'Name': "key-name",
                'Values': [key_name]
            }
        ]
    )
    instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            if instance['State']['Name']!='terminated':
                if len(instance['Tags']) > 0:
                    str = instance['Tags'][0]['Value']
                    if (config['range_name'] in str) and (config['key_name'] in str) and ('cloud-ar' in str):
                        
                        instances.append(instance)

    return instances


def get_splunk_instance_ip(config):
    all_instances = get_all_instances(config)
    for instance in all_instances:
        if instance['Tags'][0]['Value'] == 'cloud-attack-range-splunk-server':
            return instance['NetworkInterfaces'][0]['PrivateIpAddresses'][0]['Association']['PublicIp']


def check_ec2_instance_state(ec2_name, state, config):
    instance = get_instance_by_name(ec2_name, config)

    if not instance:
        log.error(ec2_name + ' not found as AWS EC2 instance.')
        sys.exit(1)

    return (instance['State']['Name'] == state)


def change_ec2_state(instances, new_state, log, config):

    region = config['region']
    client = boto3.client('ec2', region_name=region)

    if len(instances) == 0:
        log.error(ec2_name + ' not found as AWS EC2 instance.')
        sys.exit(1)

    if new_state == 'stopped':
        for instance in instances:
            if instance['State']['Name'] == 'running':
                response = client.stop_instances(
                    InstanceIds=[instance['InstanceId']]
                )
                log.info('Successfully stopped instance with ID ' +
                      instance['InstanceId'] + ' .')

    elif new_state == 'running':
        for instance in instances:
            if instance['State']['Name'] == 'stopped':
                response = client.start_instances(
                    InstanceIds=[instance['InstanceId']]
                )
                log.info('Successfully started instance with ID ' + instance['InstanceId'] + ' .')


def download_S3_bucket(directory, bucket, local_dir, last_x_hours, regions):
    client = boto3.client('s3')
    resource = boto3.resource('s3')
    download_dir(client, resource, directory, last_x_hours, regions, local_dir, bucket=bucket)


def download_dir(client, resource, dist, last_x_hours, regions, local='/tmp', bucket='your_bucket'):
    paginator = client.get_paginator('list_objects')
    for result in paginator.paginate(Bucket=bucket, Delimiter='/', Prefix=dist):
        if result.get('CommonPrefixes') is not None:
            for subdir in result.get('CommonPrefixes'):
                download_dir(client, resource, subdir.get('Prefix'), last_x_hours, regions, local, bucket)
        for file in result.get('Contents', []):
            dest_pathname = os.path.join(local, file.get('Key'))
            for region in regions:
                if file.get('Key').count(region):
                    try:
                        response = resource.meta.client.get_object(Bucket=bucket, Key=file.get('Key'), IfModifiedSince=(datetime.utcnow() - timedelta(hours=int(last_x_hours))))
                        if not os.path.exists(os.path.dirname(dest_pathname)):
                            os.makedirs(os.path.dirname(dest_pathname))
                        resource.meta.client.download_file(bucket, file.get('Key'), dest_pathname)
                    except:
                        pass


def upload_file_s3_bucket(s3_bucket, file_path, S3_file_path):
    s3_client = boto3.client('s3')
    response = s3_client.upload_file(file_path, s3_bucket, S3_file_path)


def download_cloudwatch_logs(config, local_dir):
    # Create an export task
    # poll for completition
    # download data from s3

    client = boto3.client('logs')
    response_export_task = client.create_export_task(
        taskName='aws_eks_export_task',
        logGroupName=str('/aws/eks/kubernetes_' + config['key_name'] + '/cluster'),
        fromTime=int((datetime.utcnow() - timedelta(hours=int(config['eks_data_from_last_x_hours'])) - datetime(1970,1,1)).total_seconds() * 1000.0),
        to=int((datetime.utcnow() - datetime(1970,1,1)).total_seconds() * 1000.0),
        destination=config['s3_bucket_cloudwatch_eks_export'],
        destinationPrefix='aws_eks_logs'
    )

    while True:
        response = client.describe_export_tasks(taskId=response_export_task['taskId'])
        if response['exportTasks'][0]['status']['code'] == 'COMPLETED':
            break

    client_s3 = boto3.client('s3')
    resource_s3 = boto3.resource('s3')
    download_dir_aws_eks(client_s3, resource_s3, 'aws_eks_logs', local=local_dir, bucket=config['s3_bucket_cloudwatch_eks_export'])


def download_dir_aws_eks(client, resource, dist, local='/tmp', bucket='your_bucket'):
    paginator = client.get_paginator('list_objects')
    for result in paginator.paginate(Bucket=bucket, Delimiter='/', Prefix=dist):
        if result.get('CommonPrefixes') is not None:
            for subdir in result.get('CommonPrefixes'):
                download_dir_aws_eks(client, resource, subdir.get('Prefix'), local, bucket)
        for file in result.get('Contents', []):
            dest_pathname = os.path.join(local, file.get('Key'))
            if not os.path.exists(os.path.dirname(dest_pathname)):
                os.makedirs(os.path.dirname(dest_pathname))
            resource.meta.client.download_file(bucket, file.get('Key'), dest_pathname)
