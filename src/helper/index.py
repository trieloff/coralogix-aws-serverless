#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function
import json
import boto3
import cfnresponse

print('Loading function')
s3 = boto3.resource('s3')

def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, indent=2))
    responseData={}
    try:
        if event['RequestType'] == 'Delete':
            print("Request Type:",event['RequestType'])
            Bucket=event['ResourceProperties']['Bucket']
            delete_notification(Bucket)
            print("Sending response to custom resource after Delete")
        elif event['RequestType'] == 'Create' or event['RequestType'] == 'Update':
            print("Request Type:",event['RequestType'])
            LambdaArn=event['ResourceProperties']['LambdaArn']
            Bucket=event['ResourceProperties']['Bucket']
            Prefix=event['ResourceProperties']['Prefix']
            Suffix=event['ResourceProperties']['Suffix']
            add_notification(LambdaArn, Bucket, Prefix, Suffix)
            responseData={'Bucket':Bucket}
            print("Sending response to custom resource")
        responseStatus = 'SUCCESS'
    except Exception as e:
        print('Failed to process:', e)
        responseStatus = 'FAILED'
        responseData = {'Failure': 'Something bad happened.'}
    finally:
        cfnresponse.send(event, context, responseStatus, responseData)

def add_notification(LambdaArn, Bucket, Prefix, Suffix):
    s3.BucketNotification(Bucket).put(
        NotificationConfiguration={
            'LambdaFunctionConfigurations': [
                {
                    'LambdaFunctionArn': LambdaArn,
                    'Filter': {
                        'Key': {
                            'FilterRules': [
                                {
                                    'Name': 'prefix',
                                    'Value': Prefix
                                },
                                {
                                    'Name': 'suffix',
                                    'Value': Suffix
                                },
                            ]
                        }
                    },
                    'Events': [
                        's3:ObjectCreated:*'
                    ]
                }
            ]
        }
    )
    print("Put request completed....")

def delete_notification(Bucket):
    s3.BucketNotification(Bucket).put(
        NotificationConfiguration={}
    )
    print("Delete request completed....")
