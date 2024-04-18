import requests
import json
import pandas

url = 'https://api.abuseipdb.com/api/v2/check'

def generate_header(api_key):
    custom_header = {
        'Accept': 'application/json',
        'Key': api_key
    }
    return custom_header
    
# the ingestions seems to drop one rom (the first one? a row with data. fix this!) 
def file_ingest(path):
    data_frame = pandas.read_csv(path, usecols = [0])
    data_frame_no_head = data_frame.tail(-1)
    dataframenoduplicates = data_frame_no_head.drop_duplicates()
    return dataframenoduplicates

def send_request(ip, custom_header):
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    
    response = requests.request(method='GET', url=url, headers=custom_header, params=querystring)
    return response

#This function is way to fat and ugly, I need to slim it down.
def iterate_over_ips(dataframe, custom_header):
    
    fullscore = 0
    nullscore = 0
    
    for column in dataframe.columns:
        for value in dataframe[column].values:
             response = send_request(value, custom_header)
             prettyResponse = response_cleanup(response)
                          
             if prettyResponse == 100:
                 fullscore += 1
             elif prettyResponse == 0: 
                nullscore += 1
             
             print(f'Ip:{value} has a score of {prettyResponse}')
             
    print(f'Final results: \n You ingested {len(dataframe)} ip addresses. \n Of these, {nullscore} received the score 0 and are clear. \n {fullscore} received the score 100 and are probably malicious.')
    
def response_cleanup(response):
    decodedResponse = json.loads(response.text)
    prettyResponse = decodedResponse["data"]["abuseConfidenceScore"]
    
    return prettyResponse

#Get the API key
userinput = input("Please enter your AbuseIPDB API Key: ")
path = input("And please enter the File Path: ")
custom_header = generate_header(userinput)

#ingest the file
ingested_frame = file_ingest(path)

#Send the request
iterate_over_ips(ingested_frame, custom_header)