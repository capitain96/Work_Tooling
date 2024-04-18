import argparse
import pandas
import requests

def initialize_argparser():
    parser = argparse.ArgumentParser(description='Hello user, this script will take a csv of process/file hashes and check it against VT')

    parser.add_argument('--filepath', type=str,required=True , help='the filepath to the csv with the indicators to be tested')
    parser.add_argument('--apikey', type=str,required=True , help='The VT API key')
    parser.add_argument('--column', type=str, help='the name of the column containing the hashes', default="hashes")
    
    return parser.parse_args()

def read_csv_file(args):
    try:
        csv_file = pandas.read_csv(args.filepath)
        if "verdict" not in csv_file.columns:
            csv_file.insert(csv_file.columns.get_loc(args.column)+1,"verdict",None)
        return csv_file
    except Exception as e:
        print("An error occurred: ", e)

def write_csv_file(csv_file, file_path):
    try:
        return csv_file.to_csv(file_path)
    except Exception as e:
        print("An error occurred: ", e)

def VT_request(hash,api_key):
    url = "https://www.virustotal.com/api/v3/files/"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key}
    try:
        response = requests.get(url+hash, headers=headers)
        if response.status_code == 200:
            print("Request successful!")
            prettified_response = response_prettifier(response.json())
            return prettified_response
        elif response.status_code == 404:
            print("Request successful!")
            return("No record found")
        elif response.status_code == 429:
            print("API quoty exceeded, exiting...")
            return 429
        else:
            print(f"Request failed with status code {response.status_code} due to {response.text}")
            return f"Error {response.status_code}"
    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)
        return None
    
def response_prettifier(reply):
    malicious = reply["data"]["attributes"]["last_analysis_stats"]["malicious"]
    suspicious = reply["data"]["attributes"]["last_analysis_stats"]["suspicious"]

    undetected = reply["data"]["attributes"]["last_analysis_stats"]["undetected"]
    harmless = reply["data"]["attributes"]["last_analysis_stats"]["harmless"]

    timeout = reply["data"]["attributes"]["last_analysis_stats"]["timeout"]
    failure = reply["data"]["attributes"]["last_analysis_stats"]["failure"]
    type_unsupported = reply["data"]["attributes"]["last_analysis_stats"]["type-unsupported"]

    return f"Bad {malicious + suspicious} | Good: {undetected + harmless} | N/A: {timeout+failure+type_unsupported}"

def hashes_checker(csv_file, args):
    for index, row in csv_file.iterrows():
        reply = VT_request(row[args.column], args.apikey)
        if reply == 429:
            return csv_file
        else:
            csv_file.loc[index, "verdict"] = reply

    return csv_file

def main():
    args = initialize_argparser()
    csv_file = read_csv_file(args)

    csv_file_enriched = hashes_checker(csv_file,args)

    write_csv_file(csv_file_enriched, args.filepath)
    print("All done")

main()
