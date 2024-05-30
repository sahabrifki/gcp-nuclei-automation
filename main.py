import subprocess
import json
import os
from datetime import date,datetime
from slack_sdk import WebClient
import requests
import psutil
import time
import sqlite3


current_date = date.today()
now_time = datetime.now()
current_time = now_time.strftime("%H:%M:%S")
#print("Current time Launch ", current_time)

message = f"Hi Infosec Team, automated scanning for today {current_date} completed at {current_time}"
notif_launch_messages = f"Hi Infosec Team, automated scanning for today {current_date} is starting at {current_time}"
slack_token = ""


def list_external_ips():
    external_ips = []
    # Get a list of all projects
    projects_output = subprocess.run(["gcloud", "projects", "list", "--format=json", "--quiet"], capture_output=True, text=True)
    projects = json.loads(projects_output.stdout)

    for project in projects:
        project_id = project["projectId"]
        print ("Checking for Project " + project_id)

        # Get a list of all external IP addresses in the project
        ip_output = subprocess.run(["gcloud", "compute", "addresses", "list", "--format=json", "--quiet", "--project", project_id], capture_output=True, text=True)
        ips_json = json.loads(ip_output.stdout)

        if ips_json:
            for x in ips_json:
                if (x["addressType"] == "EXTERNAL"):
                    print ("(+)External IP addresses found: " + x["address"])
                    external_ips.append(x["address"])

    return external_ips

def write_array_to_file():
    external_ips = list_external_ips() 
    filename = "/home/muhamadrifki/nuclei_project/nuclei_project/webview/list_ip_external.txt"
    
    try:
        with open(filename, 'w') as file:
            for ip in external_ips:
                file.write(str(ip) + '\n')
        print(f"Values written to {filename} successfully!")
    except IOError:
        print(f"Error writing to {filename}")



#notified nuclei running to slack
def notif_launch():
    client = WebClient(token=slack_token)
    tanggal = date.today()
    hours = datetime.now().strftime("%H:%M:%S")
    notif_messages = f"Hi Infosec Team, automated scanning for today {tanggal} is starting at {hours}" + "\n" + "template-concurrency : 9 templates/request" + "\n" + "request concurrency: 9 request/s"

# Send a message
    client.chat_postMessage(
        channel="va-automation", 
        text=notif_messages, 
        username="botvaautomation"
    )



#execute nuclei scanning
def run_nuclei():
    global waktu, tanggal
    waktu = str(current_time)
    tanggal = str(current_date)
    #print(tanggal, waktu)
    # Command to run nuclei
    path_to_file = "/home/muhamadrifki/nuclei_project/nuclei_project/webview/nuclei_output_json/"
    command = ["nuclei" , "-l", "/home/muhamadrifki/nuclei_project/nuclei_project/webview/list_ip_external.txt", "-c", "9", "-pc", "9", "-je", path_to_file + "nuclei_output_" + tanggal + "_" + waktu + ".json"]
    print(command)
    #command = ["nuclei" , "-u", "hahhahaha.x", "-je" , "nuclei_output_" + tanggal + "_" + waktu + ".json"]
    
    

    # Start the subprocess
    process = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    print("Running Nuclei at : ", tanggal, waktu)
    process.communicate()
   


def find_process_with_command(command):
    for proc in psutil.process_iter(['pid', 'cmdline']):
        if proc.info.get('cmdline') and command in ' '.join(proc.info['cmdline']):
            return proc.info['pid']
    return None


def detect_process():
    command_to_find = "nuclei -l list_ip_external.txt"
    #time.sleep(10)
    pid = True

    while pid:
        pid = find_process_with_command(command_to_find)
    
    print("Nuclei Scan Finish, saving result to database .... .... ....")
    #sending_to_slack()


def read_file():
    #current_date = str(current_date)
    # current_time = str(current_time)
    #print(tanggal, waktu)

    filepath =("/home/muhamadrifki/nuclei_project/nuclei_project/webview/nuclei_output_json/nuclei_output" + "_" + tanggal + "_" + waktu + ".json")
    with open(filepath, 'r') as file:
        mentahan = file.read()
        #print("success retrieving latest json result")
        data = json.loads(mentahan)
        
    filtered_data = []
    for item in data:
        filtered_item = {
        "name": item["info"]["name"],
        "description": item["info"]["description"] if "description" in item ["info"] and item["info"]["description"] else None,
        "reference": item["info"]["reference"] if "reference" in item["info"] and item["info"]["reference"] else None,
        "severity": item["info"]["severity"],
        "host": item["host"],
        "ip": item.get("ip", None),
        "curl-command": item.get("curl-command", None),
        "timestamp": item.get("timestamp", None)
        }
        filtered_data.append(filtered_item)

# Displaying filtered data
    for item in filtered_data:
        json_dumps = json.dumps(item)
        return json_dumps
        #fixed_data = json_dumps.split(",")
        #print(json_dumps)
    
def parsingSqlite():
    print("parsing data to sqlite database....")
    json_dumps = read_file()
    json_data = json.loads(json_dumps)  # Parse the JSON string to a dictionary

    conn = sqlite3.connect('automation.db')
    cursor = conn.cursor()

    # Insert data into the table
    insert_query = '''
    INSERT INTO scanResult (name, description, reference, severity, host, ip, curlCommand, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    '''

    data_tuple = (
        str(json_data['name']),
        str(json_data['description']),
        str(json.dumps(json_data['reference'])),  # Convert list to JSON string
        str(json_data['severity']),
        str(json_data['host']),
        str(json_data['ip']),  # Convert None to string
        str(json_data['curl-command']),  # Convert None to string
        str(json_data['timestamp'])
    )

    

    cursor.execute(insert_query, data_tuple)
    conn.commit()

    # Close the connection
    conn.close()
    time.sleep(10)
    print("data successfully saved into automation database (automation.db)")

    
    


        
        

    

    

def sending_to_slack():
    client = WebClient(token=slack_token)
    #print("current time after scan :", current_time)
    tanggal = date.today()
    hours = datetime.now().strftime("%H:%M:%S")
    notif_messages = f"Hi Infosec Team, automated scanning for today {tanggal} completed at {hours} and all scan result available to see at http://34.34.223.15:9001/"



#Send a message
    client.chat_postMessage(
        channel="va-automation", 
        text=notif_messages, 
        username="botvaautomation"
    )






def main():
    #notif_launch()
    write_array_to_file()
    run_nuclei()
    time.sleep(10)
    detect_process()
    #read_file()
    parsingSqlite()
    


if __name__ == '__main__':
    main()
