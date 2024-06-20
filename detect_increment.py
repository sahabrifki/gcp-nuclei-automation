import subprocess
import json
import os
from datetime import date,datetime
from slack_sdk import WebClient
import requests
import psutil
import time
import psycopg2


current_date = date.today()
now_time = datetime.now()
current_time = now_time.strftime("%H:%M:%S")
#print("Current time Launch ", current_time)



#listing all projects and enumerate all exeternal ip address from each project
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
                    #print ("(+)External IP addresses found: " + x["address"])
                    external_ips.append(x["address"])

    return external_ips

#execute nuclei to initiate scanning
def run_nuclei():    
    path_to_file = "/home/muhamadrifki/nuclei_project/nuclei_project/webview/nuclei_output_json/"
    command = ["nuclei" , "-l", "/home/muhamadrifki/nuclei_project/nuclei_project/webview/target/list_ip_external_" + tanggal + "_" + waktu + ".txt", "-c", "9", "-pc", "9", "-je", path_to_file + "nuclei_output_" + tanggal + "_" + waktu + ".json"]
    #print(command)
    
    # Start the subprocess
    process = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    print("(+) Running Nuclei at : ", tanggal, waktu)
    process.communicate()
   

#detect all process in linux, to detect nuclei prosess
def find_process_with_command(command):
    for proc in psutil.process_iter(['pid', 'cmdline']):
        if proc.info.get('cmdline') and command in ' '.join(proc.info['cmdline']):
            return proc.info['pid']
    return None

# Informing users from process iteration and notified if nuclei is done
def detect_process():
    command_to_find = "nuclei -l list_ip_external.txt"
    #time.sleep(10)
    pid = True

    while pid:
        pid = find_process_with_command(command_to_find)
    
    print("[INFO] Nuclei Scan Finish, Parsing Data Into Database .... .... ....")
    sending_to_slack()

#Reading Nuclei with JSON Output
def read_file():
    conn = psycopg2.connect(
        host = "localhost",
        database = "automation_db",
        user = "automation",
        password = "c111503913af1df18fd3e6387407e9a1078f624c" 
    )

    cursor = conn.cursor()

    filepath =("/home/muhamadrifki/nuclei_project/nuclei_project/webview/nuclei_output_json/nuclei_output" + "_" + tanggal + "_" + waktu + ".json")
    #filepath =("/home/muhamadrifki/nuclei_project/nuclei_project/webview/nuclei_output_json/nuclei_output_2024-05-30_13:57:34.json")
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
        json_data = json.dumps(filtered_data)
        # return json_data
    
    for item in filtered_data:
        for key in item:
            if item[key] is None:
                item[key] = "None"
        
        cursor.execute("""
            INSERT INTO scanResult (name, description, reference, severity, host, ip, curlCommand, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            item["name"],
            item["description"],
            item["reference"],
            item["severity"],
            item["host"],
            item["ip"],
            item["curl-command"],
            item["timestamp"]
        ))

    conn.commit()
    print("[FINISH] Data Successfully Stored into database")
    cursor.close()
    conn.close()
        
    

def sending_to_slack():
    client = WebClient(token=slack_token)
    #print("current time after scan :", current_time)
    tanggal = date.today()
    hours = datetime.now().strftime("%H:%M:%S")
    notif_messages = f"Hi Infosec Team, automated scanning for today {tanggal} completed at {hours} and all scan result available to see at "
#Send a message
    client.chat_postMessage(
        channel="va-automation", 
        text=notif_messages, 
        username="botvaautomation"
    )



def main():
    global waktu, tanggal
    waktu = str(current_time)
    tanggal = str(current_date)
   
    external_ips = list_external_ips() 
    filename = "/home/muhamadrifki/nuclei_project/nuclei_project/webview/target/list_ip_external.txt"
    new_target = f"/home/muhamadrifki/nuclei_project/nuclei_project/webview/target/list_ip_external_{tanggal}_{waktu}.txt"
    
    try:
        with open(filename, 'r') as file:
            existing_ips = file.read().splitlines()
        
        new_ips = [ip for ip in external_ips if ip not in existing_ips]
        
        if not new_ips:
            print("All IP addresses are identic with previous IP Lists collection result, Nuclei Scan Aborted")
            client = WebClient(token=slack_token)
            client.chat_postMessage(
                channel="va-automation",
                text = "Hi Infosec Team, No New IP Address Found From Previous Asset Collection Result, Nuclei Scan Abort",
                username="botvaautomation"
            )
        else:
            with open(filename, 'a') as oldFile:
                for ip in new_ips:
                    oldFile.write(ip + '\n')
            
            for ip in new_ips:
                print("New Ip Addresses Found: ", ip)
            
            with open(new_target, 'a') as newFile:
                for ip in new_ips:
                    newFile.write(ip + '\n')
                    

            
            print(f"[Saving Files] - New values appended to {new_target} successfully!")

            with open(new_target, 'r' ) as newIP:
                new_ip = newIP.read().splitlines()
                ip_to_string ="\n".join(str(x) for x in new_ip)
                
                #print("new_ip: " , ip_to_string)
            
            client = WebClient(token=slack_token)
            client.chat_postMessage(
            channel="va-automation",
            text = f"Hi Infosec Team, New IP Address detected : \n {ip_to_string}" +  "\n" + "\n" + "Nuclei Scan for :" + "\n" f"{ip_to_string}" + "\n" + f"Started at {tanggal, waktu}",
            username="botvaautomaton"
             )
            
            run_nuclei()
            time.sleep(10)
            detect_process()
            read_file()

            
    except IOError:
        print(f"Error reading from {filename}, {oldFile}")
    


if __name__ == '__main__':
    main()
