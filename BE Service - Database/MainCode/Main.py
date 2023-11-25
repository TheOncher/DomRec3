# Imports
import socket
import base64
import json
import os
import shutil
from time import sleep
from threading import Thread
import sys
import importlib

# Constants
SCRIPT_ROOT = os.path.dirname(__file__)
SCRIPT_UPPER_ROOT = os.path.dirname(SCRIPT_ROOT)
THREAD_SETTINGS_JSON_PATH = fr"{SCRIPT_UPPER_ROOT}\\Configuration\\ThreadSettings.json"

# Starting the constant check for ThreadSetting.json
def Check_Thread_Settings(vThreadSettingsJsonPath):
    
    # Defining Global Variables
    global vListenerUp
    global vListenerPort
    global vLocalDistributionUp
    global vDBEngineDistributionUp

    while True:
        try:
            # Read Thread Settings
            with open(fr"{vThreadSettingsJsonPath}", "r") as f:
                vThreadSettings = json.loads(f.read())

            # Change global variables to match Thread Settings
            vListenerUp = vThreadSettings['ListenerUp']
            vListenerPort = vThreadSettings['ListenerPort']
            vLocalDistributionUp = vThreadSettings['LocalDistributionUp']
            vDBEngineDistributionUp = vThreadSettings['DBEngineDistributionUp']
            sleep(2)
        
        # Try again in 2 seconds
        except:
            sleep(2)

# Starting the Json Listener for the incoming data from the connectors
def Start_Json_Connector_Listener():

    # Definign Global Variables
    global vListenerUp
    global vListenerPort

    # Pause Function
    while vListenerUp == "False":
        sleep(3)
        
    # Create a TCP/IP socket
    vSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the port
    vServerAddress = ('localhost', int(vListenerPort))
    vSocket.bind(vServerAddress)
    # Listen for incoming connections
    vSocket.listen(1)

    while True:
        # Pause Function
        if (vListenerUp == "False"):
            sleep(3)
            continue
    
        # Wait for a connection
        vConnection, client_address = vSocket.accept()

        # Pause Function
        if (vListenerUp == "False"):
            vConnection.close()
            sleep(3)
            continue

        try:
            # Receive the data in small chunks and reassemble it
            vIncomingData = b''
            while True:
                chunk = vConnection.recv(4096)
                if chunk:
                    vIncomingData += chunk
                else:
                    break
                
            try:
                # Decode the Base64 encoded data
                vDecodedData = (base64.b64decode(vIncomingData).decode())

                # Load and Format the JSON data
                vDecodedJson = json.loads(vDecodedData)
                vDecodedJsonConnector = vDecodedJson['Connector']
                vDecodedJsonTimestamp = vDecodedJson['Timestamp']
                vDecodedJsonDatabase = vDecodedJson['Database']
                vDecodedJsonData = vDecodedJson['Data']

                # Write the Data to JsonDataHolder Folder
                with open(fr"{SCRIPT_ROOT}\\JsonDataHolder\\{vDecodedJsonDatabase} {vDecodedJsonTimestamp}.json", "w") as f:
                    json.dump(vDecodedJsonData, f)

            # Stop if Data is corrupted
            except:
                pass
        
        # Clean up the connection
        finally:
            vConnection.close()

# Starting the Data Distribution to all Locally Active DB PlaceHolders (Saving Files Locally)
def Start_DataHolder_Distribution():

    # Defining Global Variables
    global vLocalDistributionUp

    while True:
        # Stop if user doesnt want to spread data
        if (vLocalDistributionUp == "False"):
            sleep(3)
            continue

        try:
            # Check what databases are active, to know where to spread the data
            with open(fr"{SCRIPT_UPPER_ROOT}\\Configuration\\ActiveDatabases.json" , "r") as f:
                vActiveDatabases = json.loads(f.read())

            # Loop through each file in JsonDataHolder
            vActiveDatabases = vActiveDatabases['ActiveDatabasePlaceholders']
            vJsonDataHolders = os.listdir(fr"{SCRIPT_ROOT}\\JsonDataHolder")
            for vJsonDataHolder in vJsonDataHolders:
                # Save the data to a file in the correct DBs folder
                for vActiveDatabase in vActiveDatabases:
                    if (os.path.isfile(fr"{SCRIPT_ROOT}\\JsonDataHolder\\{vJsonDataHolder}") and not os.path.isfile(fr"{SCRIPT_UPPER_ROOT}\\Databases\\{vActiveDatabase}\\{vJsonDataHolder}")):
                        shutil.copy(fr"{SCRIPT_ROOT}\\JsonDataHolder\\{vJsonDataHolder}",fr"{SCRIPT_UPPER_ROOT}\\Databases\\{vActiveDatabase}\\{vJsonDataHolder}")

                # After copying the file, remove it from JsonDataHolder folder
                if (os.path.isfile(fr"{SCRIPT_ROOT}\\JsonDataHolder\\{vJsonDataHolder}")):
                    os.remove(fr"{SCRIPT_ROOT}\\JsonDataHolder\\{vJsonDataHolder}")

            sleep(5)

        # Retry if encounters error
        except:
            pass

# Starting the Data Distribution to all Remotely Active DB Engines (The Actuall Database)
def Start_Database_Engine_Distribution():

    # Defining Global Variables
    global vDBEngineDistributionUp

    # Import all DBFunctions Modules:
    sys.path.insert(0,fr"{SCRIPT_ROOT}\\DBFunctions")
    for vDBFunction in os.listdir(fr"{SCRIPT_ROOT}\\DBFunctions"):
        try:
            importlib.import_module(fr"{vDBFunction}")
            #import f"{vDBFunction}"
            
        except:
            pass

    while True:
        # Stop if user doesnt want to spread data
        if (vDBEngineDistributionUp == "False"):
            sleep(3); continue

        if True:
            print("es0")
            # Get DB Credentials
            with open(fr"{SCRIPT_UPPER_ROOT}\\Configuration\\DBCredentials.json", "r") as f:
                vDBCredentials = f.read()
                print(vDBCredentials)
                vDBCredentials = json.loads(vDBCredentials)
                print(vDBCredentials)
            print("es1")
            # Check what Database Engines are active, to know where to spread the data
            with open(fr"{SCRIPT_UPPER_ROOT}\\Configuration\\ActiveDatabases.json" , "r") as f:
                vActiveDatabaseEngines = json.loads(f.read())
            
            print("es2")
            print(vDBCredentials)
            print(vActiveDatabaseEngines)
            vActiveDatabaseEngines = vActiveDatabaseEngines['ActiveDatabaseEngines']
            for vActiveDatabaseEngine in vActiveDatabaseEngines:
                # Stop if user doesnt want to spread data
                if (vDBEngineDistributionUp == "False"):
                    continue

                for vJsonDataFile in os.listdir(fr"{SCRIPT_UPPER_ROOT}\\Databases\\{vActiveDatabaseEngine}"):

                    # Stop if user doesnt want to spread data
                    if (vDBEngineDistributionUp == "False"):
                        continue

                    # Insert Data to Databases
                    vJsonDataFile = fr"{SCRIPT_UPPER_ROOT}\\Databases\\{vActiveDatabaseEngine}\\{vJsonDataFile}"
                    try:
                        print("Once")
                        print(vJsonDataFile)
                        print(vDBCredentials)
                        print("Once")
                        f"{vActiveDatabaseEngine}".Insert_To_Database(vJsonDataFile, vDBCredentials)
                    except:
                        pass

            sleep(2)
        
        # Retry if encounters error
        #except:
            #sleep(2)


# Main Function
def main():

    # Creating Global Variables
    global vListenerUp
    global vListenerPort
    global vLocalDistributionUp
    global vDBEngineDistributionUp

    # Changing Threads Settings Live Nonstop
    Check_Thread_Settings_Thread = Thread(target=Check_Thread_Settings, args=(THREAD_SETTINGS_JSON_PATH,))
    Check_Thread_Settings_Thread.start()
    sleep(5)
    
    # Creating Threads for each function to run simultaneously
    Json_Connector_Listener_Thread = Thread(target=Start_Json_Connector_Listener, args=())
    DataHolder_Distribution_Thread = Thread(target=Start_DataHolder_Distribution, args=())
    Start_Database_Engine_Distribution_Thread = Thread(target=Start_Database_Engine_Distribution, args=())

    # Starting all Threads
    Json_Connector_Listener_Thread.start()
    DataHolder_Distribution_Thread.start()
    Start_Database_Engine_Distribution_Thread.start()


# if script is being called directly, call main function
if __name__ == "__main__":
    main()