# Imports
import psycopg2 as PostgresSQL
import json

# Constants

# Insert to Database Function
def Insert_To_Database(vJsonDataFile, vDBCredentials):
    
    # Getting DB Credentials
    vDBAddress = vDBCredentials["Address"]
    vDBPort = vDBCredentials["Port/Path"]
    vDBUsername = vDBCredentials["Username"]
    vDBPassword = vDBCredentials["Password"]
    vDBCredsTable = vDBCredentials["CredsTable"]

    print(vDBAddress)
    print(vDBPort)
    print(vDBUsername)
    print(vDBPassword)
    print(vDBCredsTable)

    # Read Placeholder Data
    with open(fr"{vJsonDataFile}", "r") as f:
        vJsonData = json.laods(f.read())
    print(vJsonData)

# Main Function
def main():
    pass

# if script is being called directly, call main function
if __name__ == "__main__":
    main()