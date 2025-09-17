# node-win-pcap

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`node-win-pcap` is a Node.js packet capture module exclusively for the Windows operating system. It captures network packets using Windows' built-in functionalities without requiring separate external programs (e.g., Npcap, WinPcap).

This project is inspired by [raw-socket-sniffer](https://github.com/nospaceships/raw-socket-sniffer).

## Key Features

- **No External Dependencies:** No need to install drivers like WinPcap or Npcap.
- **Simplicity:** Operates simply and lightly by directly using Windows APIs.
- **IP Filtering:** Capable of filtering packets based on source and destination IP addresses.

## Requirements

- Windows operating system
- Administrator privileges (required for packet capture)

## Installation

```bash
npm install node-win-pcap
```

## Usage

The following is a basic example of binding to a specific network interface's IP address and capturing packets.

```javascript
const { NodeWinPcap } = require('node-win-pcap');

// If ipAddress is omitted, it will automatically be set to the first available IP address.
// To use a specific interface, pass its IP address (e.g., '192.168.0.10').
const pcap = new NodeWinPcap();

// Set up 'packet' event listener
pcap.on('packet', (packet) => {
  console.log('--- New Packet ---');
  console.log('Packet Length:', packet.length);
  
  // Print IP header information
  const ipHeader = packet.ipHeader;
  if (ipHeader) {
    console.log(`Source IP: ${ipHeader.sourceIP}`);
    console.log(`Destination IP: ${ipHeader.destIP}`);
    console.log(`Protocol: ${ipHeader.protocol}`);
    if (ipHeader.protocol === NodeWinPcap.Protocol.TCP) {
      console.log('  (TCP Protocol)');
    } else if (ipHeader.protocol === NodeWinPcap.Protocol.UDP) {
      console.log('  (UDP Protocol)');
    }
    console.log(`Source Port: ${ipHeader.sourcePort}`);
    console.log(`Destination Port: ${ipHeader.destPort}`);
  }

  // Full packet data (Buffer)
  // console.log('Packet Data:', packet.data);
});

// Set up 'error' event listener
pcap.on('error', (error) => {
  console.error('An error occurred:', error);
});

try {
  // Start packet capture (without filters)
  pcap.start('1.2.3.4', '5.6.7.8');
  console.log(`Packet sniffing started on ${pcap.ipAddress}...`);

  // Start capture with specific IP address filters
  // pcap.start('1.2.3.4', '5.6.7.8'); // sourceIP: 1.2.3.4, destIP: 5.6.7.8
  // console.log('Packet sniffing started with IP filters...');

} catch (e) {
  console.error(`Failed to start sniffing: ${e.message}`);
}

// Stop capture after 10 seconds
setTimeout(() => {
  pcap.stop();
  console.log('Packet sniffing stopped.');
}, 10000);
```

## Packet Structure

Captured packets are returned as an object conforming to the following TypeScript interface:

```typescript
interface NodeWinPcapPacket {
  data: Buffer;
  length: number;
  ipHeader: {
    sourceIP: string;
    destIP: string;
    headerLength: number;
    protocol: number;
    sourcePort: number;
    destPort: number;
  };
}
```

## IP Filtering

The `start` method captures packets by specifying the source and destination IP addresses.
For example, to capture all inbound packets to your computer, use the following:

```typescript
const { NodeWinPcap } = require('node-win-pcap');
const pcap = new NodeWinPcap();

const sourceIp = '';
const destIp = NodeWinPcap.GetLocalAddress();
pcap.start(sourceIp, destIp);
```

The IP string pattern is similar to JavaScript's `startsWith`.
For example, to capture packets from the `192.168.0.*` IP range coming to your IP, you would use a `sourceIp` like `'192.168.0.'`.

## updateFunction

By default, `node-win-pcap` uses the `setImmediate` built-in function to check for new packets on every event loop of the main thread.
This is stable, but if you want to improve performance, you can also use the `setTimeout` built-in function.

```typescript
const { NodeWinPcap } = require('node-win-pcap');

const ipAddress = NodeWinPcap.GetLocalAddress();
const pcap = new NodeWinPcap(ipAddress, {
  updateFunction: (callback) => {
    setTimeout(callback, 0);
  }
});
```

## License

[MIT](LICENSE)
