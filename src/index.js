const EventEmitter = require('node:events')
const os = require('node:os')
const path = require('node:path')
const addonPath = require('@mapbox/node-pre-gyp').find(path.resolve(path.join(__dirname, '..', 'package.json')))
const addon = require(addonPath)

class NodeWinPcap extends EventEmitter {
  static Protocol = {
    TCP: 6,
    UDP: 17,
  };
  static GetLocalAddress() {
    const interfaces = os.networkInterfaces()
    for (const iface of Object.values(interfaces)) {
      for (const address of iface) {
        if (address.family === 'IPv4' && !address.internal) {
          return address.address
        }
      }
    }
    throw new Error('No local IPv4 address found.')
  }

  constructor(ipAddress = NodeWinPcap.GetLocalAddress()) {
    super()
    this.socket = null
    this.isListening = false
    this.ipAddress = ipAddress // Store ipAddress in constructor
    this.source_ip_filter = ''
    this.dest_ip_filter = ''
  }

  start(source_ip_filter = '', dest_ip_filter = '') {
    if (this.isListening) {
      throw new Error('Already listening')
    }
    if (!this.ipAddress) {
      throw new Error('IP address must be provided in the constructor.')
    }

    this.source_ip_filter = source_ip_filter
    this.dest_ip_filter = dest_ip_filter

    try {
      this.socket = addon.createNodeWinPcap(this.ipAddress) // Use stored ipAddress
      this.isListening = true
      this._listen()
    } catch (error) {
      throw new Error(`Failed to start sniffer: ${error.message}. Make sure to run as root.`)
    }
  }

  stop() {
    if (!this.isListening) return
    
    this.isListening = false
    if (this.socket !== null) {
      addon.closeSocket(this.socket)
      this.socket = null
    }
  }

  _listen() {
    if (!this.isListening) return

    setImmediate(() => {
      try {
        // Pass filters to the C++ addon
        const packet = addon.receivePacket(this.socket, this.source_ip_filter, this.dest_ip_filter)
        
        // Only emit if a packet is returned (C++ will handle filtering)
        if (packet) {
          // The C++ addon will now return the parsed IP header as part of the packet
          this.emit('packet', packet)
        }
        
        this._listen() // Continue listening
      } catch (error) {
        // Errors might occur (e.g., non-IP packets), so we can choose to ignore or emit.
        // For now, we'll continue to emit them.
        this.emit('error', error)
      }
    })
  }
}

module.exports = {
  NodeWinPcap
}

