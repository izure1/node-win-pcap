import EventEmitter from 'node:events'

interface NodeWinPcapPacket {
  data: Buffer
  length: number
  ipHeader: {
    sourceIP: string
    destIP: string
    headerLength: number
    protocol: number
    sourcePort: number
    destPort: number
  }
}

interface NodeWinPcapEvents {
  packet: [packet: NodeWinPcapPacket]
  error: [error: Error]
}

export class NodeWinPcap extends EventEmitter<NodeWinPcapEvents> {
  static readonly Protocol: {
    TCP: 6;
    UDP: 17;
  };
  /**
   * Attempts to automatically detect and return a local IPv4 address.
   * Throws an error if no local IPv4 address is found.
   */
  static GetLocalAddress(): string
  
  readonly ipAddress: string
  socket: any
  isListening: boolean
  source_ip_filter: string
  dest_ip_filter: string

  /**
   * Creates a new NodeWinPcap instance.
   * @param ipAddress The IP address of the network interface to sniff on.
   * If not provided, it attempts to automatically detect a local IPv4 address.
   */
  constructor(ipAddress?: string)

  /**
   * Starts sniffing packets on the specified network interface.
   * @param source_ip_filter Optional. A string to filter packets by source IP address.
   * The filter can be a full IP address (e.g., '192.168.1.1') or a partial address (e.g., '192.168.1.') to match a subnet.
   * Packets will only be emitted if their source IP starts with this string.
   * @param dest_ip_filter Optional. A string to filter packets by destination IP address.
   * The filter can be a full IP address (e.g., '192.168.1.1') or a partial address (e.g., '192.168.1.') to match a subnet.
   * Packets will only be emitted if their destination IP starts with this string.
   */
  start(source_ip_filter = '', dest_ip_filter = ''): void
  stop(): void
}

