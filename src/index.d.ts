import EventEmitter from 'node:events'

export interface NodeWinPcapPacket {
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

interface NodeWinPcapOptions {
  /**
   * The size of the socket buffer in bytes.
   * This option can be used to control the amount of data that can be buffered before processing.
   * A larger size may help in capturing more packets, especially on busy networks.
   * Default is `262144` (256 KB).
   * @default 262144
   */
  socketSize?: number
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
   * @param options Optional. An object with additional options.
   */
  constructor(ipAddress?: string, options?: NodeWinPcapOptions)

  /**
   * Starts sniffing packets on the specified network interface.
   * @param source_ip_filter Optional. A string to filter packets by source IP address.
   * The filter can be a full IP address (e.g., '192.168.1.1') or a partial address (e.g., '192.168.1.') to match a subnet.
   * Packets will only be emitted if their source IP starts with this string.
   * @param dest_ip_filter Optional. A string to filter packets by destination IP address.
   * The filter can be a full IP address (e.g., '192.168.1.1') or a partial address (e.g., '192.168.1.') to match a subnet.
   * Packets will only be emitted if their destination IP starts with this string.
   */
  start(source_ip_filter?: string, dest_ip_filter?: string): void
  stop(): void
}

