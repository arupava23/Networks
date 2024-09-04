from collections import deque
from zlib import crc32
import struct

MAX_LENGTH = 1024

# Framing method: Header, CRC Checksum, Message Bytes
# Header: length of message bytes

def bytes_to_bits(the_bytes):
    result = bytearray()
    for a_byte in the_bytes:
        for i in range(8):
            result.append(0 if (a_byte & (0x1 << i)) == 0 else 1)
    return result

def bits_to_bytes(the_bits):
    result = bytearray()
    for i in range(0, len(the_bits), 8):
        current = 0
        for j in range(8):
            current += (the_bits[i+j] << j)
        result.append(current)
    return result

class MySender:
    def __init__(self, channel):
        self.channel = channel

    def send_message(self, message_bytes):
        crc_checksum = crc32(message_bytes)
        crc_bytes = crc_checksum.to_bytes(4, byteorder='big')
        print(type(message_bytes))
        format_string = f'!I{len(message_bytes)}s'
        print(f"crc_bytes: {type(crc_bytes)}\nmessage_bytes: {type(message_bytes)}\nformat_string: {type(format_string)}") 
        message_packet = struct.pack(format_string, crc_checksum, message_bytes)   
        # message_package = struct.pack(format_string, crc_checksum, message_bytes) 
        #crc_bytes = struct.pack(format_string, crc_checksum)
        #message_packet = b''.join([crc_bytes, message_bytes])
        #print(f"MessagePacket Type: {type(message_packet)}")
        self.channel.send_bits(bytes_to_bits(message_packet + b'\x00'))

        # self.channel.send_bits(bytes_to_bits(message_bytes + b'\x00'))


class MyReceiver:
    def __init__(self, got_message_function):
        self.got_message_function = got_message_function
        self.recent_bits = bytearray()

    def handle_bit_from_network(self, the_bit):
        self.recent_bits.append(the_bit)
        if len(self.recent_bits) % 8 == 0 and self.recent_bits[-8:] == bytearray([0,0,0,0,0,0,0,0]):
            received_packet_with_0 = bits_to_bytes(self.recent_bits)
            received_packet = received_packet_with_0[:-1]
            message_length = len(received_packet) - 4
            format_string = f'!I{message_length}s'
            message, crc_bytes = struct.unpack(format_string, received_packet)
            crc_checksum = int.from_bytes(crc_bytes, byteorder="big")
            
            #crc_data = received_packet[0:CRC_SIZE]
            #received_message = received_packet[CRC_SIZE:]

            #format_string = '!I'
            #crc_checksum = struct.unpack(format_string, crc_data)
            

            self.recent_bits.clear()

            if crc_checksum == crc32(message):
                self.got_message_function(message)
            
           # message_with_0 = bits_to_bytes(self.recent_bits)
            #self.recent_bits.clear()
            #self.got_message_function(message_with_0[:-1])
