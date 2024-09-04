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
        separator = b'\x00\x01\x00'

        adjusted_message = bytearray()
        for byte in message_bytes:
            if byte == b'\x01' and adjusted_message and adjusted_message[-1] == b'\x00':
                adjusted_message.extend('b\x01\x01')
            else:
                adjusted_message.append(byte)

        crc_value = crc32(message_bytes)
        crc_checksum = crc_value.to_bytes(4, byteorder='big')
        packet = crc_checksum + adjusted_message + separator

        self.channel.send_bits(bytes_to_bits(packet))


       # if len(message_bytes) > MAX_LENGTH:
        #    print("Message is too long")
         #   return 
        #crc_checksum = crc32(message_bytes)
        #crc_bytes = crc_checksum.to_bytes(4, byteorder='big')
       # print(type(message_bytes))
#        message_length = len(message_bytes)

#        format_string = f'II{message_length}s'

#        print(f'CRC={crc_checksum}\nMessage_Length={message_length}\nMessage={message_bytes}\n')

#        message_packet = struct.pack(format_string, message_length, crc_checksum, message_bytes)
 #       self.channel.send_bits(bytes_to_bits(message_packet + b'\x00'))
#



       # format_string = f'!I{len(message_bytes)}s'
       # format_string = '!I'
       # print(f"crc_bytes: {type(crc_bytes)}\nmessage_bytes: {type(message_bytes)}\nformat_string: {type(format_string)}")
      #  message_packet = crc_bytes + message_bytes
      ##  #message_packet = struct.pack(format_string, crc_checksum, message_bytes)   
        # message_package = struct.pack(format_string, crc_checksum, message_bytes) 
        #crc_bytes = struct.pack(format_string, crc_checksum)
        #message_packet = b''.join([crc_bytes, message_bytes])
        #print(f"MessagePacket Type: {type(message_packet)}")
       # self.channel.send_bits(bytes_to_bits(message_packet + b'\x00\x00'))
#
        # self.channel.send_bits(bytes_to_bits(message_bytes + b'\x00'))


class MyReceiver:
    def __init__(self, got_message_function):
        self.got_message_function = got_message_function
        self.recent_bits = bytearray()

    def handle_bit_from_network(self, the_bit):
        separator = b'\x00\x01\x00'
        self.recent_bits.append(the_bit)

        if len(self.recent_bits) % 8 == 0:
            byte_list = bits_to_bytes(self.recent_bits)
            if separator in byte_list:
                received_message, _, _ = byte_list.partition(separator)
                crc_checksum = int.from_bytes(received_message[0:4], byteorder='big') 

                # 00 01 01 01 

                original_message = bytearray()
                for i in range(4, len(received_message)):
                    skipped = False
                    if received_message[i] == b'\x01' and len(original_message) > 1 and original_message[-1] == b'\x01' and original_message[-2] == b'\x00' and not skipped:
                        skipped = True
                    else:
                        original_message.append(received_message[i])
                
                if crc32(original_message) == crc_checksum:
                    self.got_message_function(original_message)
                self.recent_bits.clear()


        #self.recent_bits.append(the_bit)
        #if len(self.recent_bits) % 8 == 0 and self.recent_bits[-8:] == bytearray([0,0,0,0,0,0,0, 0]):
        #    received_packet_with_0 = bits_to_bytes(self.recent_bits)
         #   received_packet = received_packet_with_0[:-1]
         #   int_format = 'II'
         #   unpacked_length, unpacked_crc32 = struct.unpack(int_format, received_packet[:8])

#            message_format = f'{len(unpacked_length)}s'
 #           unpacked_message = struct.unpack(message_format, received_packet[8:])
  #          print(f'Unpacked CRC={unpacked_crc32}\nUnpacked_Length={unpacked_length}\nMessage={unpacked_message}\n')
   #         if unpacked_crc32 == crc32(unpacked_message):
   #             self.got_message_function(unpacked_message)
    #        self.recent_bits.clear()



       #     received_packet = received_packet_with_0[:-1]
        #    message_length = len(received_packet) - 4
         #   crc_bytes = received_packet[:4]
         #   message = received_packet[4:] 
          #  if int.from_bytes(crc_bytes, byteorder="big") == crc32(message):
           #     self.got_message_function(message)
           # self.recent_bits.clear()
           
           
           
           
           
            #format_string = '!I'
            #message, crc_bytes = struct.unpack(format_string, received_packet)
            #crc_checksum = int.from_bytes(crc_bytes, byteorder="big")
            
            #crc_data = received_packet[0:CRC_SIZE]
            #received_message = received_packet[CRC_SIZE:]

            #format_string = '!I'
            #crc_checksum = struct.unpack(format_string, crc_data)
            

            #self.recent_bits.clear()

           # if crc_checksum == crc32(message):
             #   self.got_message_function(message)
            
           # message_with_0 = bits_to_bytes(self.recent_bits)
            #self.recent_bits.clear()
            #self.got_message_function(message_with_0[:-1])
